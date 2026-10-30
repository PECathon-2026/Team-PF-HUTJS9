"""Log scrubber, behaviour-identical to plcommon's pl::scrub (pl/scrub.hpp).

Both implementations are tested against libs/plcommon/testdata/scrubber_vectors.json.
"""

from __future__ import annotations

KEY_PREFIXES = (
    "github_pat_", "sk-ant-", "sk-proj-", "sk-", "ghp_", "gho_", "ghu_", "ghs_",
    "ghr_", "AKIA", "ASIA", "hf_", "xoxb-", "xoxp-", "xoxa-", "AIza",
)  # fmt: skip
TOKEN_MIN = 8
CARD_MIN, CARD_MAX = 13, 19
AADHAAR_LEN = 12
NUMBER_MIN = 6  # catches 6-digit OTPs and PINs
MAX_SEPARATOR = 2
SEPARATORS = " .-/_\t"
PAN_LEN = 10

_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5), (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7), (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3), (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)  # fmt: skip
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4), (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7), (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)  # fmt: skip


def _digit(c: str) -> bool:
    return "0" <= c <= "9"


def _upper(c: str) -> bool:
    return "A" <= c <= "Z"


def _alpha(c: str) -> bool:
    return _upper(c) or "a" <= c <= "z"


def _alnum(c: str) -> bool:
    return _alpha(c) or _digit(c)


def _token(c: str) -> bool:
    return _alnum(c) or c in "_-"


def _local(c: str) -> bool:
    return _alnum(c) or c in "._%+-"


def _domain(c: str) -> bool:
    return _alnum(c) or c in ".-"


def _run(s: str, i: int, pred: object) -> int:
    assert callable(pred)
    j = i
    while j < len(s) and pred(s[j]):
        j += 1
    return j


def _word_start(s: str, i: int) -> bool:
    return i == 0 or not _token(s[i - 1])


def luhn_valid(digits: str) -> bool:
    if not digits or not all(_digit(c) for c in digits):
        return False
    total = 0
    for k, c in enumerate(reversed(digits)):
        d = ord(c) - 48
        if k % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def verhoeff_valid(digits: str) -> bool:
    if not digits or not all(_digit(c) for c in digits):
        return False
    c = 0
    for pos, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[pos % 8][ord(ch) - 48]]
    return c == 0


def _match_key(s: str, i: int) -> int | None:
    if not _word_start(s, i):
        return None
    for prefix in KEY_PREFIXES:
        if s.startswith(prefix, i):
            end = _run(s, i + len(prefix), _token)
            if end - (i + len(prefix)) >= TOKEN_MIN:
                return end
    return None


def _match_jwt(s: str, i: int) -> int | None:
    if not _word_start(s, i) or not s.startswith("eyJ", i):
        return None
    j = _run(s, i, _token)
    for part in range(2):
        if j >= len(s) or s[j] != ".":
            return None
        k = _run(s, j + 1, _token)
        if k == j + 1 and part == 0:
            return None
        j = k
    return j


def _match_pan(s: str, i: int) -> int | None:
    if not _word_start(s, i) or len(s) - i < PAN_LEN:
        return None
    for k in range(PAN_LEN):
        c = s[i + k]
        if not (_upper(c) if (k < 5 or k == 9) else _digit(c)):
            return None
    if i + PAN_LEN < len(s) and _token(s[i + PAN_LEN]):
        return None
    return i + PAN_LEN


def _match_email(s: str, i: int) -> int | None:
    if not _local(s[i]) or (i > 0 and _local(s[i - 1])):
        return None
    at = _run(s, i, _local)
    if at >= len(s) or s[at] != "@":
        return None
    end = _run(s, at + 1, _domain)
    while end > at + 1 and s[end - 1] in ".-":
        end -= 1
    domain = s[at + 1 : end]
    dot = domain.rfind(".")
    if dot <= 0:
        return None
    tld = domain[dot + 1 :]
    if len(tld) < 2 or not all(_alpha(c) for c in tld):
        return None
    return end


def _digit_run(s: str, i: int) -> tuple[int, str]:
    """Digits joined by runs of up to MAX_SEPARATOR separator characters."""
    end, j, digits = i, i, []
    while j < len(s):
        if _digit(s[j]):
            digits.append(s[j])
            j += 1
            end = j
            continue
        k = j
        while k < len(s) and k - j < MAX_SEPARATOR and s[k] in SEPARATORS:
            k += 1
        if k == j or k >= len(s) or not _digit(s[k]):
            break
        j = k
    return end, "".join(digits)


def scrub(s: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(s):
        end: int | None
        tag = ""
        if (end := _match_key(s, i)) is not None:
            tag = "[KEY]"
        elif (end := _match_jwt(s, i)) is not None:
            tag = "[JWT]"
        elif (end := _match_pan(s, i)) is not None:
            tag = "[PAN]"
        elif (end := _match_email(s, i)) is not None:
            tag = "[EMAIL]"
        elif _digit(s[i]) and (i == 0 or not _digit(s[i - 1])):
            run_end, digits = _digit_run(s, i)
            n = len(digits)
            if CARD_MIN <= n <= CARD_MAX and luhn_valid(digits):
                tag = "[CARD]"
            elif n == AADHAAR_LEN and digits[0] >= "2" and verhoeff_valid(digits):
                tag = "[AADHAAR]"
            elif n >= NUMBER_MIN:
                tag = "[NUMBER]"
            if not tag:
                out.append(s[i:run_end])
                i = run_end
                continue
            end = run_end
        if end is not None:
            out.append(tag)
            i = end
        else:
            out.append(s[i])
            i += 1
    return "".join(out)
