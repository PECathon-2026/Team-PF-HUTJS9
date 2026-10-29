"""Red-team pages: every planted value decodes to a valid value, sits where the
truth says, and actually evades a naive scanner; injections are where they claim."""

from __future__ import annotations

import base64
import json
import re
import unicodedata
import urllib.parse
from pathlib import Path
from typing import Any

import pytest
from bs4 import BeautifulSoup, Comment, Tag
from gen import values as v

from plscen.build import build
from plscen.redteam import PDF, REDTEAM, RLO, UNHOMOGLYPH


@pytest.fixture(scope="module")
def out(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("rt")
    build(d)
    return d


def truth(out: Path, page: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((out / "truth" / "redteam" / f"{page}.json").read_text("utf-8"))
    return data


def soup(out: Path, page: str) -> BeautifulSoup:
    return BeautifulSoup((out / "site" / "redteam" / page / "index.html").read_text("utf-8"), "html.parser")


def one(doc: BeautifulSoup, sel: str) -> Tag:
    found = doc.select(sel)
    assert len(found) == 1, (sel, len(found))
    return found[0]


def decode(s: str, encoding: list[str]) -> str:
    for e in encoding:
        if e == "base64":
            s = base64.b64decode(s).decode()
        elif e == "hex":
            s = bytes.fromhex(s).decode()
        elif e == "url":
            s = urllib.parse.unquote(s)
        elif e == "json":
            s = " ".join(str(x) for x in json.loads(s).values())
        else:
            raise AssertionError(e)
    return s


INVISIBLE = re.compile("[\u200b-\u200f\u2060\u00ad\ufeff\u202a-\u202e]")


def canon(s: str) -> str:
    """What a careful scanner should reduce the text to (detect's normaliser target)."""
    s = re.sub(f"{RLO}(.*?){PDF}", lambda m: m.group(1)[::-1], s)  # bidi override shows reversed
    s = unicodedata.normalize("NFKC", s)
    s = "".join(UNHOMOGLYPH.get(ch, ch) for ch in s)
    s = "".join(str(unicodedata.decimal(ch)) if ch.isdecimal() else ch for ch in s)  # native digits
    s = INVISIBLE.sub("", s)
    return s.replace(".", "") if re.fullmatch(r"[\d.]+", s) else s


def candidates(it: dict[str, Any]) -> str:
    return canon(decode(it["shown"], it["encoding"]))


@pytest.mark.parametrize("page", list(REDTEAM))
def test_values_recover_to_valid(out: Path, page: str) -> None:
    for it in truth(out, page)["items"]:
        assert v.validate(it["type"], it["value"]), it["id"]
        got = candidates(it)
        if it["channel"] == "css_content":
            continue  # checked with the CSS tail below
        if it["type"] in ("name",):
            continue
        assert it["value"] in got.replace(" ", "").replace("-", "") or v.validate(it["type"], got), (it["id"], got)


@pytest.mark.parametrize("page", ["lookalike", "encoded"])
def test_tricks_defeat_a_naive_scan(out: Path, page: str) -> None:
    """Raw text must not validate: otherwise the page doesn't test anything."""
    for it in truth(out, page)["items"]:
        raw = it["shown"]
        assert it["value"] not in raw and not v.validate(it["type"], raw), it["id"]


@pytest.mark.parametrize("page", list(REDTEAM))
def test_values_sit_in_their_channel(out: Path, page: str) -> None:
    doc = soup(out, page)
    site = out / "site" / "redteam" / page
    html_src = (site / "index.html").read_text("utf-8")
    for it in truth(out, page)["items"]:
        el = one(doc, it["selector"])
        shown, ch = it["shown"], it["channel"]
        if ch in ("text", "script"):
            assert shown in el.get_text(), it["id"]
        elif ch == "input_value":
            assert el.get("value") == shown, it["id"]
        elif ch == "text_split":
            spans = [s for s in el.find_all("span", recursive=False) if isinstance(s, Tag)]
            assert len(spans) >= 2 and all(shown not in s.get_text() for s in spans), it["id"]
            if "css_order" in it["obfuscation"]:
                assert "".join(s.get_text() for s in spans) != shown, it["id"]  # DOM order differs
                spans.sort(key=lambda s: int(re.sub(r"\D", "", str(s.get("style")))))
            assert "".join(s.get_text() for s in spans) == shown, it["id"]
        elif ch == "css_content":
            m = re.search(re.escape(it["selector"]) + r'::after\s*\{\s*content:\s*"([^"]*)"', html_src)
            assert m and el.get_text() == shown and shown + m.group(1) == it["value"], it["id"]
        elif ch == "attribute":
            assert shown in str(el.get(it["attribute"])), it["id"]
        elif ch in ("url_query", "url_fragment", "url_path"):
            parts = urllib.parse.urlsplit(str(el.get(it["attribute"])))
            qvals = [x for vals in urllib.parse.parse_qs(parts.query).values() for x in vals]
            where = {"url_query": " ".join(qvals),
                     "url_fragment": parts.fragment, "url_path": parts.path}[ch]  # fmt: skip
            assert shown in where, it["id"]
        elif ch == "image":
            assert el.name == "img" and (site / str(el.get("src"))).is_file(), it["id"]
        else:
            pytest.fail(f"{it['id']}: channel {ch}")


def test_injections(out: Path) -> None:
    t = truth(out, "injection")
    doc = soup(out, "injection")
    site = out / "site" / "redteam" / "injection"
    langs, techniques = set(), set()
    for inj in t["injections"]:
        langs.add(inj["language"])
        techniques.add(inj["technique"])
        el = one(doc, inj["selector"])
        if inj["channel"] == "text":
            assert inj["content"] in el.get_text(), inj["id"]
        elif inj["channel"] == "attribute":
            assert str(el.get(inj["attribute"])) == inj["content"], inj["id"]
        elif inj["channel"] == "image":
            assert (site / inj["asset"]).is_file() and el.get("src") == inj["asset"], inj["id"]
        elif inj["channel"] == "html_comment":
            comments = [str(c) for c in el.find_all(string=lambda s: isinstance(s, Comment))]
            assert any(inj["content"] in c for c in comments), inj["id"]
        else:
            pytest.fail(inj["channel"])
        text = canon(decode(inj["content"], inj["encoding"])).lower()
        assert "evil.example" in text or "instruction" in text or "निर्देश" in text or "approved" in text, inj["id"]
        assert inj["goal"] in {"exfiltrate", "navigate", "skip_approval", "destructive_click"}
    assert langs == {"en", "hi", "hinglish"}
    assert {"visible_instruction", "css_hidden", "aria", "alt_text", "image", "encoded", "zero_width",
            "html_comment", "tiny_font"} <= techniques  # fmt: skip


def test_attacker_addresses_are_reserved(out: Path) -> None:
    for page in REDTEAM:
        src = (out / "site" / "redteam" / page / "index.html").read_text("utf-8")
        for host in re.findall(r"[a-z0-9.-]+\.(?:com|net|org|in|io|example)\b", src):
            assert host.endswith((".example", "example.com", "example.org", "example.net")), (page, host)


def test_coverage_of_attack_types(out: Path) -> None:
    obf = {o for p in REDTEAM for it in truth(out, p)["items"] for o in it["obfuscation"]}
    enc = {e for p in REDTEAM for it in truth(out, p)["items"] for e in it["encoding"]}
    chans = {it["channel"] for p in REDTEAM for it in truth(out, p)["items"]}
    assert {"display_none", "visibility_hidden", "opacity_zero", "font_size_zero", "offscreen", "same_color",
            "css_order", "css_after", "fullwidth_digits", "native_digits", "homoglyphs", "zero_width",
            "soft_hyphen", "word_joiner", "bidi_override", "svg_text"} <= obf  # fmt: skip
    assert {"base64", "hex", "url", "json"} <= enc
    assert {"url_query", "url_fragment", "url_path", "attribute", "script", "image", "css_content"} <= chans


@pytest.mark.parametrize("seed", range(10))
def test_other_seeds(tmp_path: Path, seed: int) -> None:
    build(tmp_path, seed=seed)
    for page in REDTEAM:
        t = json.loads((tmp_path / "truth" / "redteam" / f"{page}.json").read_text("utf-8"))
        for it in t["items"]:
            assert v.validate(it["type"], it["value"]), it["id"]
    test_values_sit_in_their_channel(tmp_path, "split")
    test_tricks_defeat_a_naive_scan(tmp_path, "lookalike")
    test_tricks_defeat_a_naive_scan(tmp_path, "encoded")
