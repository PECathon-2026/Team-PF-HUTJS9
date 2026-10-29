"""PrivacyLens Fourier reference (spec §10). Owner: WIN.

Python/NumPy reference for the techniques the C++ ``daemons/core/fourier``
library ports in Phase 2. The C++ port is cross-checked against this file.

Images are 2-D float arrays in [0, 255] (grayscale). Nothing here touches the
network or stores values.

Functions:
    phase_correlation      scroll tracking, sub-pixel shift between two frames
    check_redaction        is a redaction box truly empty? (with a reason)
    fuzzy_find             FFT mismatch counting with masked characters
    spectral_flatness_score  hidden-perturbation detector over tiles
    dct_denoise            8x8 block DCT hard-threshold denoiser
    nist_spectral_test     NIST SP 800-22 discrete Fourier transform test
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray

F64 = NDArray[np.float64]

# --------------------------------------------------------------------------
# Scroll tracking: phase correlation
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Shift:
    dy: float  # b is a shifted by (dy, dx): b[y, x] ≈ a[y - dy, x - dx]
    dx: float
    peak: float  # correlation peak height in [0, 1]; low means "no reliable match"


def _hann2d(h: int, w: int) -> F64:
    return np.outer(np.hanning(h), np.hanning(w))


def _parabolic(cm: float, c0: float, cp: float) -> float:
    denom = cm - 2 * c0 + cp
    return 0.0 if denom == 0 else 0.5 * (cm - cp) / denom


def phase_correlation(a: F64, b: F64, window: bool = True) -> Shift:
    """Translation of ``b`` relative to ``a`` via the normalised cross-power spectrum.

    A shift multiplies the spectrum by a linear phase, so the inverse FFT of
    the normalised cross-power spectrum is a single peak at the shift. The
    integer peak is refined to sub-pixel precision with a 3-point parabola on
    each axis.
    """
    if a.shape != b.shape or a.ndim != 2:
        raise ValueError("frames must be 2-D and the same shape")
    h, w = a.shape
    win = _hann2d(h, w) if window else 1.0
    fa = np.fft.rfft2((a - a.mean()) * win)
    fb = np.fft.rfft2((b - b.mean()) * win)
    cross = fb * np.conj(fa)
    mag = np.abs(cross)
    cross /= np.where(mag > 1e-12, mag, 1.0)
    r = np.fft.irfft2(cross, s=(h, w))
    py, px = np.unravel_index(int(np.argmax(r)), r.shape)
    peak = float(r[py, px])
    fy = _parabolic(r[(py - 1) % h, px], r[py, px], r[(py + 1) % h, px])
    fx = _parabolic(r[py, (px - 1) % w], r[py, px], r[py, (px + 1) % w])
    dy = py + fy
    dx = px + fx
    if dy > h / 2:
        dy -= h
    if dx > w / 2:
        dx -= w
    return Shift(float(dy), float(dx), peak)


# --------------------------------------------------------------------------
# Redaction checker
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RedactionVerdict:
    ok: bool
    reason: str  # "solid" | "blur" | "pixelation" | "visible_detail"
    ac_rms: float  # RMS of everything except the mean brightness
    high_freq_fraction: float  # share of AC energy above half the Nyquist radius
    block_periodicity: float  # strength of a periodic block-edge pattern


# A redaction box re-encoded as PNG must be exactly flat; allow for
# antialiasing at the very border by ignoring a 1 px rim.
SOLID_AC_RMS = 0.5


def _block_periodicity(region: F64) -> float:
    """How strongly edges sit on a regular grid (pixelation leaves edges only at
    block boundaries).

    Per axis, edge energy summed per column/row gives a 1-D signal; for a
    pixelated region it's a pulse train with period = block size. We measure
    the share of edge energy that falls on the best comb (period 3..32, any
    offset). Pixelation gives ~1.0 on both axes; text and blur spread their
    edges and score far lower. Returns the smaller of the two axis scores.
    """
    scores = []
    for axis in (0, 1):
        g = np.abs(np.diff(region, axis=1 - axis)).sum(axis=axis)
        total = float(g.sum())
        if g.size < 8 or total == 0:
            return 0.0
        best = 0.0
        for period in range(3, min(32, g.size // 2) + 1):
            # Comb filter: fold the signal by `period`, take the strongest phase.
            n = g.size - g.size % period
            folded = g[:n].reshape(-1, period).sum(axis=0)
            best = max(best, float(folded.max()) / float(g[:n].sum() or 1.0))
        scores.append(best)
    return min(scores)


def check_redaction(region: F64) -> RedactionVerdict:
    """A perfect solid fill has only DC energy. Leftover energy fails, and where it
    sits says why: periodic block edges ⇒ pixelation, mostly high frequencies ⇒
    visible text/edges, mostly low frequencies ⇒ blur."""
    r = np.asarray(region, dtype=np.float64)
    if r.ndim != 2 or min(r.shape) < 4:
        raise ValueError("region must be 2-D and at least 4x4")
    inner = r[1:-1, 1:-1]
    ac = inner - inner.mean()
    ac_rms = float(np.sqrt(np.mean(ac**2)))
    power = np.abs(np.fft.fftshift(np.fft.fft2(ac))) ** 2
    h, w = power.shape
    yy, xx = np.mgrid[0:h, 0:w]
    radius = np.hypot((yy - h // 2) / (h / 2), (xx - w // 2) / (w / 2))
    total = float(power.sum())
    hff = float(power[radius > 0.5].sum() / total) if total > 0 else 0.0
    per = _block_periodicity(inner)
    if ac_rms <= SOLID_AC_RMS:
        return RedactionVerdict(True, "solid", ac_rms, hff, per)
    if per > 0.9:
        return RedactionVerdict(False, "pixelation", ac_rms, hff, per)
    if hff > 0.05:
        return RedactionVerdict(False, "visible_detail", ac_rms, hff, per)
    return RedactionVerdict(False, "blur", ac_rms, hff, per)


# --------------------------------------------------------------------------
# FFT fuzzy secret search
# --------------------------------------------------------------------------

MASK_CHARS = frozenset("*•●xX#")


@dataclass(frozen=True)
class FuzzyMatch:
    start: int  # index into the original text
    end: int  # exclusive
    mismatches: int  # visible characters that differ
    visible: int  # characters compared (neither side masked)


def _correlate(text_ind: F64, pat_ind: F64, n_fft: int) -> F64:
    # Cross-correlation: c[i] = sum_j t[i + j] * p[j]
    ft = np.fft.rfft(text_ind, n_fft)
    fp = np.fft.rfft(pat_ind[::-1], n_fft)
    return np.fft.irfft(ft * fp, n_fft)


def fuzzy_find(
    text: str,
    secret: str,
    max_mismatches: int = 2,
    min_visible: int = 6,
    ignore: str = " -",
    mask_chars: frozenset[str] = MASK_CHARS,
) -> list[FuzzyMatch]:
    """Find places where ``secret`` appears with at most ``max_mismatches`` wrong
    characters. Masked characters on the text side (``*``, ``•``…) count as
    matches; at least ``min_visible`` characters must be compared so a fully
    masked run never matches. Characters in ``ignore`` are skipped on both sides,
    so "4111 1111" matches "41111111".

    Cost: one FFT correlation per distinct character in the secret, plus two for
    masks, each O(n log n).
    """
    keep = [i for i, c in enumerate(text) if c not in ignore]
    t = "".join(text[i] for i in keep)
    p = "".join(c for c in secret if c not in ignore)
    n, m = len(t), len(p)
    if m == 0 or n < m:
        return []
    n_fft = 1 << (n + m - 1).bit_length()
    tcodes = np.frombuffer(t.encode("utf-32-le"), dtype=np.uint32)
    t_masked = np.isin(tcodes, [ord(c) for c in mask_chars]).astype(np.float64)
    matches = np.zeros(n + m - 1)
    for ch in set(p):
        ti = (tcodes == ord(ch)).astype(np.float64)
        pi = np.array([1.0 if c == ch else 0.0 for c in p])
        matches += _correlate(ti, pi, n_fft)[: n + m - 1]
    masked = _correlate(t_masked, np.ones(m), n_fft)[: n + m - 1]
    # Window starting at text index i ends at i + m - 1 ⇒ correlation index i + m - 1.
    idx = np.arange(m - 1, n)
    match_n = np.rint(matches[idx]).astype(int)
    masked_n = np.rint(masked[idx]).astype(int)
    visible = m - masked_n
    mism = visible - match_n
    hits = np.nonzero((mism <= max_mismatches) & (visible >= min_visible))[0]
    out = []
    last_end = -1
    for i in hits:
        if i < last_end:  # report non-overlapping, first best
            continue
        out.append(FuzzyMatch(keep[i], keep[i + m - 1] + 1, int(mism[i]), int(visible[i])))
        last_end = i + m
    return out


# --------------------------------------------------------------------------
# Hidden-perturbation detector: spectral flatness over tiles
# --------------------------------------------------------------------------


# Operating point: a page is "perturbed" when more than this share of its
# non-empty tiles is noise-flat. Chosen from clean synthetic pages (score ≈ 0.01);
# the false-positive rate on clean pages is tested over many seeds.
PERTURBED_SCORE = 0.05


@dataclass(frozen=True)
class FlatnessReport:
    score: float  # share of non-empty tiles that look like noise
    mean_flatness: float  # mean high-band flatness over non-empty tiles
    tiles: int  # non-empty tiles examined
    noisy_tiles: int

    @property
    def perturbed(self) -> bool:
        return self.score > PERTURBED_SCORE


def _tile_flatness(tile: F64) -> float:
    """Wiener entropy (geometric / arithmetic mean) of the tile's AC power
    spectrum. White noise gives about e^-γ ≈ 0.56 (the periodogram of white
    noise is exponentially distributed); text and edges give much less,
    because their energy sits at a few frequencies and harmonics."""
    t = tile - tile.mean()
    p = (np.abs(np.fft.rfft2(t)) ** 2).ravel()[1:] + 1e-12
    return float(np.exp(np.mean(np.log(p))) / np.mean(p))


def spectral_flatness_score(img: F64, tile: int = 16, noise_flatness: float = 0.45) -> FlatnessReport:
    """Split into tiles, skip empty ones (exactly flat: a clean UI background),
    and count non-empty tiles whose spectrum is noise-flat.

    Noise hidden *under* text barely changes a text tile's spectrum, so the
    signal comes from background tiles that should be exactly flat but aren't.
    Perturbations below 0.5/255 round away in 8-bit images and can't be
    detected at all (spec §10 says so too)."""
    a = np.asarray(img, dtype=np.float64)
    h, w = a.shape
    flats = []
    for y in range(0, h - tile + 1, tile):
        for x in range(0, w - tile + 1, tile):
            t = a[y : y + tile, x : x + tile]
            if float(t.std()) < 1e-9:
                continue
            flats.append(_tile_flatness(t))
    if not flats:
        return FlatnessReport(0.0, 0.0, 0, 0)
    f = np.array(flats)
    noisy = int(np.sum(f > noise_flatness))
    return FlatnessReport(noisy / len(f), float(f.mean()), len(f), noisy)


# --------------------------------------------------------------------------
# DCT denoiser
# --------------------------------------------------------------------------


def _dct_matrix(n: int = 8) -> F64:
    k = np.arange(n)[:, None]
    i = np.arange(n)[None, :]
    m = np.cos(np.pi * (2 * i + 1) * k / (2 * n)) * math.sqrt(2 / n)
    m[0] /= math.sqrt(2)
    return m  # orthonormal DCT-II


_D8 = _dct_matrix(8)


def _blocks(a: F64) -> tuple[F64, int, int]:
    h, w = a.shape
    ph, pw = (-h) % 8, (-w) % 8
    p = np.pad(a, ((0, ph), (0, pw)), mode="reflect") if (ph or pw) else a
    hh, ww = p.shape
    return p.reshape(hh // 8, 8, ww // 8, 8).transpose(0, 2, 1, 3), hh, ww


def estimate_noise_sigma(img: F64, flat: float = 0.2, min_share: float = 0.02, max_sigma: float = 10.0) -> float:
    """Noise σ from the blocks that look like pure noise.

    For each 8x8 block: AC energy and spectral flatness of its 63 AC
    coefficients. White noise gives about e^-(γ + ln 2) ≈ 0.28 here (each real
    DCT coefficient's power is σ²·χ²₁). Blocks that aren't exactly flat but are noise-flat (> ``flat``)
    are background carrying noise, and their AC RMS is σ. Text blocks are
    excluded (and so is anything with AC RMS ≥ ``max_sigma``: the target is
    *invisible* perturbation, a few grey levels), so text doesn't inflate the estimate. If fewer than ``min_share``
    of the blocks qualify, the image is treated as clean (σ = 0) and
    ``dct_denoise`` leaves it unchanged.
    """
    blocks, _, _ = _blocks(np.asarray(img, dtype=np.float64))
    coef = _D8 @ blocks @ _D8.T
    ac = (coef**2).reshape(*coef.shape[:2], 64)[..., 1:] + 1e-12
    rms = np.sqrt(ac.mean(axis=-1))
    flatness = np.exp(np.log(ac).mean(axis=-1)) / ac.mean(axis=-1)
    noisy = (rms > 1e-5) & (rms < max_sigma) & (flatness > flat)
    if noisy.sum() < min_share * noisy.size:
        return 0.0
    return float(np.median(rms[noisy]))


def dct_denoise(img: F64, threshold: float | None = None, k: float = 2.0) -> F64:
    """Per 8x8 block: orthonormal DCT, zero AC coefficients with |c| < threshold,
    inverse DCT. Strong coefficients (text edges) survive; weak scattered ones
    (noise) are dropped. ``threshold`` defaults to k·σ̂ (``estimate_noise_sigma``).
    A flat block has only a DC coefficient, so solid redaction boxes come out
    unchanged (after rounding). Edges not divisible by 8 are reflect-padded.
    """
    a = np.asarray(img, dtype=np.float64)
    h, w = a.shape
    th = k * estimate_noise_sigma(a) if threshold is None else threshold
    blocks, hh, ww = _blocks(a)
    coef = _D8 @ blocks @ _D8.T
    dc = coef[..., 0, 0].copy()
    coef[np.abs(coef) < th] = 0.0
    coef[..., 0, 0] = dc
    out = _D8.T @ coef @ _D8
    out = out.transpose(0, 2, 1, 3).reshape(hh, ww)[:h, :w]
    return np.clip(out, 0, 255)


# --------------------------------------------------------------------------
# NIST SP 800-22 §2.6 discrete Fourier transform (spectral) test
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class NistResult:
    p_value: float
    n: int
    n1: int  # peaks below threshold
    n0: float  # expected
    d: float


def nist_spectral_test(bits: str | NDArray[np.integer]) -> NistResult:
    """P-value of the DFT test. Random ⇒ p ≥ 0.01. Only meaningful for long
    inputs (NIST recommends n ≥ 1000); for strings, see ``string_bits``."""
    eps = np.array([int(c) for c in bits], dtype=np.int8) if isinstance(bits, str) else np.asarray(bits)
    n = int(eps.size)
    if n < 2 or not np.isin(eps, (0, 1)).all():
        raise ValueError("need a sequence of at least 2 bits")
    x = 2.0 * eps - 1.0
    s = np.fft.fft(x)
    m = np.abs(s[: n // 2])
    t = math.sqrt(math.log(1 / 0.05) * n)
    n0 = 0.95 * n / 2
    n1 = int(np.sum(m < t))
    d, p = nist_d_p(n, n1)
    return NistResult(p, n, n1, n0, d)


def nist_d_p(n: int, n1: int) -> tuple[float, float]:
    """Steps 5-8 of SP 800-22 §2.6.4: normalised difference d and P-value."""
    d = (n1 - 0.95 * n / 2) / math.sqrt(n * 0.95 * 0.05 / 4)
    return d, math.erfc(abs(d) / math.sqrt(2))


B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def string_bits(s: str, encoding: str = "b64index") -> str:
    """Bits of a string for the spectral test.

    ``b64index`` (default): each character's index in the base64url alphabet,
    6 bits; characters outside it map to 63. Uniformly random key characters
    then give near-uniform bits, while text (a few frequent letters, spaces)
    gives structure. ``utf8`` uses raw UTF-8 bytes: ASCII's top bit is always
    0, a period-8 signal that makes random *keys* fail the test, so it's only
    useful for binary data.
    """
    if encoding == "utf8":
        return "".join(f"{b:08b}" for b in s.encode("utf-8"))
    if encoding != "b64index":
        raise ValueError(f"unknown encoding {encoding!r}")
    return "".join(f"{B64URL.find(c) if c in B64URL else 63:06b}" for c in s)
