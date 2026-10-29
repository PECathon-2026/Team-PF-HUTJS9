"""Tests for ml/reference/pl_fourier.py. Correctness only: speed and the spec's
headline numbers are measured by ml/reference/bench_fourier.py and recorded
as measured in docs/status/win.md."""

from __future__ import annotations

import io
import math
import random
import string

import numpy as np
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from PIL import Image, ImageDraw, ImageFilter, ImageFont

from reference import pl_fourier as F

# ---------------------------------------------------------------- test images


def page_image(w: int = 480, h: int = 270, seed: int = 0, lines: int = 12) -> F.F64:
    """A synthetic UI screenshot: white page, dark text lines, a few boxes."""
    rng = random.Random(seed)
    img = Image.new("L", (w, h), 255)
    d = ImageDraw.Draw(img)
    font = ImageFont.load_default(size=14)
    y = 6
    for _ in range(lines):
        words = " ".join("".join(rng.choice(string.ascii_letters) for _ in range(rng.randint(2, 9))) for _ in range(8))
        d.text((10, y), words, fill=rng.randint(0, 60), font=font)
        y += rng.randint(18, 26)
    for _ in range(3):
        x0, y0 = rng.randint(0, w - 80), rng.randint(0, h - 30)
        d.rectangle((x0, y0, x0 + rng.randint(30, 80), y0 + rng.randint(12, 30)), outline=90)
    return np.asarray(img, dtype=np.float64)


def text_box(
    w: int = 160, h: int = 40, fill: int = 0, ink: int = 255, text: str = "4111 1111 1111 1111"
) -> Image.Image:
    img = Image.new("L", (w, h), fill)
    ImageDraw.Draw(img).text((6, 10), text, fill=ink, font=ImageFont.load_default(size=16))
    return img


def arr(img: Image.Image) -> F.F64:
    return np.asarray(img, dtype=np.float64)


def png_roundtrip(a: F.F64) -> F.F64:
    buf = io.BytesIO()
    Image.fromarray(np.clip(np.rint(a), 0, 255).astype(np.uint8)).save(buf, "PNG")
    return arr(Image.open(io.BytesIO(buf.getvalue())))


# ---------------------------------------------------------------- phase correlation


@pytest.mark.parametrize("dy", [0, 1, 7, 33, -12])
def test_phase_correlation_finds_scroll_offset(dy: int) -> None:
    """Real scrolling: two crops of a taller page, not a circular shift."""
    tall = page_image(480, 270 + 80, seed=3, lines=16)
    base = 40
    a = tall[base : base + 270]
    b = tall[base - dy : base - dy + 270]
    s = F.phase_correlation(a, b)
    assert round(s.dy) == dy and round(s.dx) == 0
    assert s.peak > 0.1


def _fourier_shift(a: F.F64, dy: float, dx: float) -> F.F64:
    h, w = a.shape
    ky = np.fft.fftfreq(h)[:, None]
    kx = np.fft.fftfreq(w)[None, :]
    return np.real(np.fft.ifft2(np.fft.fft2(a) * np.exp(-2j * np.pi * (ky * dy + kx * dx))))


@pytest.mark.parametrize(("dy", "dx"), [(0.5, 0.0), (3.25, -1.75), (-10.6, 4.4), (0.1, 0.9)])
def test_phase_correlation_sub_pixel(dy: float, dx: float) -> None:
    smooth = arr(Image.fromarray(page_image(seed=5).astype(np.uint8)).filter(ImageFilter.GaussianBlur(1.5)))
    b = _fourier_shift(smooth, dy, dx)
    s = F.phase_correlation(smooth, b, window=False)
    assert abs(s.dy - dy) < 0.5 and abs(s.dx - dx) < 0.5, s


def test_phase_correlation_rejects_bad_shapes() -> None:
    with pytest.raises(ValueError):
        F.phase_correlation(np.zeros((4, 4)), np.zeros((4, 5)))


def test_phase_correlation_low_peak_for_unrelated_frames() -> None:
    s_same = F.phase_correlation(page_image(seed=1), page_image(seed=1))
    s_diff = F.phase_correlation(page_image(seed=1), page_image(seed=2))
    assert s_diff.peak < s_same.peak / 3


# ---------------------------------------------------------------- redaction checker


@pytest.mark.parametrize("level", [0, 17, 128, 255])
def test_solid_fill_passes(level: int) -> None:
    v = F.check_redaction(png_roundtrip(np.full((40, 160), float(level))))
    assert v.ok and v.reason == "solid"


@pytest.mark.parametrize("radius", [2.0, 4.0, 8.0])
def test_blur_fails_as_blur(radius: float) -> None:
    v = F.check_redaction(arr(text_box().filter(ImageFilter.GaussianBlur(radius))))
    assert not v.ok and v.reason == "blur", v


@pytest.mark.parametrize("block", [4, 8, 10])
def test_pixelation_fails_as_pixelation(block: int) -> None:
    img = text_box(160, 40)
    small = img.resize((160 // block, 40 // block), Image.Resampling.BOX)
    v = F.check_redaction(arr(small.resize((160 // block * block, 40 // block * block), Image.Resampling.NEAREST)))
    assert not v.ok and v.reason == "pixelation", v


@pytest.mark.parametrize(("fill", "ink"), [(0, 255), (0, 60), (255, 0), (20, 0)])
def test_visible_text_fails_as_visible_detail(fill: int, ink: int) -> None:
    v = F.check_redaction(arr(text_box(fill=fill, ink=ink)))
    assert not v.ok and v.reason == "visible_detail", v


def test_redaction_checker_ignores_one_pixel_antialiased_rim() -> None:
    a = np.zeros((40, 160))
    a[0, :] = 128
    a[:, -1] = 200
    assert F.check_redaction(a).ok


def test_redaction_checker_rejects_tiny_regions() -> None:
    with pytest.raises(ValueError):
        F.check_redaction(np.zeros((3, 10)))


# ---------------------------------------------------------------- fuzzy search


def naive_find(text: str, secret: str, max_mm: int, min_vis: int, ignore: str = " -") -> list[tuple[int, int]]:
    keep = [i for i, c in enumerate(text) if c not in ignore]
    t = "".join(text[i] for i in keep)
    p = "".join(c for c in secret if c not in ignore)
    out, last_end = [], -1
    for i in range(len(t) - len(p) + 1):
        if i < last_end:
            continue
        vis = sum(1 for j in range(len(p)) if t[i + j] not in F.MASK_CHARS)
        mm = sum(1 for j in range(len(p)) if t[i + j] not in F.MASK_CHARS and t[i + j] != p[j])
        if mm <= max_mm and vis >= min_vis:
            out.append((keep[i], mm))
            last_end = i + len(p)
    return out


@given(
    text=st.text(alphabet="0123456789*- ", min_size=0, max_size=80),
    secret=st.text(alphabet="0123456789", min_size=1, max_size=12),
    max_mm=st.integers(0, 3),
    min_vis=st.integers(0, 8),
)
@settings(max_examples=400)
def test_fuzzy_find_matches_brute_force(text: str, secret: str, max_mm: int, min_vis: int) -> None:
    got = [(m.start, m.mismatches) for m in F.fuzzy_find(text, secret, max_mm, min_vis)]
    assert got == naive_find(text, secret, max_mm, min_vis)


def test_fuzzy_find_ocr_mangled_card_in_large_log() -> None:
    rng = random.Random(11)
    card = "4532015112830366"
    noise = "".join(rng.choice(string.ascii_letters + string.digits + " ,.:") for _ in range(200_000))
    mangled = "4532 0151 1283 O366"  # OCR read 0 as O: one mismatch
    pos = 123_456
    text = noise[:pos] + mangled + noise[pos:]
    hits = F.fuzzy_find(text, card, max_mismatches=2, min_visible=12)
    assert [h.start for h in hits] == [pos]
    assert hits[0].mismatches == 1 and text[hits[0].start : hits[0].end] == mangled


def test_masked_characters_count_as_matches_but_need_enough_visible() -> None:
    card = "4111111111111111"
    assert F.fuzzy_find("card **** **** **** 1111", card, 0, min_visible=6) == []  # last-4 only: 4 visible
    hits = F.fuzzy_find("card 4111 11** **** 1111", card, 0, min_visible=6)
    assert len(hits) == 1 and hits[0].visible == 10
    assert F.fuzzy_find("•••• •••• •••• ••••", card, 0, min_visible=1) == []


def test_fuzzy_find_empty_inputs() -> None:
    assert F.fuzzy_find("", "123") == []
    assert F.fuzzy_find("123", "") == []


# ---------------------------------------------------------------- spectral flatness


def perturb(a: F.F64, amp: float, seed: int = 0) -> F.F64:
    rng = np.random.default_rng(seed)
    noisy = a + rng.uniform(-amp, amp, a.shape)
    return np.clip(np.rint(noisy), 0, 255)  # 8-bit, like a real screenshot


def test_clean_pages_are_not_flagged() -> None:
    for seed in range(100, 120):
        r = F.spectral_flatness_score(page_image(seed=seed, lines=random.Random(seed).randint(4, 13)))
        assert not r.perturbed, (seed, r)


@pytest.mark.parametrize("amp", [2, 4, 6])
def test_perturbed_pages_are_flagged(amp: int) -> None:
    for seed in range(200, 210):
        clean = page_image(seed=seed, lines=random.Random(seed).randint(4, 13))
        r = F.spectral_flatness_score(perturb(clean, amp, seed=seed))
        assert r.perturbed, (amp, seed, r)


def test_sub_quantisation_noise_is_undetectable() -> None:
    """Below 0.5/255 the noise rounds away in 8 bits: the image is unchanged."""
    clean = page_image(seed=7)
    assert np.array_equal(perturb(clean, 0.4), clean)
    assert F.spectral_flatness_score(perturb(clean, 0.4)) == F.spectral_flatness_score(clean)


def test_empty_image_has_no_tiles() -> None:
    assert F.spectral_flatness_score(np.full((64, 64), 255.0)).tiles == 0


# ---------------------------------------------------------------- DCT denoiser


def test_dct_is_orthonormal() -> None:
    d = F._dct_matrix(8)
    assert np.allclose(d @ d.T, np.eye(8))


def test_dct_denoise_reduces_noise() -> None:
    clean = page_image(seed=9)
    noisy = perturb(clean, 6)
    out = dct_round(F.dct_denoise(noisy))
    assert np.mean((out - clean) ** 2) < np.mean((noisy - clean) ** 2)


def dct_round(a: F.F64) -> F.F64:
    return np.clip(np.rint(a), 0, 255)


def test_dct_denoise_keeps_solid_boxes_exact() -> None:
    a = page_image(seed=4)
    a[40:120, 200:400] = 0.0  # a redaction box aligned to the 8x8 grid
    out = dct_round(F.dct_denoise(a))
    assert np.array_equal(out[40:120, 200:400], a[40:120, 200:400])


def test_dct_denoise_keeps_text_readable() -> None:
    clean = page_image(seed=9)
    out = dct_round(F.dct_denoise(perturb(clean, 6)))
    ink_a, ink_b = clean < 128, out < 128
    iou = np.sum(ink_a & ink_b) / np.sum(ink_a | ink_b)
    assert iou > 0.8, iou


def test_dct_denoise_leaves_clean_pages_alone() -> None:
    clean = page_image(seed=9)
    assert F.estimate_noise_sigma(clean) == 0.0
    assert np.array_equal(dct_round(F.dct_denoise(clean)), clean)


def test_noise_sigma_estimate_is_close_on_gray_background() -> None:
    clean = np.where(page_image(seed=9) > 200, 170.0, page_image(seed=9))
    for amp in (2.0, 4.0, 6.0):
        est = F.estimate_noise_sigma(perturb(clean, amp))
        true = float(np.std(perturb(clean, amp) - clean))
        assert 0.7 * true < est < 1.3 * true, (amp, est, true)


def test_dct_denoise_handles_odd_sizes() -> None:
    a = page_image(101, 59, seed=2)
    assert F.dct_denoise(a).shape == (59, 101)


# ---------------------------------------------------------------- NIST spectral test


# NIST SP 800-22 rev 1a, §2.6.8 example (n = 100, first 100 bits of e's binary expansion).
NIST_268 = "1100100100001111110110101010001000100001011010001100001000110100110001001100011001100010100010111000"


def test_nist_d_and_p_match_both_documented_examples() -> None:
    # §2.6.4: n = 10, N1 = 4 -> d = -2.176429, P = 0.029523
    d, p = F.nist_d_p(10, 4)
    assert math.isclose(d, -2.176429, abs_tol=5e-6) and math.isclose(p, 0.029523, abs_tol=5e-6)
    # §2.6.8: n = 100, N1 = 46 -> d = -1.376494, P = 0.168669
    d, p = F.nist_d_p(100, 46)
    assert math.isclose(d, -1.376494, abs_tol=5e-6) and math.isclose(p, 0.168669, abs_tol=5e-6)


def test_nist_peak_count_follows_the_stated_steps() -> None:
    """The document's example N1 values (4 and 46) don't follow from its own
    steps 1-6: for these inputs |S'| has 0 and 2 peaks at or above T, giving
    N1 = 5 and 48. We tried both T formulas (rev1a ln, old sqrt(3n)) and every
    index range; none gives 4 and 46. Recorded in docs/status/win.md; the C++
    port is cross-checked against this implementation of the stated steps."""
    r10 = F.nist_spectral_test("1001010011")
    assert r10.n1 == 5 and math.isclose(r10.n0, 4.75)
    r100 = F.nist_spectral_test(NIST_268)
    assert r100.n1 == 48 and math.isclose(r100.n0, 47.5)


def test_nist_random_bits_pass_and_periodic_fail() -> None:
    bits = np.random.default_rng(1).integers(0, 2, 100_000)
    assert F.nist_spectral_test(bits).p_value >= 0.01
    assert F.nist_spectral_test("01" * 50_000).p_value < 0.01
    assert F.nist_spectral_test("0011" * 25_000).p_value < 0.01


def test_nist_rejects_bad_input() -> None:
    with pytest.raises(ValueError):
        F.nist_spectral_test("0")
    with pytest.raises(ValueError):
        F.nist_spectral_test(np.array([0, 1, 2]))


def test_string_bits() -> None:
    assert F.string_bits("A", "utf8") == "01000001"
    assert F.string_bits("A") == "000000" and F.string_bits("_") == "111111" and F.string_bits(" ") == "111111"
    with pytest.raises(ValueError):
        F.string_bits("A", "rot13")
