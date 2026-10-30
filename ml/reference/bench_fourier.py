"""Measure pl_fourier against the numbers spec §10 claims. Prints JSON.

    tools/win/pyrun.sh ml uv run python -m reference.bench_fourier

Numbers are recorded as measured (docs/status/win.md); nothing is tuned to hit them.
"""

from __future__ import annotations

import json
import platform
import random
import string
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image, ImageFilter

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
from test_fourier import _fourier_shift, page_image, perturb, text_box

from reference import pl_fourier as F


def timed(fn: Any, reps: int) -> tuple[float, float]:
    ts = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        ts.append(time.perf_counter() - t0)
    return float(np.median(ts) * 1e3), float(np.percentile(ts, 99) * 1e3)


def bench_phase() -> dict[str, Any]:
    tall = page_image(480, 270 + 120, seed=3, lines=18)
    int_err: list[float] = []
    for dy in range(-50, 51, 5):
        s = F.phase_correlation(tall[60 : 60 + 270], tall[60 - dy : 60 - dy + 270])
        int_err.append(abs(s.dy - dy) + abs(s.dx))
    smooth = np.asarray(
        Image.fromarray(page_image(seed=5).astype(np.uint8)).filter(ImageFilter.GaussianBlur(1.5)), float
    )
    rng = np.random.default_rng(0)
    sub_err: list[float] = []
    for _ in range(40):
        fy, fx = float(rng.uniform(-20, 20)), float(rng.uniform(-20, 20))
        s = F.phase_correlation(smooth, _fourier_shift(smooth, fy, fx), window=False)
        sub_err.append(max(abs(s.dy - fy), abs(s.dx - fx)))
    a, b = tall[60:330], tall[50:320]
    p50, p99 = timed(lambda: F.phase_correlation(a, b), 100)
    return {
        "frame": "480x270",
        "scroll_crop_max_abs_error_px": round(max(int_err), 3),
        "subpixel_mean_abs_error_px": round(float(np.mean(sub_err)), 3),
        "subpixel_max_abs_error_px": round(float(np.max(sub_err)), 3),
        "time_ms_p50": round(p50, 2),
        "time_ms_p99": round(p99, 2),
    }


def bench_fuzzy() -> dict[str, Any]:
    rng = random.Random(1)
    text = "".join(rng.choice(string.ascii_letters + string.digits + " ,.:") for _ in range(200_000))
    card = "4532015112830366"
    p50, p99 = timed(lambda: F.fuzzy_find(text, card, 2, 12), 10)
    return {"chars": 200_000, "secret_len": 16, "time_ms_p50": round(p50, 1), "time_ms_p99": round(p99, 1)}


def bench_flatness() -> dict[str, Any]:
    out: dict[str, Any] = {}
    pages = [page_image(seed=s, lines=random.Random(s).randint(4, 13)) for s in range(300, 320)]
    for amp in (0, 0.4, 1, 2, 4, 6):
        reps = [F.spectral_flatness_score(perturb(p, amp, seed=i) if amp else p) for i, p in enumerate(pages)]
        out[f"amp_{amp}"] = {
            "score_mean": round(float(np.mean([r.score for r in reps])), 3),
            "score_min": round(float(np.min([r.score for r in reps])), 3),
            "score_max": round(float(np.max([r.score for r in reps])), 3),
            "flagged": f"{sum(r.perturbed for r in reps)}/{len(reps)}",
        }
    return out


def bench_dct() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for bg in ("white", "gray"):
        for amp in (2, 4, 6):
            red, iou = [], []
            for s in range(400, 410):
                clean = page_image(seed=s, lines=random.Random(s).randint(4, 13))
                if bg == "gray":
                    clean = np.where(clean > 200, 170.0, clean)
                noisy = perturb(clean, amp, seed=s)
                den = np.clip(np.rint(F.dct_denoise(noisy)), 0, 255)
                red.append(1 - np.mean((den - clean) ** 2) / np.mean((noisy - clean) ** 2))
                ink_c, ink_d = clean < 128, den < 128
                iou.append(np.sum(ink_c & ink_d) / np.sum(ink_c | ink_d))
            out[f"{bg}_amp_{amp}"] = {
                "mse_reduction_mean": round(float(np.mean(red)), 3),
                "mse_reduction_min": round(float(np.min(red)), 3),
                "text_ink_iou_mean": round(float(np.mean(iou)), 3),
            }
    img = page_image(seed=9)
    p50, _ = timed(lambda: F.dct_denoise(img), 20)
    out["time_ms_p50_480x270"] = round(p50, 1)
    return out


def bench_redaction() -> dict[str, Any]:
    box = text_box()
    cases = {
        "solid": np.zeros((40, 160)),
        "blur_r4": np.asarray(box.filter(ImageFilter.GaussianBlur(4)), float),
        "pixelate_8": np.asarray(
            box.resize((20, 5), Image.Resampling.BOX).resize((160, 40), Image.Resampling.NEAREST), float
        ),
        "visible_text": np.asarray(box, float),
        "low_contrast_text_20_on_0": np.asarray(text_box(fill=0, ink=20), float),
        "low_contrast_text_3_on_0": np.asarray(text_box(fill=0, ink=3), float),
    }
    return {k: {"ok": v.ok, "reason": v.reason} for k, v in ((k, F.check_redaction(a)) for k, a in cases.items())}


WORDS = (
    "the of and to in is you that it he was for on are as with his they at be this have from or one had "
    "by word but not what all were we when your can said there use an each which she do how their if will "
    "up other about out many then them these so some her would make like him into time has look two more "
    "write go see number no way could people my than first water been call who oil its now find long down "
    "day did get come made may part "
).split()


def bench_nist() -> dict[str, Any]:
    rng = random.Random(5)
    b62 = string.ascii_letters + string.digits
    out = {}
    for n_chars in (40, 100, 400):
        keys = ["".join(rng.choice(b62) for _ in range(n_chars)) for _ in range(50)]
        prose = [" ".join(rng.choice(WORDS) for _ in range(n_chars))[:n_chars] for _ in range(50)]
        rnd = [bytes(rng.getrandbits(8) for _ in range(n_chars)) for _ in range(50)]
        row: dict[str, float] = {
            "random_bytes_pass_rate": sum(
                F.nist_spectral_test("".join(f"{b:08b}" for b in r)).p_value >= 0.01 for r in rnd
            )
            / 50
        }
        for enc in ("b64index", "utf8"):
            row[f"base62_key_pass_rate_{enc}"] = (
                sum(F.nist_spectral_test(F.string_bits(k, enc)).p_value >= 0.01 for k in keys) / 50
            )
            row[f"english_pass_rate_{enc}"] = (
                sum(F.nist_spectral_test(F.string_bits(p, enc)).p_value >= 0.01 for p in prose) / 50
            )
        out[f"{n_chars}_chars"] = row
    return out


def main() -> None:
    res = {
        "machine": f"{platform.machine()} {platform.processor() or ''}".strip(),
        "python": platform.python_version(),
        "numpy": np.__version__,
        "phase_correlation": bench_phase(),
        "fuzzy_find": bench_fuzzy(),
        "spectral_flatness": bench_flatness(),
        "dct_denoise": bench_dct(),
        "redaction_checker": bench_redaction(),
        "nist_spectral": bench_nist(),
    }
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
