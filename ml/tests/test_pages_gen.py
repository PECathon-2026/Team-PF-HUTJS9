"""Synthetic page generator: deterministic, labels correct and complete, splits clean."""

from __future__ import annotations

import hashlib
import html
import json
import re
import unicodedata
from pathlib import Path
from typing import Any

import pytest
from bs4 import BeautifulSoup

from gen import pages as P
from gen import values as v

N = 70  # 10 pages per family


@pytest.fixture(scope="module")
def out(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("synth")
    P.generate(d, seed=7, n=N)
    return d


def truths(out: Path) -> list[dict[str, Any]]:
    return [json.loads(f.read_text("utf-8")) for f in sorted((out / "truth").glob("*.json"))]


def doc(out: Path, pid: str) -> BeautifulSoup:
    return BeautifulSoup((out / "pages" / pid / "index.html").read_text("utf-8"), "html.parser")


def normalize(s: str) -> str:
    return re.sub("[\u200b-\u200f\u2060\ufeff]", "", unicodedata.normalize("NFKC", s))


def test_families_splits_and_languages(out: Path) -> None:
    m = json.loads((out / "manifest.json").read_text("utf-8"))
    assert len(P.FAMILIES) >= 6 and m["n_pages"] == N
    fams_by_split = m["splits"]
    assert set(fams_by_split) == {"train", "calibration", "test"}
    all_fams = [f for fs in fams_by_split.values() for f in fs]
    assert len(all_fams) == len(set(all_fams)) == len(P.FAMILIES)  # no family in two splits
    for e in m["pages"]:
        assert e["split"] == P.FAMILY_SPLIT[e["family"]]
        assert e["family"] in fams_by_split[e["split"]]
    assert {e["family"] for e in m["pages"]} == set(P.FAMILIES)
    assert {e["language"] for e in m["pages"]} == set(P.LANGS)


def test_family_split_is_pinned() -> None:
    # Changing this mapping silently moves test families into training. Update only with a new generator version.
    assert P.FAMILY_SPLIT == {
        "form_stack": "train", "form_grid": "train", "data_table": "train", "profile_card": "train",
        "chat_thread": "calibration", "receipt": "test", "kyc_upload": "test",
    }  # fmt: skip


def test_scenario_pages_are_not_a_family() -> None:
    assert not set(P.FAMILIES) & {"login", "checkout", "support", "video", "devsettings"}


def test_items_validate_and_sit_where_annotated(out: Path) -> None:
    channels = set()
    for t in truths(out):
        d = doc(out, t["page_id"])
        for it in t["items"]:
            channels.add(it["channel"])
            assert v.validate(it["type"], it["value"]), it["id"]
            found = d.select(it["selector"])
            assert len(found) == 1, it["id"]
            el = found[0]
            if it["channel"] == "input_value":
                assert el.name == "input" and el.get("value") == it["shown"], it["id"]
            elif it["channel"] in ("text", "table_cell"):
                assert it["shown"] in el.get_text(), it["id"]
                if it["channel"] == "table_cell":
                    assert el.name == "td"
            elif it["channel"] == "image":
                assert el.name == "img" and el.get("src") == it["asset"], it["id"]
                assert (out / "pages" / t["page_id"] / it["asset"]).is_file()
                x, y, w, h = it["img_box"]
                assert x >= 0 and y >= 0 and w > 0 and h > 0
                assert x + w <= int(str(el.get("width"))) and y + h <= int(str(el.get("height")))
            else:
                pytest.fail(it["channel"])
            if it["type"] not in ("name", "password", "address"):
                assert v.validate(it["type"], it["shown"]) or v.validate(it["type"], it["shown"].replace("-", "")), it
    assert channels == {"input_value", "text", "table_cell", "image"}


def test_decoys_present_and_fail_validation(out: Path) -> None:
    kinds = set()
    for t in truths(out):
        d = doc(out, t["page_id"])
        assert t["decoys"], t["page_id"]
        for it in t["decoys"]:
            kinds.add(it["label"])
            assert not v.validate(it["type"], it["value"]), it
            assert it["value"] in d.select_one(it["selector"]).get_text()  # type: ignore[union-attr]
    assert kinds == set(P.DECOY_KINDS)


_DIGIT_RUN = re.compile(r"\d[\d -]{10,22}\d")
_PAN = re.compile(r"[A-Z]{5}[0-9]{4}[A-Z]")
_IFSC = re.compile(r"[A-Z]{4}0[A-Z0-9]{6}")
_AT = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+")


def test_no_unannotated_sensitive_values(out: Path) -> None:
    for t in truths(out):
        known = [normalize(it["value"]) for it in t["items"]]
        text = normalize(html.unescape((out / "pages" / t["page_id"] / "index.html").read_text("utf-8")))
        found = set()
        for m in _DIGIT_RUN.finditer(text):
            dgt = m.group(0).replace(" ", "").replace("-", "")
            if v.is_card(dgt) or v.is_aadhaar(dgt):
                found.add(dgt)
        found |= {m for m in _PAN.findall(text) if v.is_pan(m)}
        found |= set(_IFSC.findall(text))
        found |= {m for m in _AT.findall(text) if v.is_email(m) or v.is_upi(m)}
        missing = {f for f in found if not any(f in k for k in known)}
        assert not missing, (t["page_id"], missing)


def test_hindi_pages_use_devanagari(out: Path) -> None:
    for t in truths(out):
        page = (out / "pages" / t["page_id"] / "index.html").read_text("utf-8")
        has_dev = bool(re.search("[ऀ-ॿ]", page))
        if t["language"] == "hi":
            assert has_dev, t["page_id"]


def test_truth_not_inside_served_pages(out: Path) -> None:
    for f in (out / "pages").rglob("*"):
        assert f.suffix in ("", ".html", ".png"), f
        if f.suffix == ".html":
            assert "synth_truth" not in f.read_text("utf-8")


def test_no_external_resources(out: Path) -> None:
    ext = re.compile(r"""(?:src|href|action)\s*=\s*["']\s*(?:[a-z][a-z0-9+.-]*:|//)""", re.I)
    for f in (out / "pages").rglob("*.html"):
        s = f.read_text("utf-8")
        assert not ext.search(s) and "<script" not in s and "url(" not in s, f


def _hashes(d: Path) -> dict[str, str]:
    return {
        str(f.relative_to(d)): hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(d.rglob("*")) if f.is_file()
    }


def test_deterministic(out: Path, tmp_path: Path) -> None:
    P.generate(tmp_path, seed=7, n=N)
    assert _hashes(tmp_path) == _hashes(out)


def test_seed_changes_pages(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    P.generate(a, seed=1, n=14)
    P.generate(b, seed=2, n=14)
    va = [it["value"] for t in truths(a) for it in t["items"]]
    vb = [it["value"] for t in truths(b) for it in t["items"]]
    assert va != vb


def test_page_is_independent_of_n() -> None:
    """Page i is the same whether 10 or 100 pages are generated (stable datasets)."""
    assert P.generate_page(3, 5)[1] == P.generate_page(3, 5)[1]


@pytest.mark.parametrize("seed", range(8))
def test_other_seeds_stay_correct(tmp_path: Path, seed: int) -> None:
    P.generate(tmp_path, seed=1000 + seed, n=21)
    test_items_validate_and_sit_where_annotated(tmp_path)
    test_decoys_present_and_fail_validation(tmp_path)
    test_no_unannotated_sensitive_values(tmp_path)


def test_unknown_decoy_kind_rejected() -> None:
    p = P.Page("x", "form_stack", "en", 1)
    with pytest.raises(ValueError):
        P.Ctx(p).decoy("nope")
