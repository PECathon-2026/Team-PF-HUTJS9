"""Scenario pages: every annotation validates, sits where it says, and nothing is unannotated."""

from __future__ import annotations

import hashlib
import html
import json
import re
import struct
import unicodedata
import urllib.parse
from pathlib import Path
from typing import Any

import pytest
from bs4 import BeautifulSoup, Tag
from gen import values as v

from plscen.build import build
from plscen.builder import PageBuilder
from plscen.pages import PAGES

INVISIBLE = re.compile("[\u200b-\u200f\u2060\ufeff\u00ad]")


def normalize(s: str) -> str:
    return INVISIBLE.sub("", unicodedata.normalize("NFKC", s))


@pytest.fixture(scope="module")
def out(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("build")
    build(d)
    return d


def truth(out: Path, page: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((out / "truth" / f"{page}.json").read_text("utf-8"))
    return data


def soup(out: Path, page: str) -> BeautifulSoup:
    return BeautifulSoup((out / "site" / page / "index.html").read_text("utf-8"), "html.parser")


def all_items(out: Path) -> list[tuple[str, dict[str, Any]]]:
    return [(p, it) for p in PAGES for it in truth(out, p)["items"]]


def the_element(doc: BeautifulSoup, selector: str) -> Tag:
    found = doc.select(selector)
    assert len(found) == 1, f"{selector!r} matched {len(found)} elements"
    return found[0]


def attr(el: Tag, name: str) -> str:
    val = el.get(name)
    assert isinstance(val, str), f"{name} missing on {el.name}"
    return val


# ---------------------------------------------------------------- annotations


@pytest.mark.parametrize("page", list(PAGES))
def test_every_value_validates(out: Path, page: str) -> None:
    for it in truth(out, page)["items"]:
        assert v.validate(it["type"], it["value"]), it["id"]
        if it["type"] == "name":
            assert it["shown"].lower() == it["value"].lower(), it["id"]
        elif it["type"] != "face":
            assert v.validate(it["type"], normalize(it["shown"])), it["id"]
        if it["obfuscation"]:
            assert it["shown"] != normalize(it["shown"]), f"{it['id']}: obfuscation not actually applied"


@pytest.mark.parametrize("page", list(PAGES))
def test_every_value_sits_in_its_channel(out: Path, page: str) -> None:
    doc = soup(out, page)
    site = out / "site" / page
    for it in truth(out, page)["items"]:
        el = the_element(doc, it["selector"])
        shown, ch = it["shown"], it["channel"]
        if ch == "input_value":
            content = el.get_text() if el.name == "textarea" else attr(el, "value")
            assert el.name in ("input", "textarea") and shown in content, it["id"]
        elif ch == "input_hidden":
            assert el.name == "input" and el.get("type") == "hidden" and attr(el, "value") == shown, it["id"]
        elif ch == "text":
            assert shown in el.get_text(), it["id"]
        elif ch == "text_split":
            spans = el.find_all("span", recursive=False)
            assert len(spans) >= 2, it["id"]
            assert "".join(s.get_text() for s in spans) == shown, it["id"]
            assert all(shown not in s.get_text() for s in spans), it["id"]
        elif ch == "attribute":
            assert shown in attr(el, it["attribute"]), it["id"]
        elif ch == "url_query":
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(attr(el, it["attribute"])).query)
            assert any(shown in vals for vals in query.values()), it["id"]
        elif ch == "image":
            assert el.name == "img" and (site / attr(el, "src")).is_file(), it["id"]
            assert it["asset"] == attr(el, "src"), it["id"]
        elif ch == "canvas":
            assert el.name == "canvas", it["id"]
            x, y, w, h = it["box"]
            amp = (it["motion"] or {}).get("amp_x", 0)
            assert 0 <= x - amp and x + w + amp <= int(attr(el, "width")), it["id"]
            assert 0 <= y and y + h <= int(attr(el, "height")), it["id"]
            if it["asset"]:
                assert (site / it["asset"]).is_file(), it["id"]
        else:
            pytest.fail(f"unknown channel {ch}")


@pytest.mark.parametrize("page", list(PAGES))
def test_decoys_present_and_invalid(out: Path, page: str) -> None:
    doc = soup(out, page)
    for d in truth(out, page)["decoys"]:
        assert d["shown"] in the_element(doc, d["selector"]).get_text()
        assert not v.validate(d["type"], d["value"]), d["id"]


@pytest.mark.parametrize("page", list(PAGES))
def test_canaries_listed(out: Path, page: str) -> None:
    t = truth(out, page)
    assert t["canaries"] == [it["value"] for it in t["items"] if it["canary"]]


def test_faces_on_video_page(out: Path) -> None:
    faces = [it for it in truth(out, "video")["items"] if it["type"] == "face"]
    assert len(faces) == 3
    cfg = json.loads(the_element(soup(out, "video"), "#call-config").get_text())
    for f, it in zip(cfg["faces"], faces, strict=True):
        x, y, w, h = it["box"]
        # The head ellipse centre must sit in the middle of the annotated box.
        assert abs((x + w / 2) - f["cx"]) <= 1 and y < f["cy"] < y + h
        assert it["motion"] == {"amp_x": f["amp_x"], "period_ms": f["period_ms"]}


# ---------------------------------------------------------------- completeness

_DIGIT_RUN = re.compile(r"\d[\d -]{10,22}\d")
_PAN = re.compile(r"[A-Z]{5}[0-9]{4}[A-Z]")
_EMAILISH = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+")
_KEYS = re.compile(r"sk-[\w-]{20,}|ghp_\w{36}|AKIA[A-Z2-7]{16}|eyJ[\w-]+\.[\w-]+\.[\w-]+|PLCANARY-[\w-]+")


def _page_text(out: Path, page: str) -> str:
    raw = (out / "site" / page / "index.html").read_text("utf-8")
    return normalize(urllib.parse.unquote(html.unescape(raw)))


@pytest.mark.parametrize("page", list(PAGES))
def test_no_unannotated_sensitive_values(out: Path, page: str) -> None:
    """Every card/Aadhaar/PAN/email/UPI/key-shaped string in the page is annotated."""
    t = truth(out, page)
    known = {normalize(it["value"]) for it in t["items"]}
    text = _page_text(out, page)
    found: set[str] = set()
    for m in _DIGIT_RUN.finditer(text):
        d = m.group(0).replace(" ", "").replace("-", "")
        if v.is_card(d) or v.is_aadhaar(d):
            found.add(d)
    found |= {m for m in _PAN.findall(text) if v.is_pan(m)}
    found |= {m for m in _EMAILISH.findall(text) if v.is_email(m) or v.is_upi(m)}
    found |= set(_KEYS.findall(text))
    # Example domains in placeholder URLs are not personal data.
    found = {f for f in found if not f.endswith(("api.nimbus.example", "hooks.example.com"))}
    # A match inside an annotated value (e.g. a UPI-shaped run inside a password) is covered by it.
    missing = {f for f in found if not any(f in k for k in known)}
    assert not missing, f"unannotated values on {page}: {sorted(missing)}"


def test_hard_channels_covered(out: Path) -> None:
    """The scenario set must exercise every hiding place the spec lists."""
    seen = set()
    for _, it in all_items(out):
        seen.add(it["channel"] if it["channel"] != "attribute" else f"attr:{it['attribute']}")
        seen.update(f"obf:{o}" for o in it["obfuscation"])
    need = {
        "input_value",
        "input_hidden",
        "text",
        "text_split",
        "url_query",
        "image",
        "canvas",
        "attr:aria-label",
        "attr:alt",
        "attr:title",
        "obf:zero_width",
        "obf:fullwidth_digits",
    }
    assert need <= seen, sorted(need - seen)
    assert any(c.startswith("attr:data-") for c in seen)


# ---------------------------------------------------------------- serving safety


def test_truth_never_served(out: Path) -> None:
    for f in (out / "site").rglob("*"):
        if f.is_file():
            assert f.suffix != ".json"
            assert b"scenario_truth" not in f.read_bytes(), f


_EXTERNAL = re.compile(r"""(?:src|href|action)\s*=\s*["']\s*(?:[a-z][a-z0-9+.-]*:|//)""", re.I)


def test_no_external_resources(out: Path) -> None:
    """Pages load nothing from the network: only relative URLs (sites runs on an internal network)."""
    for f in (out / "site").rglob("*"):
        if f.suffix == ".html":
            assert not _EXTERNAL.search(f.read_text("utf-8")), f
        elif f.suffix == ".css":
            assert "url(" not in f.read_text("utf-8") and "@import" not in f.read_text("utf-8"), f
        elif f.suffix == ".js":
            src = f.read_text("utf-8")
            for bad in ("fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "http:", "https:", "innerHTML"):
                assert bad not in src, (f, bad)


def _png_chunks(data: bytes) -> list[str]:
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    i, names = 8, []
    while i < len(data):
        (n,) = struct.unpack(">I", data[i : i + 4])
        names.append(data[i + 4 : i + 8].decode())
        i += 12 + n
    return names


def test_images_have_no_metadata(out: Path) -> None:
    scenario_pngs = [f for page in PAGES for f in (out / "site" / page).glob("*.png")]
    assert len(scenario_pngs) == 3
    for f in (out / "site").rglob("*.png"):
        assert set(_png_chunks(f.read_bytes())) <= {"IHDR", "IDAT", "IEND"}, f


# ---------------------------------------------------------------- determinism


def _hashes(d: Path) -> dict[str, str]:
    return {
        str(f.relative_to(d)): hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(d.rglob("*")) if f.is_file()
    }


def test_same_seed_same_bytes(out: Path, tmp_path: Path) -> None:
    build(tmp_path)
    assert _hashes(tmp_path) == _hashes(out)


def test_different_seed_different_values(out: Path, tmp_path: Path) -> None:
    build(tmp_path, seed=1)
    for page in PAGES:
        a = {it["id"]: it["value"] for it in truth(out, page)["items"] if it["type"] in ("card", "aadhaar", "email")}
        b = {
            it["id"]: it["value"] for it in truth(tmp_path, page)["items"] if it["type"] in ("card", "aadhaar", "email")
        }
        assert a.keys() == b.keys()
        assert all(a[k] != b[k] for k in a), page


# ---------------------------------------------------------------- builder guards


def test_builder_rejects_slot_mistakes() -> None:
    p = PageBuilder("t")
    p.text("a", "x")
    with pytest.raises(ValueError, match="filled twice"):
        p.text("a", "y")
    with pytest.raises(ValueError, match="missing slots"):
        p.render("{{a}} {{b}}")
    with pytest.raises(ValueError, match="unused slots"):
        p.render("nothing")
    with pytest.raises(ValueError, match="more than once"):
        p.render("{{a}}{{a}}")
    with pytest.raises(ValueError, match="unknown channel"):
        p.put("c", type="email", value="a@example.com", selector="#c", channel="nope")
    with pytest.raises(ValueError, match="needs `attribute`"):
        p.put("d", type="email", value="a@example.com", selector="#d", channel="attribute")
    with pytest.raises(ValueError, match="split parts"):
        p.put_split("e", type="card", value="4111111111111111", shown="4111111111111111", selector="#e", parts=[4])


def test_values_are_escaped() -> None:
    p = PageBuilder("t")
    p.text("a", '"><script>x</script>')
    assert "<script>" not in p.render('<p title="{{a}}"></p>')


@pytest.mark.parametrize("seed", range(25))
def test_core_checks_hold_for_other_seeds(tmp_path: Path, seed: int) -> None:
    """Annotations stay correct whatever values the generator draws."""
    build(tmp_path, seed=seed)
    for page in PAGES:
        test_every_value_validates(tmp_path, page)
        test_every_value_sits_in_its_channel(tmp_path, page)
        test_no_unannotated_sensitive_values(tmp_path, page)
        test_decoys_present_and_invalid(tmp_path, page)
