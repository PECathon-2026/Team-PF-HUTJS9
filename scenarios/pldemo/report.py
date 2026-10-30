"""HTML reports for the data pipeline demo: summary.md, one before/after page per scenario, and a
three.js 3D data-flow scene (index.html). Owner: WIN.

Everything here lives in build/demo (gitignored): the left-hand "your screen" side shows the real
(synthetic) values. Only the redacted outputs and summary.md are copied to scenarios/demo-output.
"""

from __future__ import annotations

import base64
import html
import io
import json
import re
from pathlib import Path
from typing import Any

from PIL import Image

CHIP = re.compile(r"\[REDACTED:[A-Z_]+#\d+\]")
THREE = "https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"


def _row(r: dict[str, Any]) -> str:
    leak = "0 leaks" if not r["leaks"] else f"{len(r['leaks'])} LEAKS"
    pix = "all covered" if not r["pixel_uncovered"] else f"{len(r['pixel_uncovered'])} uncovered"
    vault = f"{r['vault_entries']} sealed; right binding opens, 5 wrong bindings refused" if r["vault_ok"] else "FAILED"
    return (
        f"| {r['page']} | {r['planted']} | {r['detected']} + {r['fail_closed_regions']} image/canvas (fail-closed) | "
        f"{r['placeholders']} | {leak} | {pix} | {vault} | {r['decoys']} |"
    )


def summary_md(results: list[dict[str, Any]], detector: str, session: str) -> str:
    miss = {r["page"]: r["misses"] for r in results if r["misses"]}
    lines = [
        "# Data pipeline demo: summary",
        "",
        f"Detector used: **{detector}** (Python validators; the C++ detect library was not used in this run). "
        "Names are found by a dictionary of the synthetic generator's names (a stand-in; GLiNER is Sprint 2). "
        "Images and canvases are blacked out whole (no OCR yet).",
        "",
        "| page | values planted | detected | placeholders issued | leak check (values + encodings) | "
        "pixel check (planted values under solid black) | vault binding test | decoys kept (must stay visible) |",
        "|---|---|---|---|---|---|---|---|",
        *[_row(r) for r in results],
        "",
        f"Totals: {sum(r['planted'] for r in results)} planted, {sum(r['detected'] for r in results)} detected by the "
        f"detector, {sum(r['fail_closed_regions'] for r in results)} inside images/canvas (blacked out), "
        f"{sum(len(r['leaks']) for r in results)} leaked, {sum(r['placeholders'] for r in results)} placeholders issued.",
        "",
        f"Planted values the detector did NOT catch (by type): {json.dumps(miss) if miss else 'none'}.",
        "",
        "Leak check: every planted value, as rendered and canonical, in these encodings: as is, case-folded, "
        "normalised (look-alikes/invisible characters removed), separators removed (digits only), base64, base64url, "
        "hex, URL-encoded, reversed digits, searched in all string content of what the AI would receive. "
        "Control: the same scan finds the values in the original DOM capture "
        + ", ".join(f"{r['page']} {r['control_found_in_original']}" for r in results)
        + ".",
        "",
        f"Session id of the demo vault: `{session}`. Placeholder numbers are random per run.",
        "",
    ]
    return "\n".join(lines)


def _b64png(png: bytes, width: int = 960) -> str:
    img = Image.open(io.BytesIO(png)).convert("RGB")
    if img.width > width:
        img = img.resize((width, round(img.height * width / img.width)))
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def _tree_html(sanitized: dict[str, Any]) -> str:
    rows = []
    for e in sanitized["elements"]:
        name = CHIP.sub(lambda m: f'<span class="chip">{html.escape(m.group(0))}</span>', html.escape(e["name"]))
        parts = [f'<span class="role">{html.escape(e["role"])}</span>', name or "<i>(no name)</i>"]
        if "data_type" in e:
            parts.append(f'<span class="dt">{html.escape(e["data_type"])}</span>')
        if e.get("pixels_redacted"):
            parts.append('<span class="dt">pixels blacked out</span>')
        rows.append(f'<div class="node" id="{e["element_id"]}">{" ".join(parts)}</div>')
    return "\n".join(rows)


CSS = """
:root{--bg:#07090f;--panel:#0f1420;--ink:#e6edf6;--mut:#8b97ab;--red:#ff4d6d;--cy:#27e1ff;--ok:#3ddc97;--line:#1c2538}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,sans-serif}
a{color:var(--cy)}header{padding:18px 24px;border-bottom:1px solid var(--line)}h1{margin:0;font-size:20px}
.mut{color:var(--mut)}main{padding:20px 24px}table{border-collapse:collapse;width:100%;font-size:13px}
td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:1100px){.cols{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px;overflow:auto}
.panel img{max-width:100%;display:block;border-radius:6px}.left h2{color:var(--red)}.right h2{color:var(--cy)}
h2{margin:0 0 10px;font-size:15px;letter-spacing:.08em;text-transform:uppercase}
.chip{background:#0b3a46;color:var(--cy);border:1px solid #1b6b80;border-radius:999px;padding:0 8px;font:12px ui-monospace,monospace}
.node{padding:3px 0;border-bottom:1px dashed var(--line)}.role{color:var(--mut);font:11px ui-monospace,monospace;margin-right:6px}
.dt{color:#ffd166;font:11px ui-monospace,monospace;margin-left:6px}pre{background:#05070c;border-radius:8px;padding:10px;overflow:auto;max-height:420px;font-size:12px}
.v{color:var(--red);font-family:ui-monospace,monospace}.good{color:var(--ok)}
"""


def page_html(r: dict[str, Any]) -> str:
    rows = "\n".join(
        f"<tr><td>{html.escape(i['type'])}</td><td class='v'>{html.escape(i['shown'])}</td><td class='mut'>{html.escape(i['channel'])}</td></tr>"
        for i in r["truth_items"]
    )
    js = html.escape(json.dumps(r["sanitized"], indent=2, ensure_ascii=False))
    js = CHIP.sub(lambda m: f'<span class="chip">{m.group(0)}</span>', js)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{r["page"]}: before and after</title>
<style>{CSS}</style></head><body><header><h1>{r["page"]}: before / after</h1>
<div class="mut"><a href="index.html">3D view and summary</a> · {r["planted"]} planted · {r["detected"]} detected ·
{r["placeholders"]} placeholders · <span class="good">{len(r["leaks"])} leaks</span></div></header><main>
<div class="cols"><section class="panel left"><h2>Your screen (original)</h2><img src="{r["page"]}/original.png" alt="original">
<h2 style="margin-top:16px">Planted values (synthetic)</h2><table><tr><th>type</th><th>as rendered</th><th>channel</th></tr>{rows}</table></section>
<section class="panel right"><h2>What the AI sees</h2><img src="{r["page"]}/redacted.png" alt="redacted">
<h2 style="margin-top:16px">Sanitized accessibility tree</h2>{_tree_html(r["sanitized"])}
<h2 style="margin-top:16px">Exact JSON sent to the AI</h2><pre>{js}</pre></section></div></main></body></html>"""


SCENE_JS = r"""
const DATA = __DATA__;
const el = (id) => document.getElementById(id);
if (typeof THREE === 'undefined') { el('hud').innerHTML = '<b>three.js could not load (offline?).</b> The 2D before/after pages still work.'; throw new Error('no three'); }
const W = innerWidth, H = innerHeight - 0;
const scene = new THREE.Scene(); scene.fog = new THREE.FogExp2(0x07090f, 0.018);
const cam = new THREE.PerspectiveCamera(55, W / H, 0.1, 400);
const ren = new THREE.WebGLRenderer({antialias: true, canvas: el('c')}); ren.setSize(W, H); ren.setPixelRatio(Math.min(devicePixelRatio, 2));
scene.add(new THREE.AmbientLight(0xffffff, 0.6));
const key = new THREE.PointLight(0x27e1ff, 1.4, 60); key.position.set(0, 8, 8); scene.add(key);
// stars
{ const g = new THREE.BufferGeometry(), n = 1800, p = new Float32Array(n * 3);
  for (let i = 0; i < n * 3; i++) p[i] = (Math.random() - 0.5) * 220;
  g.setAttribute('position', new THREE.BufferAttribute(p, 3));
  scene.add(new THREE.Points(g, new THREE.PointsMaterial({color: 0x6b7a99, size: 0.18, transparent: true, opacity: 0.8}))); }
const grid = new THREE.GridHelper(120, 80, 0x1c2f55, 0x0f1b33); grid.position.y = -6; scene.add(grid);
function label(text, color, scale) {
  const c = document.createElement('canvas'); c.width = 512; c.height = 96; const x = c.getContext('2d');
  x.font = 'bold 44px system-ui'; x.textAlign = 'center'; x.fillStyle = color; x.shadowColor = color; x.shadowBlur = 18; x.fillText(text, 256, 62);
  const s = new THREE.Sprite(new THREE.SpriteMaterial({map: new THREE.CanvasTexture(c), transparent: true, depthWrite: false}));
  s.scale.set(scale * 5.3, scale, 1); return s;
}
const loader = new THREE.TextureLoader();
function screen(x, color) {
  const g = new THREE.Group(); g.position.x = x;
  const frame = new THREE.Mesh(new THREE.BoxGeometry(7.4, 5.4, 0.12), new THREE.MeshBasicMaterial({color}));
  const plane = new THREE.Mesh(new THREE.PlaneGeometry(7, 5), new THREE.MeshBasicMaterial({color: 0x111111}));
  plane.position.z = 0.07; g.add(frame, plane);
  const glow = new THREE.Mesh(new THREE.PlaneGeometry(9, 7), new THREE.MeshBasicMaterial({color, transparent: true, opacity: 0.12, blending: THREE.AdditiveBlending, depthWrite: false}));
  glow.position.z = -0.2; g.add(glow); scene.add(g); return {g, plane};
}
const L = screen(-13, 0xff4d6d), R = screen(13, 0x27e1ff);
L.g.rotation.y = 0.35; R.g.rotation.y = -0.35;
const lt = label('YOUR SCREEN', '#ff4d6d', 1.1); lt.position.set(-13, 4.2, 0); scene.add(lt);
const rt = label('WHAT THE AI SEES', '#27e1ff', 1.1); rt.position.set(13, 4.2, 0); scene.add(rt);
// detector: three gyroscopic rings
const det = new THREE.Group(); det.position.set(-5, 0, 0);
const rings = [0xffd166, 0xff9f1c, 0xffbf69].map((c, i) => { const m = new THREE.Mesh(new THREE.TorusGeometry(1.9 + i * 0.25, 0.05, 12, 90), new THREE.MeshBasicMaterial({color: c})); det.add(m); return m; });
const core = new THREE.Mesh(new THREE.IcosahedronGeometry(0.8, 1), new THREE.MeshBasicMaterial({color: 0xffd166, wireframe: true})); det.add(core); scene.add(det);
const dl = label('DETECT', '#ffd166', 0.8); dl.position.set(-5, 3.2, 0); scene.add(dl);
// sanitizer: gate with scanning beam
const san = new THREE.Group(); san.position.set(2, 0, 0);
san.add(new THREE.Mesh(new THREE.BoxGeometry(0.3, 5, 5), new THREE.MeshBasicMaterial({color: 0x27e1ff, transparent: true, opacity: 0.18})));
const beam = new THREE.Mesh(new THREE.BoxGeometry(0.35, 0.08, 5), new THREE.MeshBasicMaterial({color: 0xffffff})); san.add(beam); scene.add(san);
const sl = label('SANITIZE', '#27e1ff', 0.8); sl.position.set(2, 3.6, 0); scene.add(sl);
// vault: locked cube far below the flow
const vault = new THREE.Group(); vault.position.set(-1, -4.2, -6);
vault.add(new THREE.Mesh(new THREE.BoxGeometry(3, 3, 3), new THREE.MeshBasicMaterial({color: 0x3ddc97, wireframe: true})));
vault.add(new THREE.Mesh(new THREE.BoxGeometry(1.6, 1.6, 1.6), new THREE.MeshBasicMaterial({color: 0x3ddc97, transparent: true, opacity: 0.35}))); scene.add(vault);
const vl = label('VAULT  (XChaCha20-Poly1305, bound)', '#3ddc97', 0.65); vl.position.set(-1, -1.6, -6); scene.add(vl);
// paths
const V3 = (x, y, z) => new THREE.Vector3(x, y, z);
const pathVals = new THREE.CatmullRomCurve3([V3(-13, 0, 0), V3(-9, 1, 1), V3(-5, 0, 0), V3(-3, -2, -3), V3(-1, -4.2, -6)]);
const pathPh = new THREE.CatmullRomCurve3([V3(-5, 0, 0), V3(2, 0.4, 0), V3(7, 0.2, 0), V3(13, 0, 0)]);
function particles(n, color) {
  const g = new THREE.BufferGeometry(); g.setAttribute('position', new THREE.BufferAttribute(new Float32Array(n * 3), 3));
  const m = new THREE.Points(g, new THREE.PointsMaterial({color, size: 0.5, transparent: true, opacity: 0.95, blending: THREE.AdditiveBlending, depthWrite: false}));
  m.userData = {n, off: Array.from({length: n}, () => Math.random()), spread: Array.from({length: n}, () => [(Math.random() - 0.5) * 0.8, (Math.random() - 0.5) * 0.8, (Math.random() - 0.5) * 0.8])};
  scene.add(m); return m;
}
const pv = particles(220, 0xff4d6d), pp = particles(220, 0x27e1ff);
function flow(sys, path, t, speed) {
  const a = sys.geometry.attributes.position, u = sys.userData;
  for (let i = 0; i < u.n; i++) { const k = (u.off[i] + t * speed) % 1; const p = path.getPoint(k);
    a.setXYZ(i, p.x + u.spread[i][0], p.y + u.spread[i][1], p.z + u.spread[i][2]); }
  a.needsUpdate = true;
}
// chips floating around the right screen
let chips = [];
function setChips(list) {
  chips.forEach((c) => scene.remove(c)); chips = [];
  list.slice(0, 16).forEach((t, i) => { const s = label(t, '#27e1ff', 0.42); const a = i / Math.max(list.length, 1) * Math.PI * 2;
    s.userData = {a, r: 5.2 + (i % 3) * 0.7, y: (i % 5 - 2) * 1.2}; scene.add(s); chips.push(s); });
}
function load(page) {
  const d = DATA[page];
  loader.load(d.original, (t) => { L.plane.material.map = t; L.plane.material.color.set(0xffffff); L.plane.material.needsUpdate = true; });
  loader.load(d.redacted, (t) => { R.plane.material.map = t; R.plane.material.color.set(0xffffff); R.plane.material.needsUpdate = true; });
  const asp = d.h / d.w; [L, R].forEach((s) => s.plane.scale.set(1, Math.min(1.4, Math.max(0.55, asp * 1.4)), 1));
  setChips(d.chips);
  el('hud').innerHTML = '<b>' + page + '</b><br>planted <b>' + d.planted + '</b> · detected <b>' + d.detected + '</b> + ' + d.fail_closed + ' image regions blacked out<br>' +
    'placeholders <b>' + d.placeholders + '</b> · vault entries <b>' + d.vault + '</b> (' + (d.vault_ok ? 'binding test passed' : 'FAILED') + ')<br>' +
    'leak check: <b class="' + (d.leaks ? 'bad' : 'ok') + '">' + d.leaks + ' leaks</b>';
  el('links').innerHTML = '<a href="' + page + '.html">2D before / after</a>';
  document.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b.dataset.p === page));
}
document.querySelectorAll('button').forEach((b) => b.onclick = () => load(b.dataset.p));
// orbit
let yaw = 0, pitch = 0.12, dist = 21, drag = false, lx = 0, ly = 0, auto = true;
ren.domElement.onpointerdown = (e) => { drag = true; auto = false; lx = e.clientX; ly = e.clientY; };
addEventListener('pointerup', () => drag = false);
addEventListener('pointermove', (e) => { if (!drag) return; yaw -= (e.clientX - lx) * 0.005; pitch = Math.max(-0.6, Math.min(1.0, pitch + (e.clientY - ly) * 0.004)); lx = e.clientX; ly = e.clientY; });
ren.domElement.onwheel = (e) => { dist = Math.max(9, Math.min(60, dist + e.deltaY * 0.03)); e.preventDefault(); };
addEventListener('resize', () => { cam.aspect = innerWidth / innerHeight; cam.updateProjectionMatrix(); ren.setSize(innerWidth, innerHeight); });
const clock = new THREE.Clock();
(function tick() {
  const t = clock.getElapsedTime();
  if (auto) yaw = Math.sin(t * 0.12) * 0.55;
  cam.position.set(Math.sin(yaw) * dist, 4 + pitch * dist * 0.5, Math.cos(yaw) * dist); cam.lookAt(0, -0.8, 0);
  rings.forEach((r, i) => { r.rotation.x = t * (0.6 + i * 0.3); r.rotation.y = t * (0.4 + i * 0.25); }); core.rotation.y = t;
  beam.position.y = Math.sin(t * 1.6) * 2.4; vault.rotation.y = t * 0.3;
  flow(pv, pathVals, t, 0.16); flow(pp, pathPh, t, 0.2);
  chips.forEach((s) => { const u = s.userData; s.position.set(13 + Math.cos(u.a + t * 0.25) * u.r * 0.55, u.y + Math.sin(t + u.a) * 0.3, Math.sin(u.a + t * 0.25) * u.r * 0.9); });
  ren.render(scene, cam); requestAnimationFrame(tick);
})();
load(Object.keys(DATA)[0]);
"""


def index_html(results: list[dict[str, Any]], detector: str, summary_table: str) -> str:
    data: dict[str, Any] = {}
    for r in results:
        img = Image.open(io.BytesIO(r["png"]["original"]))
        chips = sorted({d["placeholder"] for d in r["dets"] if d["placeholder"]})
        data[r["page"]] = {
            "original": _b64png(r["png"]["original"]), "redacted": _b64png(r["png"]["redacted"]),
            "w": img.width, "h": img.height, "planted": r["planted"], "detected": r["detected"],
            "fail_closed": r["fail_closed_regions"], "placeholders": r["placeholders"], "vault": r["vault_entries"],
            "vault_ok": r["vault_ok"], "leaks": len(r["leaks"]), "chips": chips,
        }  # fmt: skip
    buttons = "".join(f'<button data-p="{r["page"]}">{r["page"]}</button>' for r in results)
    table = "".join(
        f"<tr><td><a href='{r['page']}.html'>{r['page']}</a></td><td>{r['planted']}</td><td>{r['detected']} + {r['fail_closed_regions']}</td>"
        f"<td>{r['placeholders']}</td><td class='{'good' if not r['leaks'] else 'bad'}'>{len(r['leaks'])}</td>"
        f"<td>{'ok' if r['vault_ok'] else 'FAIL'}</td><td>{r['decoys']}</td></tr>"
        for r in results
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PrivacyLens data pipeline</title><style>{CSS}
#scene{{position:relative;height:100vh;min-height:560px}}canvas#c{{position:absolute;inset:0;width:100%;height:100%;display:block}}
#top{{position:absolute;left:16px;top:14px;right:16px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}}
#top h1{{margin-right:12px;text-shadow:0 0 18px #27e1ff}}button{{background:#0f1420cc;color:var(--ink);border:1px solid var(--line);border-radius:999px;padding:6px 14px;cursor:pointer;font:inherit;backdrop-filter:blur(6px)}}
button.on{{border-color:var(--cy);box-shadow:0 0 14px #27e1ff88;color:var(--cy)}}
#hud{{position:absolute;left:16px;bottom:16px;background:#0f1420cc;border:1px solid var(--line);border-radius:10px;padding:12px 16px;backdrop-filter:blur(6px);max-width:460px}}
#links{{position:absolute;right:16px;bottom:16px}}.bad{{color:var(--red)}}.ok{{color:var(--ok)}}
#hint{{position:absolute;right:16px;top:16px;color:var(--mut);font-size:12px}}</style></head><body>
<div id="scene"><canvas id="c"></canvas><div id="top"><h1>PrivacyLens: from your screen to what the AI sees</h1>{buttons}</div>
<div id="hint">drag to orbit · wheel to zoom · detector: {html.escape(detector)}</div><div id="hud"></div><div id="links"></div></div>
<main><h2 style="color:var(--ink)">Summary</h2><table><tr><th>page</th><th>planted</th><th>detected + blacked-out images</th><th>placeholders</th><th>leaks</th><th>vault binding</th><th>decoys kept</th></tr>{table}</table>
<p class="mut">Red particles: real values flowing to the vault. Cyan particles: placeholders flowing to the AI. Full numbers and caveats: summary.md.</p></main>
<script src="{THREE}"></script><script>{SCENE_JS.replace("__DATA__", json.dumps(data))}</script></body></html>"""


def write_reports(results: list[dict[str, Any]], out: Path, detector: str, session: str) -> None:
    md = summary_md(results, detector, session)
    (out / "summary.md").write_text(md, "utf-8")
    for r in results:
        (out / f"{r['page']}.html").write_text(page_html(r), "utf-8")
    (out / "index.html").write_text(index_html(results, detector, md), "utf-8")
