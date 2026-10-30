"""DOM capture in headless Chromium (Playwright): live input values, accessibility-style
roles and names, every attribute, own text nodes, boxes, and a full-page screenshot.

The page DOM is never modified (elements are indexed in a JS-side array, not tagged
with attributes). Owner: WIN.
"""

from __future__ import annotations

from typing import Any

CAPTURE_JS = r"""
() => {
  const els = [];
  window.__plEls = els;
  const SKIP = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'LINK']);
  const sx = window.scrollX, sy = window.scrollY;
  const roleOf = (el) => {
    const r = el.getAttribute('role');
    if (r) return r;
    const t = el.tagName.toLowerCase();
    if (t === 'input') {
      const ty = (el.getAttribute('type') || 'text').toLowerCase();
      if (ty === 'button' || ty === 'submit') return 'button';
      if (ty === 'checkbox') return 'checkbox';
      if (ty === 'hidden') return 'hidden';
      return 'textbox';
    }
    return ({a: 'link', button: 'button', select: 'combobox', textarea: 'textbox', img: 'img', canvas: 'img',
             h1: 'heading', h2: 'heading', h3: 'heading', li: 'listitem', ol: 'list', ul: 'list', table: 'table',
             th: 'columnheader', td: 'cell', form: 'form', main: 'main', header: 'banner', option: 'option',
             dl: 'list', dt: 'term', dd: 'definition', label: 'label', code: 'code', pre: 'code'})[t] || 'text';
  };
  const labelOf = (el) => {
    const al = el.getAttribute('aria-label');
    if (al) return al;
    const lb = el.getAttribute('aria-labelledby');
    if (lb) { const n = document.getElementById(lb); if (n) return n.textContent.trim(); }
    if (el.id) { const l = document.querySelector('label[for="' + CSS.escape(el.id) + '"]'); if (l) return l.textContent.trim(); }
    const w = el.closest('label'); if (w) return w.textContent.trim();
    return el.getAttribute('alt') || el.getAttribute('placeholder') || el.getAttribute('title') || '';
  };
  const vis = (el, r) => {
    const cs = getComputedStyle(el);
    return cs.display !== 'none' && cs.visibility !== 'hidden' && parseFloat(cs.opacity) > 0 && r.width > 0 && r.height > 0;
  };
  const walk = (el, parent) => {
    if (SKIP.has(el.tagName)) return;
    const id = els.length;
    els.push(el);
    const r = el.getBoundingClientRect();
    const attrs = {};
    for (const a of el.attributes) attrs[a.name] = a.value;
    const tns = [];
    el.childNodes.forEach((n, i) => { if (n.nodeType === 3 && n.data.trim() !== '') tns.push({i, text: n.data}); });
    const tag = el.tagName.toLowerCase();
    let value = null;
    if (tag === 'input' || tag === 'textarea') value = el.value;
    if (tag === 'select') value = el.selectedOptions.length ? el.selectedOptions[0].text : '';
    const rec = {id, parent, tag, attrs, text_nodes: tns, value, role: roleOf(el), label: labelOf(el),
                 type: tag === 'input' ? (el.getAttribute('type') || 'text').toLowerCase() : '',
                 rect: [r.x + sx, r.y + sy, r.width, r.height], visible: vis(el, r)};
    out.push(rec);
    for (const c of el.children) walk(c, id);
  };
  const out = [];
  walk(document.documentElement, -1);
  return {title: document.title, url: location.href, elements: out,
          width: document.documentElement.scrollWidth, height: document.documentElement.scrollHeight};
}
"""

RANGE_RECTS_JS = r"""
([id, childIndex, start, end]) => {
  const el = window.__plEls[id];
  const n = el.childNodes[childIndex];
  const rg = document.createRange();
  rg.setStart(n, start); rg.setEnd(n, end);
  const sx = window.scrollX, sy = window.scrollY;
  return Array.from(rg.getClientRects()).map(r => [r.x + sx, r.y + sy, r.width, r.height]).filter(r => r[2] > 0 && r[3] > 0);
}
"""

FIND_RECTS_JS = r"""
([sel, needle]) => {
  const sx = window.scrollX, sy = window.scrollY;
  const el = document.querySelector(sel);
  if (!el) return [];
  const box = (r) => [r.x + sx, r.y + sy, r.width, r.height];
  if (needle) {
    // The needle may be split over several descendant text nodes: use the element's first match per node.
    const w = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    const out = [];
    let n;
    while ((n = w.nextNode())) {
      const k = n.data.indexOf(needle);
      if (k >= 0) {
        const rg = document.createRange(); rg.setStart(n, k); rg.setEnd(n, k + needle.length);
        out.push(...Array.from(rg.getClientRects()).map(box));
      }
    }
    if (out.length) return out;
  }
  const kids = Array.from(el.children).filter(c => c.getBoundingClientRect().width > 0);
  if (needle && kids.length >= 2) return kids.map(c => box(c.getBoundingClientRect()));
  return [box(el.getBoundingClientRect())];
}
"""


def capture(page: Any) -> dict[str, Any]:
    cap: dict[str, Any] = page.evaluate(CAPTURE_JS)
    try:
        cap["ax_tree"] = page.accessibility.snapshot(interesting_only=False)
    except Exception:  # accessibility API absent in this Playwright build: recorded, not fatal
        cap["ax_tree"] = None
    return cap


def range_rects(page: Any, el_id: int, child_index: int, start16: int, end16: int) -> list[list[float]]:
    rects: list[list[float]] = page.evaluate(RANGE_RECTS_JS, [el_id, child_index, start16, end16])
    return rects


def find_rects(page: Any, selector: str, needle: str) -> list[list[float]]:
    rects: list[list[float]] = page.evaluate(FIND_RECTS_JS, [selector, needle])
    return rects
