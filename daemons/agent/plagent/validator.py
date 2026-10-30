"""Action validator (spec §9): is this well-formed action *sensible* on this page?

- the target exists, is visible and enabled, and is the right kind of element
- no ``javascript:`` (or ``data:``, ``vbscript:``, ``file:``, ``blob:``...) URLs,
  however they're disguised
- navigation only to the task's allowed domains, no userinfo tricks
- no coordinate clicks (``actions.parse_action`` already refuses x/y fields)

Every refusal names a rule ID (A-xx) so the decision record can cite it.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass

from .actions import Action
from .page import SanitizedPage, Task

SAFE_SCHEMES = ("https", "http")
_CTRL = re.compile("[" + "".join(chr(c) for c in range(0x00, 0x21)) + chr(0x7F) + "]")
FILLABLE_ROLES = ("textbox", "searchbox", "spinbutton", "combobox", "textarea")
SELECT_ROLES = ("combobox", "listbox")


@dataclass(frozen=True)
class Verdict:
    ok: bool
    rule_id: str = ""
    reason: str = ""


OK = Verdict(True)


def _deny(rule: str, reason: str) -> Verdict:
    return Verdict(False, rule, reason)


def _scheme_of(url: str) -> str:
    """The scheme a browser would see, after the tricks browsers forgive:
    leading/trailing controls and spaces, embedded tabs/newlines, any case.
    Percent-encoding is decoded too (a browser wouldn't treat ``%6Aavascript:``
    as a scheme, but nothing legitimate needs it, so we treat it as one)."""
    u = url
    for _ in range(3):
        u = urllib.parse.unquote(u)
    u = _CTRL.sub("", u).lower()
    m = re.match(r"([a-z][a-z0-9+.-]*):", u)
    return m.group(1) if m else ""


def host_allowed(host: str, allowed: tuple[str, ...]) -> bool:
    h = host.lower().rstrip(".")
    for d in allowed:
        d = d.lower().rstrip(".")
        if h == d or h.endswith("." + d):
            return True
    return False


def check_url(url: str, base: str, allowed: tuple[str, ...]) -> Verdict:
    """Absolute or relative URL, resolved against the current page."""
    scheme = _scheme_of(url)
    if scheme and scheme not in SAFE_SCHEMES:
        return _deny("A-04", f"scheme {scheme!r} is not allowed")
    if _CTRL.search(url.strip()) and not url.strip().startswith(("http://", "https://")):
        return _deny("A-04", "control characters in URL")
    u = url.strip()
    m = re.match(r"(?i)(https?):[/\\]*", u)
    if m:
        # Browsers (WHATWG URL) ignore any run of slashes after a special scheme:
        # "https:///evil.example" and "https:evil.example" both mean host evil.example.
        # Python's urljoin would read them as paths on the current host.
        u = f"{m.group(1).lower()}://{u[m.end() :]}"
    full = urllib.parse.urljoin(base, u)
    parts = urllib.parse.urlsplit(full)
    if parts.scheme not in SAFE_SCHEMES:
        return _deny("A-04", f"scheme {parts.scheme!r} is not allowed")
    if "@" in parts.netloc:
        return _deny("A-07", "credentials/userinfo in URL (host confusion)")
    if "\\" in full:
        return _deny("A-07", "backslash in URL (host confusion)")
    host = parts.hostname or ""
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = False
    if not host or (is_ip and host not in allowed):
        return _deny("A-05", "host missing or a raw IP address")
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        return _deny("A-05", "non-ASCII host (possible look-alike domain)")
    if not host_allowed(host, allowed):
        return _deny("A-05", "domain not in this task's allowed list")
    return OK


def validate(action: Action, page: SanitizedPage, task: Task) -> Verdict:
    if action.kind in ("click", "fill", "select"):
        assert action.target is not None
        node = page.node(action.target)
        if node is None:
            return _deny("A-02", "target node does not exist on this page")
        if not node.visible:
            return _deny("A-03", "target is not visible")
        if not node.enabled:
            return _deny("A-03", "target is disabled")
        if action.kind == "click" and node.href is not None:
            v = check_url(node.href, page.url, task.allowed_domains)
            if not v.ok:
                return v
        if action.kind == "fill" and (node.field is None or not node.field.fillable or node.role not in FILLABLE_ROLES):
            return _deny("A-08", "target is not a fillable field")
        if action.kind == "select":
            if node.role not in SELECT_ROLES:
                return _deny("A-08", "target is not a select")
            if action.option not in node.options:
                return _deny("A-09", "option is not one of the target's options")
    if action.kind == "navigate":
        assert action.url is not None
        return check_url(action.url, page.url, task.allowed_domains)
    return OK
