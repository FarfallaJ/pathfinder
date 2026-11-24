"""Parse a .eml message: auth results, spoofing signals, URLs, attachments."""
from __future__ import annotations
import hashlib
import re
from email import message_from_bytes, policy
from email.utils import parseaddr

from .typosquat import BRANDS, registrable

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _auth_result(auth_headers: str, mech: str) -> str | None:
    # e.g. "spf=pass", "dkim=fail", "dmarc=pass"
    m = re.search(rf"\b{mech}\s*=\s*(\w+)", auth_headers, re.IGNORECASE)
    return m.group(1).lower() if m else None


def _domain(addr: str) -> str:
    return registrable((addr.split("@")[-1] if "@" in addr else "").lower())


def parse(raw: bytes) -> dict:
    msg = message_from_bytes(raw, policy=policy.default)

    from_name, from_addr = parseaddr(msg.get("From", ""))
    _, reply_addr = parseaddr(msg.get("Reply-To", ""))
    _, return_addr = parseaddr(msg.get("Return-Path", ""))
    from_dom = _domain(from_addr)

    auth = " ".join(msg.get_all("Authentication-Results", []) or [])
    spf = _auth_result(auth, "spf")
    dkim = _auth_result(auth, "dkim")
    dmarc = _auth_result(auth, "dmarc")

    # Display-name spoof: the display name names a brand/domain that isn't the
    # actual sending domain.
    display_spoof = False
    dn = (from_name or "").lower()
    for brand, domains in BRANDS.items():
        if brand in dn and from_dom not in domains:
            display_spoof = True
            break
    dn_domain = re.search(r"[\w.-]+\.[a-z]{2,}", dn)
    if dn_domain and registrable(dn_domain.group(0)) != from_dom and from_dom:
        display_spoof = True

    reply_mismatch = bool(reply_addr and from_dom and _domain(reply_addr) != from_dom)

    # Body URLs + received IPs + attachments
    body_text = ""
    attachments = []
    for part in msg.walk():
        disp = (part.get_content_disposition() or "")
        ctype = part.get_content_type()
        if disp == "attachment" or (part.get_filename()):
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": part.get_filename(),
                "content_type": ctype,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest() if payload else None,
            })
        elif ctype in ("text/plain", "text/html"):
            try:
                body_text += part.get_content()
            except Exception:  # noqa: BLE001
                pass

    urls = []
    seen = set()
    for u in _URL_RE.findall(body_text):
        u = u.rstrip(".,);")
        if u not in seen:
            seen.add(u)
            urls.append(u)

    received = " ".join(msg.get_all("Received", []) or [])
    received_ips = []
    for ip in _IP_RE.findall(received):
        if ip not in received_ips and not ip.startswith(("10.", "192.168.", "127.")):
            received_ips.append(ip)

    return {
        "from": from_addr,
        "from_name": from_name,
        "from_domain": from_dom,
        "reply_to": reply_addr or None,
        "return_path": return_addr or None,
        "subject": str(msg.get("Subject", ""))[:300],
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "display_name_spoof": display_spoof,
        "reply_to_mismatch": reply_mismatch,
        "urls": urls[:50],
        "received_ips": received_ips[:10],
        "attachments": attachments[:20],
    }
