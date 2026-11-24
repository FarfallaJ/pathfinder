"""URL normalization: defang/refang, unwrap protective wrappers, decode."""
from __future__ import annotations
import re
from urllib.parse import unquote, urlparse, parse_qs

# Common URL shorteners (expanded by following redirects, flagged as a signal).
SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "t.ly", "lnkd.in",
    "tiny.cc", "soo.gd", "s.id",
}


def defang(u: str) -> str:
    """Reverse common defanging so hxxp://a[.]b parses as a real URL."""
    v = (u or "").strip()
    v = v.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".").replace("[dot]", ".")
    v = v.replace("[:]", ":").replace("[://]", "://")
    v = re.sub(r"^h[xX]{2}p", "http", v)
    return v.strip()


def host_of(u: str) -> str | None:
    try:
        return (urlparse(u).hostname or "").lower() or None
    except Exception:  # noqa: BLE001
        return None


def is_shortener(host: str | None) -> bool:
    return (host or "").lower() in SHORTENERS


def _proofpoint_v2(u: str) -> str | None:
    q = parse_qs(urlparse(u).query)
    if "u" not in q:
        return None
    raw = q["u"][0]
    # Proofpoint URL Defense v2 encodes '%' as '-' and '/' as '_'.
    s = raw.replace("-", "%").replace("_", "/")
    try:
        dec = unquote(s)
        if dec.startswith(("http://", "https://")):
            return dec
    except Exception:  # noqa: BLE001
        pass
    return None


def _unwrap_once(u: str) -> str:
    try:
        p = urlparse(u)
    except Exception:  # noqa: BLE001
        return u
    host = (p.hostname or "").lower()
    q = parse_qs(p.query)
    # Microsoft Safe Links
    if "safelinks.protection.outlook.com" in host and "url" in q:
        return unquote(q["url"][0])
    # Proofpoint URL Defense
    if "urldefense" in host:
        dec = _proofpoint_v2(u)
        if dec:
            return dec
    # Generic single-redirect wrappers (?url=, ?u=, ?redirect=, ?target=, ?q=)
    for key in ("url", "u", "redirect", "redirecturl", "target", "dest", "q"):
        if key in q and q[key]:
            val = unquote(q[key][0])
            if val.startswith(("http://", "https://")):
                return val
    return u


def unwrap(u: str) -> str:
    """Unwrap known protective redirectors (Microsoft Safe Links, Proofpoint URL
    Defense) and generic ?url= wrappers, repeatedly, to the real destination."""
    v = defang(u)
    for _ in range(5):  # wrappers can nest
        w = _unwrap_once(v)
        if w == v:
            break
        v = w
    return v
