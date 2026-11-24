"""PhishTank (Cisco Talos) blocklist check — anonymous or with an optional key."""
from __future__ import annotations
import requests

from . import config

_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"
_UA = "phishtank/FarfallaJ"


def _truthy(v) -> bool:
    return str(v).lower() in ("y", "yes", "true", "1")


def check(url: str, timeout: int = 15) -> dict:
    """Check a URL against PhishTank. Returns {in_database, verified, phish_id,
    detail_url}. Works anonymously (rate-limited); a key raises the limit."""
    key = config.get_key("phishtank")
    data = {"url": url, "format": "json"}
    if key:
        data["app_key"] = key
    try:
        r = requests.post(_ENDPOINT, data=data, headers={"User-Agent": _UA},
                          timeout=timeout)
        if r.status_code == 509:
            return {"source": "phishtank", "in_database": False, "rate_limited": True,
                    "note": "rate limited (HTTP 509); set PHISHTANK_API_KEY to raise it"}
        if r.status_code != 200:
            return {"source": "phishtank", "in_database": False,
                    "error": f"HTTP {r.status_code}"}
        body = r.json()
    except Exception as e:  # noqa: BLE001
        return {"source": "phishtank", "in_database": False, "error": str(e)}

    res = body.get("results", {}) or {}
    return {
        "source": "phishtank",
        "in_database": bool(res.get("in_database")),
        "verified": _truthy(res.get("verified")),
        "valid": _truthy(res.get("valid")),
        "phish_id": res.get("phish_id"),
        "detail_url": res.get("phish_detail_page"),
    }
