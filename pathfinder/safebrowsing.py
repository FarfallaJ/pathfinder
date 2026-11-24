"""Google Safe Browsing v4 Lookup API — authoritative phishing/malware check."""
from __future__ import annotations
import requests

from . import config

_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                 "POTENTIALLY_HARMFUL_APPLICATION"]


def check(url: str, timeout: int = 15) -> dict:
    """Look up a URL. Returns {configured, listed, threat_types}. SOCIAL_ENGINEERING
    is Google's label for phishing. Degrades cleanly without a key."""
    key = config.get_key("gsb")
    if not key:
        return {"source": "safe-browsing", "configured": False, "listed": False,
                "note": "GSB_API_KEY not set"}
    body = {
        "client": {"clientId": "pathfinder", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": _THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(f"{_ENDPOINT}?key={key}", json=body, timeout=timeout)
        if r.status_code != 200:
            return {"source": "safe-browsing", "configured": True, "listed": False,
                    "error": f"HTTP {r.status_code}"}
        data = r.json()
    except Exception as e:  # noqa: BLE001
        return {"source": "safe-browsing", "configured": True, "listed": False,
                "error": str(e)}
    matches = data.get("matches", []) or []
    threats = sorted({m.get("threatType") for m in matches if m.get("threatType")})
    return {"source": "safe-browsing", "configured": True,
            "listed": bool(matches), "threat_types": threats}
