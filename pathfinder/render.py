"""Optional page render via urlscan.io (reuses the Station URLSCAN_API_KEY).

Submits the URL for a fresh scan and returns a screenshot URL, urlscan's own
verdict, the resolved page URL, and observed IPs. Degrades to None without a key.
"""
from __future__ import annotations
import time

import requests

from . import config

_SUBMIT = "https://urlscan.io/api/v1/scan/"
_RESULT = "https://urlscan.io/api/v1/result/{uuid}/"


def _key() -> str | None:
    return config.get_key("urlscan")


def scan(url: str, visibility: str = "unlisted", timeout: int = 60) -> dict | None:
    key = _key()
    if not key:
        return None
    try:
        r = requests.post(_SUBMIT, headers={"API-Key": key, "Content-Type": "application/json"},
                          json={"url": url, "visibility": visibility}, timeout=20)
        if r.status_code not in (200, 201):
            return {"error": f"submit HTTP {r.status_code}", "screenshot_url": None}
        uuid = r.json().get("uuid")
    except Exception as e:  # noqa: BLE001
        return {"error": str(e), "screenshot_url": None}

    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(5)
        try:
            rr = requests.get(_RESULT.format(uuid=uuid), timeout=15)
        except Exception:  # noqa: BLE001
            continue
        if rr.status_code == 404:
            continue  # result not ready yet
        if rr.status_code != 200:
            break
        data = rr.json()
        page = data.get("page", {}) or {}
        verd = (data.get("verdicts", {}) or {}).get("overall", {}) or {}
        ips = []
        for li in (data.get("lists", {}) or {}).get("ips", []) or []:
            if li not in ips:
                ips.append(li)
        verdict = "malicious" if verd.get("malicious") else (
            "suspicious" if verd.get("score", 0) and verd["score"] > 0 else "benign")
        return {
            "uuid": uuid,
            "screenshot_url": f"https://urlscan.io/screenshots/{uuid}.png",
            "result_url": f"https://urlscan.io/result/{uuid}/",
            "page_url": page.get("url"),
            "urlscan_verdict": verdict,
            "urlscan_score": verd.get("score"),
            "ips": ips[:20],
        }
    return {"uuid": uuid, "screenshot_url": f"https://urlscan.io/screenshots/{uuid}.png",
            "note": "scan submitted; result not ready before timeout",
            "result_url": f"https://urlscan.io/result/{uuid}/"}
