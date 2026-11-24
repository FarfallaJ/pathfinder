"""Bridge to Station (cti-ioc-enrichment): enrich the IOCs Pathfinder found.

Pathfinder answers "what is this URL/email doing?"; Station answers "is this
indicator known bad?". This hands the discovered indicators to Station for
reputation and attribution, if it's installed alongside.
"""
from __future__ import annotations

_ENRICHABLE = {"ipv4", "domain", "url", "md5", "sha1", "sha256"}


def available() -> bool:
    try:
        import ioc_enrich.engine  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def enrich_iocs(iocs: list[dict]) -> dict:
    """Enrich each IOC via Station. Returns a result dict; degrades gracefully
    when Station isn't installed."""
    try:
        from ioc_enrich.engine import enrich
    except Exception:  # noqa: BLE001
        return {"available": False,
                "note": "Station (cti-ioc-enrichment) is not installed; "
                        "install it to enrich discovered indicators.",
                "assessments": []}
    out = []
    for i in iocs:
        if i.get("type") not in _ENRICHABLE:
            continue
        try:
            out.append(enrich(i["indicator"]).to_dict())
        except Exception as e:  # noqa: BLE001
            out.append({"ioc": i["indicator"], "error": str(e)})
    return {"available": True, "assessments": out}
