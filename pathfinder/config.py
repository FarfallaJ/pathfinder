"""Key loading for Pathfinder — from the environment or a .env file.

Looks in: real env vars, then a project-local .env (walking up from the cwd),
then $PATHFINDER_ENV. Falls back to Station's loader for shared keys (urlscan),
so one .env can serve both tools.
"""
from __future__ import annotations
import os
from pathlib import Path

_LOADED = False

_ENV_VARS = {
    "gsb": "GSB_API_KEY",
    "phishtank": "PHISHTANK_API_KEY",
    "urlscan": "URLSCAN_API_KEY",
}


def _load_dotenv() -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    try:
        from dotenv import load_dotenv, find_dotenv
    except Exception:  # noqa: BLE001 — dotenv optional
        return
    candidates = []
    explicit = os.environ.get("PATHFINDER_ENV")
    if explicit:
        candidates.append(Path(explicit).expanduser())
    try:
        found = find_dotenv(usecwd=True)
    except Exception:  # noqa: BLE001
        found = ""
    if found:
        candidates.append(Path(found))
    for p in candidates:
        try:
            if p and p.is_file():
                load_dotenv(p, override=False)
        except Exception:  # noqa: BLE001
            pass


def get_key(name: str) -> str | None:
    """Return the API key for a source ('gsb' | 'phishtank' | 'urlscan')."""
    _load_dotenv()
    var = _ENV_VARS.get(name, name)
    val = os.environ.get(var)
    if val:
        return val
    # Shared keys (urlscan) may live in Station's .env — reuse its loader.
    try:
        from ioc_enrich.config import get_key as station_key
        return station_key(name)
    except Exception:  # noqa: BLE001
        return None
