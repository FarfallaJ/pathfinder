"""Optional headless-browser render via Playwright.

Unlike the static `requests` fetch, this executes JavaScript, so it catches
JS-driven redirects and dynamically-rendered login forms, and it produces a
keyless screenshot (no urlscan key needed). Comparing where the browser lands
against the static fetch also reveals cloaking.

Install:  pip install "pathfinder-phish[browser]"   then   playwright install chromium
"""
from __future__ import annotations
import os
import re
from urllib.parse import urlparse

_BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


def available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def _safe_name(url: str) -> str:
    host = (urlparse(url).hostname or "page")
    return re.sub(r"[^A-Za-z0-9._-]", "_", host)[:80]


def render(url: str, screenshot_dir: str | None = None,
           timeout_ms: int = 30000) -> dict:
    """Render `url` in headless Chromium. Returns the JS-executed final URL, the
    rendered HTML, a screenshot path, and status. Never raises."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception:  # noqa: BLE001
        return {"available": False,
                "note": "Playwright not installed. Run: "
                        "pip install \"pathfinder-phish[browser]\" "
                        "&& playwright install chromium"}

    out: dict = {"available": True, "requested_url": url, "error": None}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(user_agent=_BROWSER_UA,
                                      ignore_https_errors=True)
            page = ctx.new_page()
            resp = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            try:
                page.wait_for_load_state("networkidle", timeout=6000)
            except Exception:  # noqa: BLE001
                pass
            out["final_url"] = page.url
            out["status"] = resp.status if resp else None
            try:
                out["title"] = page.title()
            except Exception:  # noqa: BLE001
                out["title"] = ""
            try:
                out["html"] = page.content()[:300_000]
            except Exception:  # noqa: BLE001
                out["html"] = ""
            shot_dir = screenshot_dir or os.getcwd()
            try:
                os.makedirs(shot_dir, exist_ok=True)
                path = os.path.join(shot_dir, f"pathfinder_{_safe_name(url)}.png")
                page.screenshot(path=path, full_page=False)
                out["screenshot_path"] = path
            except Exception as e:  # noqa: BLE001
                out["screenshot_error"] = str(e)
            browser.close()
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    return out
