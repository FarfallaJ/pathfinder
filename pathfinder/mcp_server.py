"""Pathfinder MCP server — expose phishing/URL analysis as MCP tools.

Tools:
    analyze_url        full analysis of a suspicious URL
    analyze_email      analysis of a raw .eml (passed as text)
    check_reputation   fast Safe Browsing + PhishTank lookup only

With enrich=True, results include Station's enrichment of the indicators
Pathfinder discovers — so the two tools compose into one investigation.

Run:  pip install "pathfinder-phish[mcp]"  then  pathfinder-mcp
"""
from __future__ import annotations
from typing import Optional

from .analyze import analyze_url as _au, analyze_email as _ae
from . import safebrowsing, phishtank

SERVER_NAME = "Pathfinder"


# --------------------------------------------------------------------------- #
# Pure logic — no MCP dependency, unit-testable.
# --------------------------------------------------------------------------- #
def _trim(analysis: dict) -> dict:
    """Drop the heavy rendered-HTML blob before returning over MCP."""
    br = analysis.get("browser")
    if isinstance(br, dict) and "html" in br:
        analysis = {**analysis, "browser": {k: v for k, v in br.items() if k != "html"}}
    la = analysis.get("link_analysis")
    if isinstance(la, dict):
        analysis = {**analysis, "link_analysis": _trim(la)}
    return analysis


def _analyze_url(url: str, render: bool = False, browser: bool = False,
                 enrich: bool = False, screenshot_dir: Optional[str] = None) -> dict:
    return _trim(_au(url, do_render=render, do_browser=browser, do_enrich=enrich,
                     screenshot_dir=screenshot_dir))


def _analyze_email(eml_text: str, render: bool = False, browser: bool = False,
                   enrich: bool = False) -> dict:
    raw = eml_text.encode("utf-8", "replace") if isinstance(eml_text, str) else eml_text
    return _trim(_ae(raw, do_render=render, do_browser=browser, do_enrich=enrich))


def _check_reputation(url: str) -> dict:
    return {"url": url,
            "safe_browsing": safebrowsing.check(url),
            "phishtank": phishtank.check(url)}


# --------------------------------------------------------------------------- #
# MCP wiring — supports mcp 2.x (MCPServer) and legacy 1.x (FastMCP).
# --------------------------------------------------------------------------- #
try:  # mcp >= 2.0
    from mcp.server.mcpserver import MCPServer as _Server
except Exception:  # noqa: BLE001
    try:  # mcp 1.x
        from mcp.server.fastmcp import FastMCP as _Server
    except Exception:  # noqa: BLE001
        _Server = None


def build_server():
    if _Server is None:
        raise RuntimeError(
            "The 'mcp' package is required to run the Pathfinder server. "
            "Install it with:  pip install \"pathfinder-phish[mcp]\"")
    mcp = _Server(SERVER_NAME)

    @mcp.tool()
    def analyze_url(url: str, render: bool = False, browser: bool = False,
                    enrich: bool = False) -> dict:
        """Analyze a suspicious URL (defanged input OK): unwrap protective
        redirectors, follow the redirect chain, check typosquat/lookalike and
        page/credential-form signals, look it up in Google Safe Browsing and
        PhishTank, and return a 0-100 phishing score, verdict, and the signals
        that fired, plus the indicators discovered. render=True adds a urlscan
        screenshot; browser=True renders in headless Chromium (JS final URL,
        dynamic forms, cloaking detection); enrich=True also runs Station on the
        discovered indicators for reputation and attribution."""
        return _analyze_url(url, render, browser, enrich)

    @mcp.tool()
    def analyze_email(eml_text: str, render: bool = False, browser: bool = False,
                      enrich: bool = False) -> dict:
        """Analyze a raw email given as text (the .eml contents): From / Reply-To
        / Return-Path, SPF/DKIM/DMARC results, display-name spoofing, body URLs
        and attachment hashes, plus full analysis of the first link. Same
        render/browser/enrich options as analyze_url."""
        return _analyze_email(eml_text, render, browser, enrich)

    @mcp.tool()
    def check_reputation(url: str) -> dict:
        """Fast reputation-only check of a URL against Google Safe Browsing and
        PhishTank, without the full structural analysis."""
        return _check_reputation(url)

    return mcp


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
