"""Headless-render integration — Playwright itself is mocked (not launched)."""
from pathfinder import analyze, score


def _fake_follow(url, **kw):
    return {
        "final_url": "https://scanner-safe.example/landing",
        "redirect_chain": [{"url": "https://scanner-safe.example/landing", "status": 200}],
        "hops": 0, "final_status": 200, "final_headers": {},
        "final_body": "<title>Loading…</title>",  # static fetch sees a stub
        "shortener_in_chain": False, "error": None,
    }


def _no_rep(monkeypatch):
    monkeypatch.setattr(analyze.safebrowsing, "check",
                        lambda u: {"configured": True, "listed": False})
    monkeypatch.setattr(analyze.phishtank, "check", lambda u: {"in_database": False})
    monkeypatch.setattr(analyze.infra, "resolve", lambda h: [])
    monkeypatch.setattr(analyze.infra, "domain_age", lambda d: None)
    monkeypatch.setattr(analyze.infra, "tls_cert", lambda h: None)


def test_browser_cloaking_detected(monkeypatch):
    monkeypatch.setattr(analyze.redirect, "follow", _fake_follow)
    _no_rep(monkeypatch)
    # Browser lands on a DIFFERENT domain than the static fetch -> cloaking.
    monkeypatch.setattr(analyze.browser, "render", lambda url, **kw: {
        "available": True, "error": None,
        "final_url": "https://evil-phish.tk/signin",
        "html": "<title>Microsoft Login</title><input type='password'>",
        "title": "Microsoft Login", "screenshot_path": "/tmp/shot.png", "status": 200,
    })
    a = analyze.analyze_url("https://scanner-safe.example/landing", do_browser=True)
    assert a["browser"]["cloaking"] is True
    assert a["browser"]["js_redirect"] is True
    # The rendered DOM is used, so the login form is now detected.
    assert a["brand"]["login_form"] is True
    codes = {s["code"] for s in a["signals"]}
    assert "cloaking" in codes


def test_browser_unavailable_is_graceful(monkeypatch):
    monkeypatch.setattr(analyze.redirect, "follow", _fake_follow)
    _no_rep(monkeypatch)
    monkeypatch.setattr(analyze.browser, "render",
                        lambda url, **kw: {"available": False, "note": "not installed"})
    a = analyze.analyze_url("https://scanner-safe.example/landing", do_browser=True)
    assert a["browser"]["available"] is False
    # no cloaking signal when the browser didn't run
    assert "cloaking" not in {s["code"] for s in a["signals"]}


def test_render_degrades_without_playwright(monkeypatch):
    # Force the "Playwright not installed" branch without launching a browser.
    import sys
    from pathfinder import browser
    monkeypatch.setitem(sys.modules, "playwright", None)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    r = browser.render("https://example.com")
    assert r["available"] is False and "note" in r


def test_browser_available_returns_bool():
    from pathfinder import browser
    assert isinstance(browser.available(), bool)
