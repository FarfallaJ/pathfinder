"""Pathfinder MCP server tests — analysis mocked, no network."""
import pathfinder.mcp_server as m


def test_analyze_url_helper_trims_html(monkeypatch):
    monkeypatch.setattr(m, "_au",
                        lambda url, do_render=False, do_browser=False, do_enrich=False,
                        screenshot_dir=None: {
                            "verdict": "phishing", "score": 80,
                            "browser": {"html": "<BIG>", "cloaking": True,
                                        "screenshot_path": "/tmp/x.png"}})
    out = m._analyze_url("http://x", browser=True)
    assert out["verdict"] == "phishing"
    assert "html" not in out["browser"]            # heavy field trimmed
    assert out["browser"]["cloaking"] is True


def test_analyze_email_helper_encodes(monkeypatch):
    captured = {}

    def _fake_ae(raw, do_render=False, do_browser=False, do_enrich=False):
        captured["raw"] = raw
        return {"verdict": "suspicious", "email": {"spf": "fail"}}

    monkeypatch.setattr(m, "_ae", _fake_ae)
    out = m._analyze_email("From: a@b.com\nSubject: x\n\nbody")
    assert isinstance(captured["raw"], bytes)       # str was encoded to bytes
    assert out["verdict"] == "suspicious"


def test_check_reputation_helper(monkeypatch):
    monkeypatch.setattr(m.safebrowsing, "check", lambda u: {"listed": True})
    monkeypatch.setattr(m.phishtank, "check", lambda u: {"in_database": False})
    out = m._check_reputation("http://x")
    assert out["url"] == "http://x"
    assert out["safe_browsing"]["listed"] is True


def test_build_server_registers_tools():
    import pytest
    pytest.importorskip("mcp")
    srv = m.build_server()
    names = set(srv._tool_manager._tools.keys())
    assert {"analyze_url", "analyze_email", "check_reputation"} <= names
