"""End-to-end analyze with network mocked, plus the Station bridge."""
from pathfinder import analyze, station


def _fake_follow(url, **kw):
    return {
        "final_url": "https://paypal-secure-login.tk/signin",
        "redirect_chain": [{"url": "https://bit.ly/x", "status": 301},
                           {"url": "https://paypal-secure-login.tk/signin", "status": 200}],
        "hops": 1,
        "final_status": 200,
        "final_headers": {},
        "final_body": "<title>PayPal - Log In</title><input type='password'> PayPal",
        "shortener_in_chain": True,
        "error": None,
    }


def test_analyze_url_flags_phishing(monkeypatch):
    monkeypatch.setattr(analyze.redirect, "follow", _fake_follow)
    monkeypatch.setattr(analyze.infra, "resolve", lambda h: ["45.33.1.1"])
    monkeypatch.setattr(analyze.infra, "domain_age", lambda d: 2)
    monkeypatch.setattr(analyze.infra, "tls_cert", lambda h: {"issuer": "Let's Encrypt"})

    a = analyze.analyze_url("hxxps://bit[.]ly/x")
    assert a["verdict"] == "phishing"
    assert a["typosquat"]["nearest_brand"] == "paypal"
    assert a["brand"]["login_form"] is True
    # IOCs discovered for Station
    types = {i["type"] for i in a["iocs"]}
    assert {"url", "domain", "ipv4"} <= types


def test_station_bridge_without_station(monkeypatch):
    # Simulate ioc_enrich not installed.
    import builtins
    real_import = builtins.__import__

    def _blocked(name, *args, **kw):
        if name.startswith("ioc_enrich"):
            raise ImportError("no station")
        return real_import(name, *args, **kw)

    monkeypatch.setattr(builtins, "__import__", _blocked)
    out = station.enrich_iocs([{"indicator": "1.2.3.4", "type": "ipv4", "context": "x"}])
    assert out["available"] is False and "not installed" in out["note"]


def test_station_bridge_with_fake_station(monkeypatch):
    import sys, types

    class _A:
        def to_dict(self):
            return {"ioc": "1.2.3.4", "verdict": "malicious", "risk_score": 70}

    fake_engine = types.ModuleType("ioc_enrich.engine")
    fake_engine.enrich = lambda ioc, sources=None: _A()
    fake_pkg = types.ModuleType("ioc_enrich")
    monkeypatch.setitem(sys.modules, "ioc_enrich", fake_pkg)
    monkeypatch.setitem(sys.modules, "ioc_enrich.engine", fake_engine)

    out = station.enrich_iocs([
        {"indicator": "1.2.3.4", "type": "ipv4", "context": "x"},
        {"indicator": "skip-me", "type": "other", "context": "x"},
    ])
    assert out["available"] is True
    assert len(out["assessments"]) == 1
    assert out["assessments"][0]["verdict"] == "malicious"
