"""Safe Browsing + PhishTank checks and their scoring — HTTP mocked."""
from pathfinder import safebrowsing, phishtank, score, config


class FakeResp:
    def __init__(self, data, status=200):
        self._d = data
        self.status_code = status

    def json(self):
        return self._d


# ---- Google Safe Browsing ----------------------------------------------
def test_gsb_listed(monkeypatch):
    monkeypatch.setattr(config, "get_key", lambda n: "k")
    monkeypatch.setattr(safebrowsing.requests, "post", lambda u, **k: FakeResp(
        {"matches": [{"threatType": "SOCIAL_ENGINEERING",
                      "threat": {"url": "http://bad.tld"}}]}))
    r = safebrowsing.check("http://bad.tld")
    assert r["listed"] is True and "SOCIAL_ENGINEERING" in r["threat_types"]


def test_gsb_clean(monkeypatch):
    monkeypatch.setattr(config, "get_key", lambda n: "k")
    monkeypatch.setattr(safebrowsing.requests, "post", lambda u, **k: FakeResp({}))
    r = safebrowsing.check("http://good.tld")
    assert r["listed"] is False and r["configured"] is True


def test_gsb_no_key(monkeypatch):
    monkeypatch.setattr(config, "get_key", lambda n: None)
    r = safebrowsing.check("http://x.tld")
    assert r["configured"] is False and r["listed"] is False


# ---- PhishTank ---------------------------------------------------------
def test_phishtank_verified(monkeypatch):
    monkeypatch.setattr(config, "get_key", lambda n: None)
    monkeypatch.setattr(phishtank.requests, "post", lambda u, **k: FakeResp(
        {"results": {"in_database": True, "verified": "y", "valid": "y",
                     "phish_id": "12345",
                     "phish_detail_page": "https://phishtank.com/phish/12345"}}))
    r = phishtank.check("http://bad.tld/login")
    assert r["in_database"] and r["verified"] and r["phish_id"] == "12345"


def test_phishtank_clean(monkeypatch):
    monkeypatch.setattr(config, "get_key", lambda n: None)
    monkeypatch.setattr(phishtank.requests, "post", lambda u, **k: FakeResp(
        {"results": {"in_database": False}}))
    assert phishtank.check("http://good.tld")["in_database"] is False


def test_phishtank_rate_limited(monkeypatch):
    monkeypatch.setattr(config, "get_key", lambda n: None)
    monkeypatch.setattr(phishtank.requests, "post",
                        lambda u, **k: FakeResp({}, status=509))
    r = phishtank.check("http://x.tld")
    assert r["rate_limited"] is True and r["in_database"] is False


# ---- scoring -----------------------------------------------------------
def test_reputation_signals_drive_verdict():
    a = {"url": {}, "infra": {}, "brand": {}, "typosquat": {}, "render": {},
         "email": {}, "reputation": {
             "safe_browsing": {"listed": True, "threat_types": ["SOCIAL_ENGINEERING"]},
             "phishtank": {"in_database": True, "verified": True, "phish_id": "9"}}}
    s, v, sigs = score.compute(a)
    codes = {x["code"] for x in sigs}
    assert "gsb-listed" in codes and "phishtank-verified" in codes
    assert v == "phishing" and s >= 60


def test_authoritative_hit_floors_verdict():
    # GSB hit alone scores 35 (< 60), but an authoritative hit must read phishing.
    a = {"url": {}, "infra": {}, "brand": {}, "typosquat": {}, "render": {},
         "email": {}, "reputation": {
             "safe_browsing": {"listed": True, "threat_types": ["SOCIAL_ENGINEERING"]},
             "phishtank": {"in_database": False}}}
    s, v, _ = score.compute(a)
    assert s < 60 and v == "phishing"
