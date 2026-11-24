from pathfinder import score


def test_phishing_combo():
    a = {
        "url": {"hops": 4, "cross_site_redirect": True, "shortener_in_chain": True},
        "infra": {"domain_age_days": 3, "tls": {"issuer": "Let's Encrypt"}},
        "brand": {"login_form": True, "impersonates": ["microsoft"]},
        "typosquat": {"is_lookalike": True, "nearest_brand": "microsoft",
                      "technique": "combo-squat", "punycode": False},
        "render": {}, "email": {},
    }
    s, v, sigs = score.compute(a)
    assert v == "phishing" and s >= 60
    codes = {x["code"] for x in sigs}
    assert {"very-new-domain", "credential-form", "typosquat"} <= codes


def test_clean_is_benign_or_inconclusive():
    a = {"url": {"hops": 0}, "infra": {"domain_age_days": 3000, "tls": {}},
         "brand": {"login_form": False, "impersonates": []},
         "typosquat": {"is_lookalike": False}, "render": {}, "email": {}}
    s, v, sigs = score.compute(a)
    assert s == 0 and v == "inconclusive"


def test_email_auth_failures_score():
    a = {"url": {}, "infra": {}, "brand": {}, "typosquat": {}, "render": {},
         "email": {"dmarc": "fail", "spf": "fail", "display_name_spoof": True,
                   "reply_to_mismatch": True}}
    s, v, sigs = score.compute(a)
    assert s >= 30 and v in ("suspicious", "phishing")


def test_cross_site_helper():
    chain = [{"url": "https://bit.ly/x"}, {"url": "https://evil.tld/y"}]
    assert score.cross_site(chain) is True
    assert score.cross_site([{"url": "https://a.evil.tld/1"},
                             {"url": "https://b.evil.tld/2"}]) is False
