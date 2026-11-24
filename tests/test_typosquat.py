from pathfinder import typosquat as t


def test_legit_brand_is_not_lookalike():
    r = t.analyze("login.microsoftonline.com")
    assert r["is_lookalike"] is False
    assert r["legit_brand"] == "microsoft"


def test_exact_brand_wrong_tld():
    r = t.analyze("paypal.tk")
    assert r["is_lookalike"] and r["nearest_brand"] == "paypal"


def test_combosquat():
    r = t.analyze("paypal-secure-login.com")
    assert r["is_lookalike"] and r["nearest_brand"] == "paypal"


def test_brand_in_subdomain():
    r = t.analyze("login.microsoft.account-verify.ru")
    assert r["is_lookalike"] and r["nearest_brand"] == "microsoft"


def test_homoglyph():
    r = t.analyze("paypa1.com")  # '1' -> 'l'
    assert r["is_lookalike"] and r["nearest_brand"] == "paypal"


def test_punycode():
    r = t.analyze("xn--pypal-4ve.com")
    assert r["is_lookalike"] and r["punycode"]


def test_unrelated_domain_is_clean():
    r = t.analyze("example.org")
    assert r["is_lookalike"] is False


def test_registrable_multi_tld():
    assert t.registrable("a.b.co.uk") == "b.co.uk"
