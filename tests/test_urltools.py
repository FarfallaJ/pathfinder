from pathfinder import urltools as u


def test_defang():
    assert u.defang("hxxps://evil[.]com/x") == "https://evil.com/x"


def test_safelinks_unwrap():
    wrapped = ("https://nam12.safelinks.protection.outlook.com/?url="
               "https%3A%2F%2Fevil%2Elogin%2Ecom%2Fverify&data=05%7C01")
    assert u.unwrap(wrapped) == "https://evil.login.com/verify"


def test_generic_url_wrapper():
    assert u.unwrap("https://gw.example.com/redir?url=https%3A%2F%2Fbad.tld%2Fp") \
        == "https://bad.tld/p"


def test_proofpoint_v2():
    # u param: '-' -> '%', '_' -> '/'
    wrapped = "https://urldefense.proofpoint.com/v2/url?u=https-3A__bad.tld_login&d=x"
    out = u.unwrap(wrapped)
    assert out.startswith("https://bad.tld/login")


def test_shortener_detection():
    assert u.is_shortener("bit.ly")
    assert not u.is_shortener("microsoft.com")


def test_host_of():
    assert u.host_of("https://a.b.com/x") == "a.b.com"
