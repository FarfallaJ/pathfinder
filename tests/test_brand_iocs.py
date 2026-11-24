from pathfinder import brand, iocs


def test_login_form_and_impersonation():
    html = ("<html><head><title>Sign in to your Microsoft account</title></head>"
            "<body><form><input type='password' name='pw'></form>"
            "Microsoft 365 login</body></html>")
    r = brand.analyze_page(html, "secure-ms-verify.tk")
    assert r["login_form"] is True
    assert "microsoft" in r["impersonates"]
    assert "Microsoft" in r["title"]


def test_no_impersonation_on_legit_domain():
    html = "<title>Microsoft</title><body>Microsoft</body>"
    r = brand.analyze_page(html, "www.microsoft.com")
    assert r["impersonates"] == []


def test_ioc_extraction():
    analysis = {
        "url": {"final_url": "https://bad.tld/login",
                "redirect_chain": [{"url": "https://bit.ly/x"},
                                   {"url": "https://bad.tld/login"}]},
        "infra": {"ips": ["45.33.1.1"]},
        "render": {"ips": ["45.33.1.1"]},
        "email": {},
    }
    out = iocs.extract(analysis)
    inds = {(i["type"], i["indicator"]) for i in out}
    assert ("url", "https://bad.tld/login") in inds
    assert ("domain", "bad.tld") in inds
    assert ("domain", "bit.ly") in inds
    assert ("ipv4", "45.33.1.1") in inds
