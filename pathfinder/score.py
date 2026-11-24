"""Weighted phishing score and verdict from the assembled analysis."""
from __future__ import annotations
from urllib.parse import urlparse

from .typosquat import registrable


def _sig(signals, code, weight, severity, detail):
    signals.append({"code": code, "weight": weight, "severity": severity,
                    "detail": detail})


def compute(analysis: dict) -> tuple[int, str, list[dict]]:
    """Return (score 0-100, verdict, signals) from an analysis dict."""
    signals: list[dict] = []
    url = analysis.get("url") or {}
    infra = analysis.get("infra") or {}
    brand = analysis.get("brand") or {}
    typo = analysis.get("typosquat") or {}
    render = analysis.get("render") or {}
    email = analysis.get("email") or {}
    rep = analysis.get("reputation") or {}

    # Authoritative blocklist hits (strongest signals).
    gsb = rep.get("safe_browsing") or {}
    if gsb.get("listed"):
        tt = ", ".join(gsb.get("threat_types") or []) or "listed"
        _sig(signals, "gsb-listed", 35, "high",
             f"Google Safe Browsing flagged it ({tt})")
    pt = rep.get("phishtank") or {}
    if pt.get("in_database") and pt.get("verified"):
        _sig(signals, "phishtank-verified", 35, "high",
             f"PhishTank verified phish (id {pt.get('phish_id')})")
    elif pt.get("in_database"):
        _sig(signals, "phishtank-listed", 15, "medium",
             "Listed in PhishTank (unverified)")

    age = infra.get("domain_age_days")
    if age is not None and age < 7:
        _sig(signals, "very-new-domain", 30, "high",
             f"Domain registered {age} day(s) ago")
    elif age is not None and age < 30:
        _sig(signals, "new-domain", 22, "high",
             f"Domain registered {age} day(s) ago")

    if brand.get("login_form"):
        _sig(signals, "credential-form", 22, "high",
             "Password/login form present on the landing page")

    if typo.get("is_lookalike"):
        _sig(signals, "typosquat", 25, "high",
             f"Lookalike of {typo.get('nearest_brand') or 'a known brand'}: "
             f"{typo.get('technique')}")
    if typo.get("punycode"):
        _sig(signals, "punycode", 15, "high", "Punycode / IDN homograph domain")

    if brand.get("impersonates"):
        _sig(signals, "brand-impersonation", 20, "high",
             "Page content impersonates: " + ", ".join(brand["impersonates"]))

    hops = url.get("hops") or 0
    if hops > 3:
        _sig(signals, "long-redirect-chain", 10, "medium",
             f"{hops} redirect hops before landing")
    if url.get("cross_site_redirect"):
        _sig(signals, "cross-site-redirect", 10, "medium",
             "Redirect crossed to an unrelated registrable domain")
    if url.get("shortener_in_chain"):
        _sig(signals, "shortener", 6, "low", "URL shortener used in the chain")

    tls = infra.get("tls") or {}
    issuer = (tls.get("issuer") or "").lower()
    if issuer and ("let's encrypt" in issuer or "zerossl" in issuer) and \
            (typo.get("is_lookalike") or brand.get("impersonates")):
        _sig(signals, "free-cert-on-lookalike", 10, "medium",
             f"Free TLS cert ({tls.get('issuer')}) on a brand-impersonating domain")

    rv = (render.get("urlscan_verdict") or "").lower()
    if rv == "malicious":
        _sig(signals, "urlscan-malicious", 25, "high", "urlscan.io scored it malicious")
    elif rv == "suspicious":
        _sig(signals, "urlscan-suspicious", 12, "medium", "urlscan.io flagged it suspicious")

    # Email authentication signals
    if email:
        if (email.get("dmarc") or "").lower() == "fail":
            _sig(signals, "dmarc-fail", 20, "high", "DMARC failed")
        if (email.get("spf") or "").lower() == "fail":
            _sig(signals, "spf-fail", 10, "medium", "SPF failed")
        if email.get("display_name_spoof"):
            _sig(signals, "display-name-spoof", 15, "high",
                 "Sender display name impersonates a brand/domain it isn't")
        if email.get("reply_to_mismatch"):
            _sig(signals, "reply-to-mismatch", 10, "medium",
                 "Reply-To domain differs from the From domain")

    score = min(100, sum(s["weight"] for s in signals))
    if score >= 60:
        verdict = "phishing"
    elif score >= 30:
        verdict = "suspicious"
    elif signals:
        verdict = "likely-benign"
    else:
        verdict = "inconclusive"
    return score, verdict, signals


def cross_site(chain: list[dict]) -> bool:
    regs = {registrable(urlparse(h.get("url", "")).hostname) for h in chain}
    regs.discard("")
    return len(regs) > 1
