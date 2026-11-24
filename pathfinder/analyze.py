"""Orchestrate a full analysis of a URL or an email, then score it."""
from __future__ import annotations
from urllib.parse import urlparse

from . import (urltools, redirect, infra, brand, typosquat, render, emailmsg,
               iocs, score, station, safebrowsing, phishtank, browser)


def analyze_url(url: str, do_render: bool = False, do_enrich: bool = False,
                do_browser: bool = False, screenshot_dir: str | None = None) -> dict:
    unwrapped = urltools.unwrap(url)
    red = redirect.follow(unwrapped)
    final = red["final_url"]
    host = urlparse(final).hostname

    typo = typosquat.analyze(host)
    page = brand.analyze_page(red.get("final_body", ""), host)
    rnd = render.scan(final) if do_render else None

    br = None
    if do_browser:
        br = browser.render(final, screenshot_dir=screenshot_dir)
        if br.get("available") and not br.get("error"):
            b_host = urlparse(br.get("final_url") or final).hostname
            # Re-run page analysis on the JS-rendered DOM (catches dynamic forms).
            if br.get("html"):
                page = brand.analyze_page(br["html"], b_host)
            # Cloaking: the browser landed on a different registrable than the
            # static fetch — a common evasion (benign content shown to scanners).
            s_reg, b_reg = typosquat.registrable(host), typosquat.registrable(b_host)
            br["cloaking"] = bool(b_reg and s_reg and b_reg != s_reg)
            br["js_redirect"] = bool(br.get("final_url") and br["final_url"] != final)

    ips = infra.resolve(host)
    analysis = {
        "input": {"type": "url", "value": url},
        "unwrapped": unwrapped,
        "url": {
            "final_url": final,
            "redirect_chain": red["redirect_chain"],
            "hops": red["hops"],
            "host": host,
            "scheme": urlparse(final).scheme,
            "shortener_in_chain": red["shortener_in_chain"],
            "cross_site_redirect": score.cross_site(red["redirect_chain"]),
            "fetch_error": red["error"],
        },
        "infra": {
            "domain": typo["registrable"],
            "domain_age_days": infra.domain_age(typo["registrable"]),
            "tls": infra.tls_cert(host),
            "ips": ips,
        },
        "brand": page,
        "typosquat": typo,
        "render": rnd,
        "browser": br,
        "reputation": {
            "safe_browsing": safebrowsing.check(final),
            "phishtank": phishtank.check(final),
        },
        "email": None,
    }
    analysis["iocs"] = iocs.extract(analysis)
    s, v, sigs = score.compute(analysis)
    analysis.update(score=s, verdict=v, signals=sigs)
    if do_enrich:
        analysis["enrichment"] = station.enrich_iocs(analysis["iocs"])
    return analysis


def analyze_email(raw: bytes, do_render: bool = False, do_enrich: bool = False,
                  do_browser: bool = False, screenshot_dir: str | None = None) -> dict:
    em = emailmsg.parse(raw)
    analysis = {
        "input": {"type": "email", "value": em.get("subject")},
        "email": em,
        "url": {}, "infra": {}, "brand": {}, "typosquat": {},
        "render": None, "browser": None,
    }
    # If the email carries URLs, analyze the first http(s) link as the payload URL.
    if em.get("urls"):
        link = analyze_url(em["urls"][0], do_render=do_render, do_enrich=False,
                           do_browser=do_browser, screenshot_dir=screenshot_dir)
        analysis["link_analysis"] = link
        # Lift the link's analysis up for scoring context.
        for k in ("url", "infra", "brand", "typosquat", "render", "browser",
                  "reputation"):
            analysis[k] = link.get(k) or analysis.get(k)
    analysis["iocs"] = iocs.extract(analysis)
    if analysis.get("link_analysis"):
        for extra in analysis["link_analysis"].get("iocs", []):
            if extra not in analysis["iocs"]:
                analysis["iocs"].append(extra)
    s, v, sigs = score.compute(analysis)
    analysis.update(score=s, verdict=v, signals=sigs)
    if do_enrich:
        analysis["enrichment"] = station.enrich_iocs(analysis["iocs"])
    return analysis
