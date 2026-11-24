"""Extract indicators discovered during analysis, for handoff to Station."""
from __future__ import annotations
from urllib.parse import urlparse


def _add(out, seen, indicator, itype, context):
    key = (itype, indicator)
    if indicator and key not in seen:
        seen.add(key)
        out.append({"indicator": indicator, "type": itype, "context": context})


def extract(analysis: dict) -> list[dict]:
    """Pull IOCs (final URL, domains, IPs, redirectors, payload/mail artifacts)."""
    out: list[dict] = []
    seen: set = set()
    url = analysis.get("url") or {}
    infra = analysis.get("infra") or {}
    render = analysis.get("render") or {}
    email = analysis.get("email") or {}

    final = url.get("final_url")
    if final:
        _add(out, seen, final, "url", "final landing URL")
        host = urlparse(final).hostname
        if host:
            _add(out, seen, host, "domain", "landing-page host")

    for hop in url.get("redirect_chain") or []:
        h = urlparse(hop.get("url", "")).hostname
        if h:
            _add(out, seen, h, "domain", "redirect-chain host")

    for ip in (infra.get("ips") or []) + (render.get("ips") or []):
        _add(out, seen, ip, "ipv4", "resolved hosting IP")

    if email:
        dom = email.get("from_domain")
        if dom:
            _add(out, seen, dom, "domain", "email sender domain")
        for ip in email.get("received_ips") or []:
            _add(out, seen, ip, "ipv4", "email relay IP")
        for att in email.get("attachments") or []:
            if att.get("sha256"):
                _add(out, seen, att["sha256"], "sha256",
                     f"attachment {att.get('filename', '')}")
        for u in email.get("urls") or []:
            _add(out, seen, u, "url", "URL in email body")
    return out
