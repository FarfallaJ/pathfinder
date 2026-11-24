"""Pathfinder CLI.

    pathfinder <url> [--render] [--enrich] [--json] [--out FILE]
    pathfinder --eml message.eml [--render] [--enrich] [--json]
"""
from __future__ import annotations
import argparse
import json
import sys

from .analyze import analyze_url, analyze_email

_EMOJI = {"phishing": "🔴", "suspicious": "🟠", "likely-benign": "🟢",
          "inconclusive": "⚪"}


def _render_text(a: dict) -> str:
    L = []
    v = a.get("verdict", "inconclusive")
    L.append(f"{_EMOJI.get(v, '')} VERDICT: {v.upper()}  ·  phishing score {a.get('score', 0)}/100")
    if a["input"]["type"] == "url":
        u = a.get("url", {})
        L.append(f"Input:  {a['input']['value']}")
        if a.get("unwrapped") and a["unwrapped"] != a["input"]["value"]:
            L.append(f"Unwrapped: {a['unwrapped']}")
        L.append(f"Final:  {u.get('final_url')}  ({u.get('hops')} hop(s))")
        inf = a.get("infra", {})
        if inf.get("domain_age_days") is not None:
            L.append(f"Domain age: {inf['domain_age_days']} day(s)")
        if inf.get("ips"):
            L.append(f"Hosting IPs: {', '.join(inf['ips'])}")
        b = a.get("brand", {})
        if b.get("title"):
            L.append(f"Page title: {b['title']}")
    else:
        em = a.get("email", {})
        L.append(f"From:   {em.get('from')}  (domain {em.get('from_domain')})")
        L.append(f"Subject: {em.get('subject')}")
        L.append(f"Auth:   SPF={em.get('spf')} DKIM={em.get('dkim')} DMARC={em.get('dmarc')}")

    rep = a.get("reputation") or {}
    if rep:
        gsb = rep.get("safe_browsing", {}) or {}
        pt = rep.get("phishtank", {}) or {}
        L.append("")
        L.append("Reputation:")
        if not gsb.get("configured"):
            L.append("  Safe Browsing: (no GSB_API_KEY set)")
        elif gsb.get("listed"):
            L.append("  Safe Browsing: 🔴 LISTED — " + ", ".join(gsb.get("threat_types") or []))
        else:
            L.append(f"  Safe Browsing: not listed{' (' + gsb['error'] + ')' if gsb.get('error') else ''}")
        if pt.get("rate_limited"):
            L.append("  PhishTank: rate-limited (anonymous)")
        elif pt.get("in_database"):
            L.append(f"  PhishTank: 🔴 in database"
                     f"{' (verified)' if pt.get('verified') else ' (unverified)'}"
                     f"{' — ' + pt['detail_url'] if pt.get('detail_url') else ''}")
        else:
            L.append("  PhishTank: not listed")
    L.append("")
    L.append("Signals:")
    if a.get("signals"):
        for s in a["signals"]:
            L.append(f"  [{s['severity']:>6}] {s['detail']}")
    else:
        L.append("  (none fired)")
    L.append("")
    L.append("Indicators for enrichment:")
    for i in a.get("iocs", []):
        L.append(f"  {i['type']:>6}  {i['indicator']}   — {i['context']}")
    enr = a.get("enrichment")
    if enr:
        if not enr.get("available"):
            L.append("\n" + enr.get("note", ""))
        else:
            L.append("\nStation enrichment:")
            for x in enr.get("assessments", []):
                if "error" in x:
                    L.append(f"  {x.get('ioc')}: {x['error']}")
                else:
                    L.append(f"  {x['ioc']}: {x['verdict']} (risk {x['risk_score']}/100)")
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="pathfinder",
        description="Phishing & URL analysis: scout a suspicious URL or email, "
                    "mark the hazards, and extract indicators for Station.")
    p.add_argument("url", nargs="?", help="suspicious URL to analyze (defanged OK)")
    p.add_argument("--eml", help="path to an .eml email file to analyze instead")
    p.add_argument("--render", action="store_true",
                   help="submit the URL to urlscan.io for a screenshot + verdict (needs a key)")
    p.add_argument("--enrich", action="store_true",
                   help="enrich discovered indicators via Station (if installed)")
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    p.add_argument("--out", help="also write the output to this file")
    args = p.parse_args(argv)

    if args.eml:
        with open(args.eml, "rb") as f:
            result = analyze_email(f.read(), do_render=args.render, do_enrich=args.enrich)
    elif args.url:
        result = analyze_url(args.url, do_render=args.render, do_enrich=args.enrich)
    else:
        p.error("provide a URL or --eml FILE")

    out = json.dumps(result, indent=2, default=str) if args.json else _render_text(result)
    print(out)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"\n[written: {args.out}]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
