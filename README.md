# Pathfinder

Phishing & URL analysis for CTI and SOC triage. Pathfinder takes a suspicious
**URL** or **email (.eml)**, scouts the route it takes without clicking it in a
real browser, marks the hazards, and extracts the indicators it discovers — then
hands them to [Station](https://github.com/FarfallaJ/cti-ioc-enrichment) for
reputation and attribution.

> **Station vs. Pathfinder** — Station answers *"is this indicator known bad?"*
> (reputation across threat-intel feeds). Pathfinder answers *"what is this URL
> or email actually doing?"* (behavioral/structural analysis). Pathfinder doesn't
> re-implement reputation — it discovers IOCs and delegates that to Station.

## What it checks

- **Unwrap & decode** — Microsoft Safe Links, Proofpoint URL Defense, and generic
  `?url=` redirectors; defanged input (`hxxp://a[.]b`) is fine.
- **Redirect chain** — follows every hop to the final landing page, flags long
  chains, cross-site hops, and URL shorteners.
- **Typosquat / lookalike** — exact-brand-wrong-domain, combo-squats, brand-in-
  subdomain, homoglyph substitutions, and punycode/IDN homographs.
- **Page signals** — credential (password) form detection and brand impersonation
  in the page title/content.
- **Infrastructure** — domain age (RDAP), TLS certificate issuer/SAN, resolved IPs.
- **Email (.eml)** — From / Reply-To / Return-Path analysis, SPF/DKIM/DMARC
  results, display-name spoofing, body URLs, and attachment hashes.
- **Optional render** — submit the URL to urlscan.io for a screenshot and verdict
  (reuses the `URLSCAN_API_KEY` you already set for Station).
- **Weighted verdict** — a 0–100 phishing score with the signals that fired.

## Quick start

```bash
pip install -e .

# Analyze a URL
pathfinder "hxxps://paypal-secure-login[.]tk/signin"

# Add a urlscan screenshot + verdict (needs URLSCAN_API_KEY)
pathfinder https://suspicious.example/login --render

# Analyze an email
pathfinder --eml reported_message.eml

# Enrich the discovered indicators through Station, and emit JSON
pathfinder https://suspicious.example/login --enrich --json
```

## The Station handoff

Pathfinder *finds* indicators; Station *enriches* them. With `--enrich` (or the
`station` module), every IOC Pathfinder extracts — the final domain, hosting IPs,
redirector domains, email sender domain, attachment hashes — is passed to
Station's engine for a verdict and attribution:

```
Suspicious URL / .eml
   │  decode, follow redirects, screenshot, detect impersonation, parse email
   ▼
Pathfinder ──emits IOCs──▶ Station (enrich + score + attribute)
   │                                     │
   ▼                                     ▼
 phishing verdict                 known-bad? tied to an actor/campaign?
```

Install Station alongside Pathfinder so the handoff works:

```bash
pip install -e ../cti-ioc-enrichment    # or wherever Station lives
```

If Station isn't installed, Pathfinder still runs — it just reports the IOCs for
you to enrich elsewhere.

## Configuration

Only the optional urlscan render needs a key. Pathfinder reuses Station's key
loader if present, or reads `URLSCAN_API_KEY` from the environment / a `.env`.
See `.env.example`.

## Testing

```bash
python -m pytest        # 26 tests, network mocked (no keys or network needed)
```

## Disclaimer

For defensive and authorized use. Verdicts are a first-pass triage aid — confirm
before blocking or alerting. Pathfinder follows redirects and reads pages with a
plain HTTP client; analyze hostile URLs from an environment you're willing to
expose, and prefer the urlscan render for anything you don't want to touch directly.

## License

MIT — see [LICENSE](LICENSE).
