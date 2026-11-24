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
- **Reputation blocklists** — checks the final URL against **Google Safe Browsing**
  (authoritative phishing/malware verdict) and **PhishTank**; a hit near-confirms
  the verdict.
- **Infrastructure** — domain age (RDAP), TLS certificate issuer/SAN, resolved IPs.
- **Email (.eml)** — From / Reply-To / Return-Path analysis, SPF/DKIM/DMARC
  results, display-name spoofing, body URLs, and attachment hashes.
- **Headless render (keyless)** — with `--browser`, render the page in headless
  Chromium (Playwright): a screenshot, the *JavaScript-executed* final URL,
  dynamically-rendered login forms the static fetch misses, and **cloaking
  detection** (when the browser lands somewhere different than the static fetch).
- **urlscan render** — alternatively, `--render` submits to urlscan.io for a
  screenshot + verdict (reuses the `URLSCAN_API_KEY` you set for Station).
- **Weighted verdict** — a 0–100 phishing score with the signals that fired.

## Quick start

```bash
pip install -e .

# Analyze a URL
pathfinder "hxxps://paypal-secure-login[.]tk/signin"

# Keyless headless render: screenshot, JS redirects, dynamic forms, cloaking
pathfinder https://suspicious.example/login --browser

# Or a urlscan screenshot + verdict (needs URLSCAN_API_KEY)
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

All keys are optional — Pathfinder degrades cleanly without them. Copy
`.env.example` to `.env` and fill what you have:

- **`GSB_API_KEY`** — Google Safe Browsing v4 (free, non-commercial). In the
  Google Cloud Console: create a project, enable the **Safe Browsing API**, and
  create an API key. This unlocks the strongest signal.
- **`PHISHTANK_API_KEY`** — optional; PhishTank works anonymously (rate-limited)
  and a key raises the limit.
- **`URLSCAN_API_KEY`** — only for the `--render` screenshot.

Pathfinder reuses Station's key loader too, so one `.env` can serve both tools.

## Headless render (optional)

The `--browser` render is keyless but needs Playwright and a Chromium binary:

```bash
pip install -e ".[browser]"
playwright install chromium
```

Then `--browser` gives a screenshot, the JS-executed final URL, dynamic-form
detection, and cloaking. It executes page JavaScript in sandboxed headless
Chromium — still, analyze genuinely hostile URLs from an isolated environment.

## MCP server

Pathfinder ships an MCP server so an assistant (Claude Desktop, IDEs, agents)
can drive it as native tools — and, with `enrich=True`, chain straight into
Station in one call.

```bash
pip install -e ".[mcp]"
pathfinder-mcp            # stdio transport
```

Tools: `analyze_url`, `analyze_email`, `check_reputation`. Each `analyze_*` tool
takes `render` / `browser` / `enrich` flags, so a client can say "analyze this
URL in a real browser and enrich what you find" and get Pathfinder's analysis
and Station's reputation/attribution in a single response.

## Testing

```bash
python -m pytest        # 42 tests, network mocked (no keys or network needed)
```

## Disclaimer

For defensive and authorized use. Verdicts are a first-pass triage aid — confirm
before blocking or alerting. Pathfinder follows redirects and reads pages with a
plain HTTP client; analyze hostile URLs from an environment you're willing to
expose, and prefer the urlscan render for anything you don't want to touch directly.

## License

MIT — see [LICENSE](LICENSE).
