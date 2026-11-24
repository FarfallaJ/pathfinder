"""Lookalike / typosquat analysis against commonly-impersonated brands."""
from __future__ import annotations

# brand -> legitimate registrable domains
BRANDS: dict[str, list[str]] = {
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com",
                  "office365.com", "microsoftonline.com"],
    "google": ["google.com", "gmail.com", "googlemail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com"],
    "paypal": ["paypal.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "coinbase": ["coinbase.com"],
}

# characters attackers swap to mimic letters
_HOMOGLYPHS = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    "$": "s", "@": "a", "|": "l", "!": "i",
})

_MULTI_TLD = {"co.uk", "com.au", "co.jp", "com.br", "co.in", "co.nz"}


def _lev(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return len(a) or len(b)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[-1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registrable(host: str | None) -> str:
    """Crude eTLD+1 (good enough for the brand set; handles a few multi-part TLDs)."""
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in _MULTI_TLD and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def analyze(host: str | None) -> dict:
    host = (host or "").lower().strip(".")
    reg = registrable(host)
    base = reg.split(".")[0] if reg else ""
    norm = base.translate(_HOMOGLYPHS)
    labels = host.split(".")
    subdomains = labels[:-2] if len(labels) > 2 else []
    res = {"host": host, "registrable": reg, "punycode": "xn--" in host,
           "is_lookalike": False, "nearest_brand": None, "technique": None,
           "legit_brand": None}

    # Legitimate brand domain -> not a typosquat.
    for brand, domains in BRANDS.items():
        if reg in domains:
            res["legit_brand"] = brand
            return res

    for brand, domains in BRANDS.items():
        names = {d.split(".")[0] for d in domains} | {brand}
        # length >= 4 names only for substring checks (avoids short-token noise)
        long_names = {n for n in names if len(n) >= 4}
        # exact brand name on a non-official registrable (wrong TLD / fake domain)
        if base in names:
            return {**res, "is_lookalike": True, "nearest_brand": brand,
                    "technique": "exact brand name on non-official domain"}
        # brand name embedded in the registrable base (combo-squat)
        if any(n in base and base != n for n in long_names):
            return {**res, "is_lookalike": True, "nearest_brand": brand,
                    "technique": "brand keyword in domain (combo-squat)"}
        # brand name used in a subdomain while the registrable is unrelated
        if any(n in sub for sub in subdomains for n in long_names):
            return {**res, "is_lookalike": True, "nearest_brand": brand,
                    "technique": "brand name in subdomain"}
        # homoglyph substitution normalizes the base exactly onto a brand name
        for n in names:
            if norm == n and base != n:
                return {**res, "is_lookalike": True, "nearest_brand": brand,
                        "technique": f"homoglyph substitution for '{n}'"}
        # single-character typo on a longer brand name
        for n in long_names:
            if len(n) >= 5 and 0 < _lev(norm, n) <= 1 and abs(len(norm) - len(n)) <= 1:
                return {**res, "is_lookalike": True, "nearest_brand": brand,
                        "technique": f"lookalike of '{n}' (edit distance 1)"}

    if res["punycode"]:
        return {**res, "is_lookalike": True,
                "technique": "punycode / IDN homograph"}
    return res
