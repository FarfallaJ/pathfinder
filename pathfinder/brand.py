"""Page-content signals: login forms and brand impersonation."""
from __future__ import annotations
import re

from .typosquat import BRANDS, registrable

_PASSWORD_RE = re.compile(r"<input[^>]+type\s*=\s*['\"]?password", re.IGNORECASE)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def analyze_page(html: str, host: str | None) -> dict:
    """Detect a credential form and brand impersonation in page HTML.

    Impersonation = brand name/keyword in the page's title or visible text while
    the host is NOT one of that brand's legitimate domains.
    """
    html = html or ""
    reg = registrable(host)
    title_m = _TITLE_RE.search(html)
    title = re.sub(r"\s+", " ", (title_m.group(1) if title_m else "")).strip()[:200]

    login_form = bool(_PASSWORD_RE.search(html))

    text = re.sub(r"<[^>]+>", " ", html).lower()
    hay = (title.lower() + " " + text)[:50_000]
    impersonates: list[str] = []
    for brand, domains in BRANDS.items():
        if reg in domains:
            continue  # legitimately on the brand's own domain
        names = {brand} | {d.split(".")[0] for d in domains}
        if any(re.search(rf"\b{re.escape(n)}\b", hay) for n in names):
            impersonates.append(brand)

    return {
        "title": title,
        "login_form": login_form,
        "impersonates": impersonates[:5],
    }
