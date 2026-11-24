"""Follow a URL's redirect chain without executing it in a real browser."""
from __future__ import annotations
from urllib.parse import urljoin, urlparse

import requests

from .urltools import is_shortener

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


def follow(url: str, max_hops: int = 10, timeout: int = 15,
           user_agent: str = BROWSER_UA) -> dict:
    """Walk HTTP redirects one hop at a time. Returns the chain, the final URL,
    and the final response body/headers (for page analysis). Never raises."""
    chain: list[dict] = []
    shortener = False
    cur = url
    final_body, final_status, final_headers, error = "", None, {}, None
    try:
        sess = requests.Session()
        for _ in range(max_hops):
            host = urlparse(cur).hostname
            if is_shortener(host):
                shortener = True
            resp = sess.get(cur, allow_redirects=False, timeout=timeout,
                            headers={"User-Agent": user_agent}, verify=True)
            chain.append({"url": cur, "status": resp.status_code})
            loc = resp.headers.get("Location")
            if resp.is_redirect and loc:
                cur = urljoin(cur, loc)
                continue
            final_status = resp.status_code
            final_headers = dict(resp.headers)
            final_body = resp.text[:200_000] if resp.text else ""
            break
    except Exception as e:  # noqa: BLE001
        error = str(e)

    return {
        "final_url": cur,
        "redirect_chain": chain,
        "hops": max(0, len(chain) - 1),
        "final_status": final_status,
        "final_headers": final_headers,
        "final_body": final_body,
        "shortener_in_chain": shortener,
        "error": error,
    }
