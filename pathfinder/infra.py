"""Infrastructure checks: TLS certificate, domain age (RDAP), resolved IPs."""
from __future__ import annotations
import socket
import ssl
from datetime import datetime, timezone

import requests


def resolve(host: str | None) -> list[str]:
    if not host:
        return []
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        return sorted({i[4][0] for i in infos})
    except Exception:  # noqa: BLE001
        return []


def tls_cert(host: str | None, port: int = 443, timeout: int = 10) -> dict | None:
    if not host:
        return None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
    except Exception:  # noqa: BLE001
        return None
    if not cert:
        return None

    def _name(seq):
        out = {}
        for rdn in seq or []:
            for k, v in rdn:
                out[k] = v
        return out

    issuer = _name(cert.get("issuer"))
    subject = _name(cert.get("subject"))
    san = [v for (t, v) in cert.get("subjectAltName", []) if t == "DNS"]
    return {
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "subject": subject.get("commonName"),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "san": san[:20],
    }


def domain_age(domain: str | None, timeout: int = 12) -> int | None:
    """Age in days from the RDAP registration event, or None if unavailable."""
    if not domain:
        return None
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=timeout,
                         headers={"Accept": "application/rdap+json"})
        if r.status_code != 200:
            return None
        data = r.json()
    except Exception:  # noqa: BLE001
        return None
    reg = None
    for ev in data.get("events", []) or []:
        if ev.get("eventAction") == "registration":
            reg = ev.get("eventDate")
            break
    if not reg:
        return None
    try:
        dt = datetime.fromisoformat(reg.replace("Z", "+00:00"))
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except Exception:  # noqa: BLE001
        return None
