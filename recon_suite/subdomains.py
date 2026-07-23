"""
Passive subdomain enumerator (standard library only).

Uses Certificate Transparency logs via crt.sh (passive OSINT -- no traffic to the
target) and optionally resolves each name to an IP. Safe, non-intrusive recon.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field


@dataclass
class SubdomainResult:
    domain: str
    found: list = field(default_factory=list)     # list[(subdomain, ip_or_None)]

    @property
    def live(self) -> list:
        return [(s, ip) for s, ip in self.found if ip]

    def as_text(self) -> str:
        lines = [f"Domain    : {self.domain}",
                 f"Found     : {len(self.found)} subdomain(s)  "
                 f"({len(self.live)} resolve to an IP)"]
        for sub, ip in self.found:
            lines.append(f"  {sub:<45} {ip or '-'}")
        return "\n".join(lines)


def parse_crtsh(data: list, domain: str) -> list:
    """Extract unique in-scope names from crt.sh JSON records."""
    subs: set = set()
    for entry in data:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith("." + domain) or name == domain:
                subs.add(name)
    return sorted(subs)


def from_crtsh(domain: str, timeout: float = 40.0) -> list:
    """Query crt.sh certificate transparency logs for names under `domain`."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "recon-suite/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        raise ConnectionError(f"crt.sh query failed for {domain}: {exc}") from exc
    return parse_crtsh(data, domain)


def resolve(name: str, timeout: float = 3.0) -> str | None:
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyname(name)
    except (socket.gaierror, OSError):
        return None


def enumerate_domain(domain: str, resolve_ips: bool = True) -> SubdomainResult:
    domain = domain.strip().lower().lstrip("*.")
    subs = from_crtsh(domain)
    found = [(s, resolve(s) if resolve_ips else None) for s in subs]
    return SubdomainResult(domain=domain, found=found)
