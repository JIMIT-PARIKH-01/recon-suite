"""
Recon pipeline: chain the passive + active modules into one pass over a domain.

Order: passive subdomain discovery -> security-header audit -> top-port scan.
Each stage is optional and failures are collected, not fatal.

Authorized use only: point this at domains you own or are permitted to test.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import subdomains, headers, portscan


@dataclass
class ReconResult:
    domain: str
    subdomains: object | None = None      # SubdomainResult
    headers: object | None = None         # HeaderReport
    ports: object | None = None           # ScanResult
    errors: list = field(default_factory=list)


def run(domain: str, *, do_subs: bool = True, do_headers: bool = True,
        do_ports: bool = True, ports: list | None = None,
        timeout: float = 1.0) -> ReconResult:
    domain = domain.strip().lower().lstrip("*.")
    result = ReconResult(domain=domain)

    if do_subs:
        try:
            result.subdomains = subdomains.enumerate_domain(domain)
        except Exception as exc:  # noqa: BLE001 - one stage failing shouldn't stop the rest
            result.errors.append(f"subdomains: {exc}")

    if do_headers:
        try:
            result.headers = headers.analyze(domain)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"headers: {exc}")

    if do_ports:
        try:
            result.ports = portscan.scan(domain, ports, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"portscan: {exc}")

    return result
