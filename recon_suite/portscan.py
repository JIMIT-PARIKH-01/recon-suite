"""
Async TCP connect port scanner (standard library only).

For authorized use: scan only hosts you own or have explicit permission to test.
This performs a plain TCP connect (no stealth / evasion) and reports open ports.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field

# A compact "top ports" set with service names for readable output.
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s", 1723: "pptp",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 27017: "mongodb",
}
TOP_PORTS = sorted(COMMON_PORTS)


@dataclass
class ScanResult:
    host: str
    ip: str
    open_ports: list = field(default_factory=list)   # list[(port, service)]

    def as_text(self) -> str:
        lines = [f"Host : {self.host} ({self.ip})",
                 f"Open : {len(self.open_ports)} port(s)"]
        for port, svc in self.open_ports:
            lines.append(f"  {port:>5}/tcp  open   {svc}")
        if not self.open_ports:
            lines.append("  (no open ports found in the scanned range)")
        return "\n".join(lines)


def parse_ports(spec: str) -> list:
    """Parse '22,80,443', '1-1024', 'top', or a mix into a sorted port list."""
    if not spec or spec.strip().lower() == "top":
        return list(TOP_PORTS)
    ports: set = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p <= 65535)


async def _check(ip: str, port: int, timeout: float) -> bool:
    try:
        fut = asyncio.open_connection(ip, port)
        _reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 - close errors don't change "open"
            pass
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def _scan_async(ip: str, ports: list, timeout: float, concurrency: int) -> list:
    sem = asyncio.Semaphore(concurrency)
    found: list = []

    async def worker(port: int) -> None:
        async with sem:
            if await _check(ip, port, timeout):
                found.append(port)

    await asyncio.gather(*(worker(p) for p in ports))
    return sorted(found)


def scan(host: str, ports: list | None = None, timeout: float = 1.0,
         concurrency: int = 300) -> ScanResult:
    """Resolve `host` and TCP-connect-scan `ports` (defaults to top ports)."""
    ports = ports if ports is not None else list(TOP_PORTS)
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve host '{host}': {exc}") from exc
    open_ports = asyncio.run(_scan_async(ip, ports, timeout, concurrency))
    return ScanResult(host=host, ip=ip,
                      open_ports=[(p, COMMON_PORTS.get(p, "unknown")) for p in open_ports])
