"""
HTTP security-header analyzer (defensive; standard library only).

Fetches a URL and grades its security headers, flags information-leak headers,
and lists what's missing. A read-only GET — safe to run against any site you
want to audit.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field

# header (lowercase) -> (short name, why it matters)
SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "forces HTTPS, blocks SSL-strip"),
    "content-security-policy": ("CSP", "mitigates XSS / injection"),
    "x-frame-options": ("X-Frame-Options", "clickjacking protection"),
    "x-content-type-options": ("X-Content-Type-Options", "blocks MIME sniffing"),
    "referrer-policy": ("Referrer-Policy", "limits referrer leakage"),
    "permissions-policy": ("Permissions-Policy", "restricts browser features"),
    "cross-origin-opener-policy": ("COOP", "isolates browsing context (Spectre)"),
    "cross-origin-embedder-policy": ("COEP", "controls cross-origin resource loading"),
    "cross-origin-resource-policy": ("CORP", "blocks cross-origin resource theft"),
}
# Headers that leak stack/version info.
LEAK_HEADERS = ("server", "x-powered-by", "x-aspnet-version",
                "x-aspnetmvc-version", "x-generator")


@dataclass
class HeaderReport:
    url: str
    status: int
    present: dict = field(default_factory=dict)     # header -> value
    missing: list = field(default_factory=list)     # (header, name, why)
    leaks: dict = field(default_factory=dict)       # header -> value
    grade: str = "?"

    def as_text(self) -> str:
        lines = [f"URL    : {self.url}",
                 f"Status : {self.status}",
                 f"Grade  : {self.grade}  ({len(self.present)}/{len(SECURITY_HEADERS)} security headers)"]
        if self.present:
            lines.append("Present:")
            for h in self.present:
                lines.append(f"  + {SECURITY_HEADERS[h][0]}")
        if self.missing:
            lines.append("Missing:")
            for _h, name, why in self.missing:
                lines.append(f"  - {name:<26} ({why})")
        if self.leaks:
            lines.append("Info leaks:")
            for h, v in self.leaks.items():
                lines.append(f"  ! {h}: {v}")
        return "\n".join(lines)


def _grade(n_present: int) -> str:
    total = len(SECURITY_HEADERS)
    pct = n_present / total
    return ("A" if pct >= 0.9 else "B" if pct >= 0.7 else
            "C" if pct >= 0.5 else "D" if pct >= 0.3 else "F")


def analyze(url: str, timeout: float = 10.0) -> HeaderReport:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    req = urllib.request.Request(
        url, method="GET",
        headers={"User-Agent": "recon-suite/1.0 (security header audit)"})
    ctx = ssl.create_default_context()
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        status = resp.status
        raw = resp.headers
    except urllib.error.HTTPError as exc:      # 4xx/5xx still carry headers
        status = exc.code
        raw = exc.headers
    except (urllib.error.URLError, ssl.SSLError, OSError) as exc:
        raise ConnectionError(f"Could not fetch {url}: {exc}") from exc

    headers = {k.lower(): v for k, v in raw.items()}
    present = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
    missing = [(h, name, why) for h, (name, why) in SECURITY_HEADERS.items()
               if h not in headers]
    leaks = {h: headers[h] for h in LEAK_HEADERS if h in headers}
    return HeaderReport(url=url, status=status, present=present, missing=missing,
                        leaks=leaks, grade=_grade(len(present)))
