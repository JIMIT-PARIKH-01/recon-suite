"""Render a ReconResult into a readable Markdown report."""

from __future__ import annotations

from datetime import datetime

from . import headers as headers_mod


def to_markdown(result) -> str:
    lines = [
        f"# Recon report - {result.domain}",
        "",
        f"_Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} - authorized testing only_",
        "",
    ]

    # --- Subdomains ---
    lines.append("## Subdomains (passive, crt.sh)")
    if result.subdomains:
        sr = result.subdomains
        lines.append(f"- Found **{len(sr.found)}** names, **{len(sr.live)}** resolve to an IP.")
        lines.append("")
        lines.append("| Subdomain | IP |")
        lines.append("|---|---|")
        for sub, ip in sr.found:
            lines.append(f"| {sub} | {ip or '-'} |")
    else:
        lines.append("- _not run or unavailable_")
    lines.append("")

    # --- Headers ---
    lines.append("## Security headers")
    if result.headers:
        h = result.headers
        lines.append(f"- Grade **{h.grade}** - {len(h.present)}/"
                     f"{len(headers_mod.SECURITY_HEADERS)} security headers present "
                     f"(HTTP {h.status}).")
        if h.missing:
            lines.append("- Missing: " +
                         ", ".join(name for _h, name, _why in h.missing))
        if h.leaks:
            lines.append("- Info-leak headers: " +
                         ", ".join(f"`{k}: {v}`" for k, v in h.leaks.items()))
    else:
        lines.append("- _not run or unavailable_")
    lines.append("")

    # --- Ports ---
    lines.append("## Open ports (top ports, TCP connect)")
    if result.ports:
        p = result.ports
        lines.append(f"- {result.domain} ({p.ip}) - **{len(p.open_ports)}** open.")
        if p.open_ports:
            lines.append("")
            lines.append("| Port | Service |")
            lines.append("|---|---|")
            for port, svc in p.open_ports:
                lines.append(f"| {port}/tcp | {svc} |")
    else:
        lines.append("- _not run or unavailable_")
    lines.append("")

    if result.errors:
        lines.append("## Notes / errors")
        for e in result.errors:
            lines.append(f"- {e}")
        lines.append("")

    return "\n".join(lines)
