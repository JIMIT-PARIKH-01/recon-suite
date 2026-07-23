"""
Recon Suite command line.

    python -m recon_suite portscan example.com --ports top
    python -m recon_suite portscan 127.0.0.1 --ports 1-1024 --timeout 0.5
    python -m recon_suite headers  github.com
    python -m recon_suite subs     example.com
    python -m recon_suite recon    example.com --out report.md

Authorized use only: target hosts you own or are permitted to test.
"""

from __future__ import annotations

import argparse
import sys

from . import portscan, headers, subdomains, pipeline, report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon_suite",
        description="Passive+active recon: port scan, header audit, subdomain enum, pipeline.")
    sub = p.add_subparsers(dest="command", required=True)

    ps = sub.add_parser("portscan", help="Async TCP connect port scan.")
    ps.add_argument("host")
    ps.add_argument("--ports", default="top", help="'top', '1-1024', or '22,80,443'.")
    ps.add_argument("--timeout", type=float, default=1.0)
    ps.add_argument("--concurrency", type=int, default=300)

    hd = sub.add_parser("headers", help="Security-header audit of a URL.")
    hd.add_argument("url")
    hd.add_argument("--timeout", type=float, default=10.0)

    sb = sub.add_parser("subs", help="Passive subdomain enumeration (crt.sh).")
    sb.add_argument("domain")
    sb.add_argument("--no-resolve", action="store_true", help="Skip DNS resolution.")

    rc = sub.add_parser("recon", help="Full pipeline -> Markdown report.")
    rc.add_argument("domain")
    rc.add_argument("--ports", default="top")
    rc.add_argument("--timeout", type=float, default=1.0)
    rc.add_argument("--no-subs", action="store_true")
    rc.add_argument("--no-headers", action="store_true")
    rc.add_argument("--no-ports", action="store_true")
    rc.add_argument("--out", help="Write the Markdown report to this file.")
    return p


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "portscan":
            res = portscan.scan(args.host, portscan.parse_ports(args.ports),
                                timeout=args.timeout, concurrency=args.concurrency)
            print(res.as_text())

        elif args.command == "headers":
            print(headers.analyze(args.url, timeout=args.timeout).as_text())

        elif args.command == "subs":
            print(subdomains.enumerate_domain(
                args.domain, resolve_ips=not args.no_resolve).as_text())

        elif args.command == "recon":
            result = pipeline.run(
                args.domain, do_subs=not args.no_subs, do_headers=not args.no_headers,
                do_ports=not args.no_ports, ports=portscan.parse_ports(args.ports),
                timeout=args.timeout)
            md = report.to_markdown(result)
            if args.out:
                with open(args.out, "w", encoding="utf-8") as fh:
                    fh.write(md)
                print(f"Wrote report to {args.out}")
            else:
                print(md)
    except (ValueError, ConnectionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
