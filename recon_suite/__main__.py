"""Entry point:  python -m recon_suite <portscan|headers|subs|recon> ..."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
