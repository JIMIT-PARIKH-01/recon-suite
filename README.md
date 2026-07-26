# Recon Suite

[![CI](https://github.com/JIMIT-PARIKH-01/recon-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/JIMIT-PARIKH-01/recon-suite/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.8%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

A small, **dependency-free** reconnaissance toolkit for authorized security testing —
four tools in one, with a **GUI and a CLI**:

1. **Port scanner** — async TCP connect scan (top ports or custom ranges)
2. **Security-header analyzer** — grades a site's HTTP security headers (defensive)
3. **Subdomain enumerator** — passive discovery via Certificate Transparency (crt.sh)
4. **Recon pipeline** — chains all three into one Markdown report

Built on the Python standard library only (`asyncio`, `urllib`, `socket`, `ssl`).

---

## ⚠️ Authorized use only

Run these tools **only** against systems you own or have **explicit written permission**
to test. Port scanning and enumeration of systems you don't control may be illegal.
This project is for CTFs, your own labs/VMs, and sanctioned engagements.

---

## Install & run

Just **Python 3.8+** — nothing to install.

```powershell
# GUI (tabs: Port Scan / Headers / Subdomains / Full Recon)
python recon_suite/gui.py        # or double-click run.bat

# CLI
python -m recon_suite portscan 127.0.0.1 --ports 1-1024 --timeout 0.5
python -m recon_suite portscan example.com --ports top
python -m recon_suite headers  github.com
python -m recon_suite subs     example.com
python -m recon_suite recon    example.com --out report.md
```

### Command reference

| Command | What it does | Key flags |
|---|---|---|
| `portscan HOST` | async TCP connect scan | `--ports top\|1-1024\|22,80` · `--timeout` · `--concurrency` |
| `headers URL`   | grade security headers | `--timeout` |
| `subs DOMAIN`   | passive subdomain enum  | `--no-resolve` |
| `recon DOMAIN`  | full pipeline → report  | `--out FILE` · `--no-subs/--no-headers/--no-ports` |

---

## How it works

- **Port scan:** `asyncio` TCP connects with a concurrency cap; reports open ports + service
  names. No stealth/evasion — a plain, honest connect scan.
- **Headers:** a single GET, then checks for HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy; grades A–F and flags info-leak headers (`Server`, …).
- **Subdomains:** queries crt.sh Certificate Transparency logs (passive — no packets to the
  target), then optionally resolves each name. (crt.sh can be slow; the tool degrades gracefully.)
- **Pipeline:** runs the stages, tolerates per-stage failures, and renders a clean Markdown report.

## Project layout

```
recon-suite/
└── recon_suite/
    ├── portscan.py     # async TCP port scanner
    ├── headers.py      # security-header analyzer
    ├── subdomains.py   # passive subdomain enumeration (crt.sh)
    ├── pipeline.py     # orchestrates the three stages
    ├── report.py       # Markdown report
    ├── cli.py  gui.py  run.bat  requirements.txt
```

## ⬇️ Download & Install

**This is a public tool — download and use it on your device for free.**

```bash
# 1) Clone it
git clone https://github.com/JIMIT-PARIKH-01/recon-suite.git
cd recon-suite

# 2) ...or download a ZIP (no git needed)
#    https://github.com/JIMIT-PARIKH-01/recon-suite/archive/refs/heads/main.zip

# 3) ...or install the command straight from GitHub
pip install git+https://github.com/JIMIT-PARIKH-01/recon-suite.git
```

Then run it as shown in the usage section above (CLI `python -m ...`, or launch
the GUI via `run.bat`).

<details>
<summary><b>🔒 Requesting access to a private tool</b></summary>

Public tools install with the commands above. If a tool is **private**, access
is granted by the owner through GitHub — a static link cannot unlock private
code, only GitHub can:

1. **Request access** — open an [access request](https://github.com/JIMIT-PARIKH-01/JIMIT-PARIKH-01/issues/new?template=tool-access-request.md&title=Access+request:+recon-suite) or message on
   [LinkedIn](https://www.linkedin.com/in/jimit-devangkumar-parikh/).
2. The owner reviews it and, if approved, **adds you as a collaborator** on the
   private repository.
3. GitHub then lets you clone / download it with your own account. Access is
   revoked the moment the owner removes you as a collaborator.

</details>

## License
MIT — see [LICENSE](./LICENSE).
