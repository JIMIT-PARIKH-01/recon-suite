"""
Tkinter GUI for the Recon Suite (standard library only).

Tabs: Port Scan · Headers · Subdomains · Full Recon. Network operations run on
background threads; only the main thread touches widgets (via a queue).

Authorized use only. Launch with run.bat, or:  python recon_suite/gui.py
"""

from __future__ import annotations

import queue
import threading

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

try:
    from recon_suite import portscan, headers, subdomains, pipeline, report
except ImportError:  # pragma: no cover
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from recon_suite import portscan, headers, subdomains, pipeline, report


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Recon Suite")
        self.geometry("860x680")
        self.minsize(740, 560)
        self.ui_queue: "queue.Queue" = queue.Queue()
        self.after(60, self._drain)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        for tab, title in ((PortScanTab, "  Port Scan  "), (HeadersTab, "  Headers  "),
                           (SubsTab, "  Subdomains  "), (ReconTab, "  Full Recon  ")):
            nb.add(tab(nb, self), text=title)

        self.status = ttk.Label(self, relief="sunken", anchor="w",
                                text="Ready — authorized testing only.")
        self.status.pack(fill="x", side="bottom")

    def set_status(self, msg: str) -> None:
        self.status.configure(text=msg)

    def _drain(self) -> None:
        try:
            while True:
                cb = self.ui_queue.get_nowait()
                try:
                    cb()
                except Exception:  # noqa: BLE001 - keep the pump alive
                    self.set_status("A UI update failed.")
        except queue.Empty:
            pass
        self.after(60, self._drain)


class _Tab(ttk.Frame):
    def __init__(self, master, app: App) -> None:
        super().__init__(master, padding=10)
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
        self.btn: ttk.Button | None = None

    def _output(self, row: int) -> scrolledtext.ScrolledText:
        box = scrolledtext.ScrolledText(self, wrap="word", font=("Consolas", 10),
                                        state="disabled")
        box.grid(row=row, column=0, sticky="nsew", pady=(8, 0))
        return box

    def _show(self, widget, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _run_async(self, work, on_done, busy: str) -> None:
        if self.btn:
            self.btn.configure(state="disabled")
        self.app.set_status(busy)

        def runner() -> None:
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001
                result = f"Error: {exc}"

            def finish() -> None:
                on_done(result)
                if self.btn:
                    self.btn.configure(state="normal")
                self.app.set_status("Done.")
            self.app.ui_queue.put(finish)

        threading.Thread(target=runner, daemon=True).start()


class PortScanTab(_Tab):
    def __init__(self, master, app):
        super().__init__(master, app)
        ttk.Label(self, text="Host / IP").grid(row=0, column=0, sticky="w")
        self.host = tk.StringVar()
        ttk.Entry(self, textvariable=self.host).grid(row=1, column=0, sticky="ew")
        ctl = ttk.Frame(self); ctl.grid(row=2, column=0, sticky="ew", pady=6)
        ttk.Label(ctl, text="Ports").pack(side="left")
        self.ports = tk.StringVar(value="top")
        ttk.Entry(ctl, textvariable=self.ports, width=16).pack(side="left", padx=6)
        ttk.Label(ctl, text="Timeout").pack(side="left")
        self.timeout = tk.StringVar(value="1.0")
        ttk.Entry(ctl, textvariable=self.timeout, width=6).pack(side="left", padx=6)
        self.btn = ttk.Button(ctl, text="Scan", command=self.run); self.btn.pack(side="right")
        self.out = self._output(3)

    def run(self):
        host = self.host.get().strip()
        if not host:
            messagebox.showinfo("No host", "Enter a host or IP."); return
        ports = portscan.parse_ports(self.ports.get())
        try:
            to = float(self.timeout.get())
        except ValueError:
            to = 1.0
        self._run_async(lambda: portscan.scan(host, ports, timeout=to).as_text(),
                        lambda r: self._show(self.out, r), f"Scanning {host}…")


class HeadersTab(_Tab):
    def __init__(self, master, app):
        super().__init__(master, app)
        ttk.Label(self, text="URL / domain").grid(row=0, column=0, sticky="w")
        self.url = tk.StringVar()
        ttk.Entry(self, textvariable=self.url).grid(row=1, column=0, sticky="ew")
        ctl = ttk.Frame(self); ctl.grid(row=2, column=0, sticky="ew", pady=6)
        self.btn = ttk.Button(ctl, text="Analyze", command=self.run); self.btn.pack(side="right")
        self.out = self._output(3)

    def run(self):
        url = self.url.get().strip()
        if not url:
            messagebox.showinfo("No URL", "Enter a URL or domain."); return
        self._run_async(lambda: headers.analyze(url).as_text(),
                        lambda r: self._show(self.out, r), f"Fetching {url}…")


class SubsTab(_Tab):
    def __init__(self, master, app):
        super().__init__(master, app)
        ttk.Label(self, text="Domain").grid(row=0, column=0, sticky="w")
        self.domain = tk.StringVar()
        ttk.Entry(self, textvariable=self.domain).grid(row=1, column=0, sticky="ew")
        ctl = ttk.Frame(self); ctl.grid(row=2, column=0, sticky="ew", pady=6)
        self.resolve = tk.BooleanVar(value=True)
        ttk.Checkbutton(ctl, text="Resolve IPs", variable=self.resolve).pack(side="left")
        self.btn = ttk.Button(ctl, text="Enumerate", command=self.run); self.btn.pack(side="right")
        self.out = self._output(3)

    def run(self):
        dom = self.domain.get().strip()
        if not dom:
            messagebox.showinfo("No domain", "Enter a domain."); return
        self._run_async(
            lambda: subdomains.enumerate_domain(dom, resolve_ips=self.resolve.get()).as_text(),
            lambda r: self._show(self.out, r), f"Querying crt.sh for {dom}… (can be slow)")


class ReconTab(_Tab):
    def __init__(self, master, app):
        super().__init__(master, app)
        ttk.Label(self, text="Domain").grid(row=0, column=0, sticky="w")
        self.domain = tk.StringVar()
        ttk.Entry(self, textvariable=self.domain).grid(row=1, column=0, sticky="ew")
        ctl = ttk.Frame(self); ctl.grid(row=2, column=0, sticky="ew", pady=6)
        self.subs = tk.BooleanVar(value=True)
        self.hdrs = tk.BooleanVar(value=True)
        self.pts = tk.BooleanVar(value=True)
        ttk.Checkbutton(ctl, text="Subdomains", variable=self.subs).pack(side="left")
        ttk.Checkbutton(ctl, text="Headers", variable=self.hdrs).pack(side="left", padx=6)
        ttk.Checkbutton(ctl, text="Ports", variable=self.pts).pack(side="left")
        ttk.Button(ctl, text="Save report…", command=self.save).pack(side="right", padx=4)
        self.btn = ttk.Button(ctl, text="Run recon", command=self.run); self.btn.pack(side="right")
        self.out = self._output(3)
        self._md = ""

    def run(self):
        dom = self.domain.get().strip()
        if not dom:
            messagebox.showinfo("No domain", "Enter a domain."); return

        def work():
            res = pipeline.run(dom, do_subs=self.subs.get(), do_headers=self.hdrs.get(),
                               do_ports=self.pts.get())
            return report.to_markdown(res)

        def done(md):
            self._md = md if not md.startswith("Error:") else ""
            self._show(self.out, md)

        self._run_async(work, done, f"Running recon on {dom}…")

    def save(self):
        if not self._md:
            messagebox.showinfo("Nothing to save", "Run recon first."); return
        path = filedialog.asksaveasfilename(defaultextension=".md",
                                            filetypes=[("Markdown", "*.md")])
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self._md)
            self.app.set_status(f"Saved report to {path}")


def main() -> int:
    App().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
