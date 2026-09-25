#!/usr/bin/env python3
"""ThreatLens - a small, dependency-free log threat analyzer.

Reads SSH auth logs (syslog format) and web access logs (Apache/Nginx
"combined" format), runs a set of detection rules, and prints a ranked report
of suspicious sources. It is read-only: it never touches the firewall.

    python threatlens.py --auth /var/log/auth.log --web /var/log/nginx/access.log
"""
from __future__ import annotations

import argparse
import collections
import dataclasses
import datetime as dt
import gzip
import ipaddress
import json
import re
import sys
from urllib.parse import unquote_plus

__version__ = "0.1.0"

SEVERITIES = ["low", "medium", "high", "critical"]
WEIGHT = {"low": 1, "medium": 3, "high": 7, "critical": 15}


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
@dataclasses.dataclass
class AuthEvent:
    ts: dt.datetime
    ip: str
    user: str
    ok: bool
    raw: str


@dataclasses.dataclass
class WebEvent:
    ts: dt.datetime
    ip: str
    method: str
    path: str
    status: int
    agent: str
    raw: str
    referer: str = ""


@dataclasses.dataclass
class Finding:
    rule: str
    severity: str
    ip: str
    title: str
    count: int
    first_seen: dt.datetime
    last_seen: dt.datetime
    detail: str = ""
    evidence: list = dataclasses.field(default_factory=list)


def _opt(default: int, help_text: str):
    return dataclasses.field(default=default, metadata={"help": help_text})


@dataclasses.dataclass
class Config:
    ssh_threshold: int = _opt(5, "failed SSH logins from one IP that count as brute force")
    ssh_window: int = _opt(300, "window in seconds for --ssh-threshold")
    spray_users: int = _opt(5, "distinct usernames tried by one IP that count as spraying")
    scan_404: int = _opt(15, "404 responses to one IP that count as content discovery")
    scan_window: int = _opt(60, "window in seconds for --scan-404")
    probe_paths: int = _opt(3, "distinct sensitive paths requested by one IP")
    rate_limit: int = _opt(300, "requests per minute from one IP considered abnormal")
    web_auth_fails: int = _opt(10, "401/403 responses to one path within 5 minutes")


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+"
    r"\S+\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
FAILED_RE = re.compile(r"^Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+")
ACCEPT_RE = re.compile(r"^Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port \d+")

ACCESS_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>[^"]*?)(?: HTTP/[\d.]+)?" '
    r"(?P<status>\d{3}) \S+"
    r'(?: "(?P<ref>[^"]*)" "(?P<agent>[^"]*)")?'
)


def parse_auth_line(line: str, year: int):
    """Return an AuthEvent for sshd 'Failed ...' / 'Accepted ...' lines, else None.

    'Invalid user ...' lines are ignored on purpose: sshd logs them alongside
    the matching 'Failed password' line, so counting both would double-count.
    """
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    msg = m["msg"]
    for rx, ok in ((FAILED_RE, False), (ACCEPT_RE, True)):
        hit = rx.match(msg)
        if hit:
            try:
                ts = dt.datetime.strptime(
                    f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S"
                )
            except ValueError:
                return None
            return AuthEvent(ts, hit["ip"], hit["user"], ok, line.rstrip("\n"))
    return None


def parse_web_line(line: str):
    """Return a WebEvent for an Apache/Nginx combined-format line, else None."""
    m = ACCESS_RE.match(line)
    if not m:
        return None
    try:
        ts = dt.datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    ts = ts.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return WebEvent(ts, m["ip"], m["method"], m["path"], int(m["status"]),
                    m["agent"] or "", line.rstrip("\n"), m["ref"] or "")


def open_text(path: str):
    if path == "-":
        return sys.stdin
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def load(paths, parse):
    events, unparsed = [], 0
    for path in paths:
        with open_text(path) as fh:
            for line in fh:
                if not line.strip():
                    continue
                ev = parse(line)
                if ev is None:
                    unparsed += 1
                else:
                    events.append(ev)
    return events, unparsed


def make_allowlist(spec: str):
    nets = []
    for part in (s.strip() for s in spec.split(",")):
        if part:
            nets.append(ipaddress.ip_network(part, strict=False))
    return nets


def is_allowed(ip: str, nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


# --------------------------------------------------------------------------
# Detection helpers
# --------------------------------------------------------------------------
def densest_window(times, window_s):
    """For a sorted list of datetimes, find the window of `window_s` seconds
    holding the most events. Returns (count, start_index, end_index)."""
    best = (0, 0, 0)
    j = 0
    for i in range(len(times)):
        while (times[i] - times[j]).total_seconds() > window_s:
            j += 1
        if i - j + 1 > best[0]:
            best = (i - j + 1, j, i)
    return best


def decoded(path: str) -> str:
    """URL-decode twice so double-encoded payloads (%252e%252e) are caught."""
    return unquote_plus(unquote_plus(path))


def bare(path: str) -> str:
    return path.split("?", 1)[0]


SENSITIVE_RE = re.compile(
    r"(?:^|/)(?:\.env|\.git|\.svn|\.htaccess|\.htpasswd|\.aws|\.ds_store|wp-login\.php|"
    r"wp-admin|wp-config|xmlrpc\.php|phpmyadmin|pma|adminer|config\.php|web\.config|"
    r"phpinfo\.php|shell\.php|backup\.(?:zip|sql|tar)|id_rsa|etc/passwd|cgi-bin|"
    r"actuator|server-status)(?![A-Za-z0-9])",
    re.I,
)

SIGNATURES = [
    ("SQL injection",
     re.compile(r"union\s+(?:all\s+)?select|or\s+1\s*=\s*1|'\s*or\s*'|sleep\s*\(\s*\d|"
                r"benchmark\s*\(|information_schema|;\s*drop\s+table|select\s+[\w*,\s]+\s+from\s+\w+", re.I),
     "high"),
    ("Cross-site scripting",
     re.compile(r"<script|javascript:|onerror\s*=|onload\s*=|<img[^>]+src", re.I), "medium"),
    ("Path traversal",
     re.compile(r"\.\./|\.\.\\|/etc/(?:passwd|shadow)|boot\.ini|win\.ini", re.I), "high"),
    ("Command injection",
     re.compile(r"(?:;|\||`|\$\()\s*(?:cat|ls|id|whoami|wget|curl|nc|bash|sh|powershell)\b", re.I),
     "high"),
    ("Log4Shell JNDI lookup", re.compile(r"\$\{jndi:", re.I), "critical"),
    ("Shellshock", re.compile(r"\(\)\s*\{\s*:\s*;\s*\}\s*;"), "high"),
]

# Exploits that are usually delivered in headers, not just the URL.
HEADER_BORNE = {"Log4Shell JNDI lookup", "Shellshock"}

SCANNER_UA_RE = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|nuclei|hydra|"
    r"acunetix|nessus|openvas|havij|wfuzz|ffuf|feroxbuster)", re.I)


def _ok(e: WebEvent) -> bool:
    return 200 <= e.status < 300


# --------------------------------------------------------------------------
# Detectors - auth logs
# --------------------------------------------------------------------------
def detect_ssh_bruteforce(auth, cfg):
    fails, wins = collections.defaultdict(list), collections.defaultdict(list)
    for e in sorted(auth, key=lambda e: e.ts):
        (wins if e.ok else fails)[e.ip].append(e)
    for ip, evs in fails.items():
        peak, a, b = densest_window([e.ts for e in evs], cfg.ssh_window)
        if peak < cfg.ssh_threshold:
            continue
        burst = evs[a:b + 1]
        later_ok = [w for w in wins.get(ip, []) if w.ts >= burst[0].ts]
        if later_ok:
            w = later_ok[0]
            sev = "critical"
            title = "SSH brute force followed by a successful login (possible compromise)"
            detail = (f"{len(evs)} failures (peak {peak} in {cfg.ssh_window}s), then an accepted "
                      f"login as '{w.user}' at {w.ts:%Y-%m-%d %H:%M:%S}")
            evidence = [e.raw for e in burst[:2]] + [w.raw]
        else:
            sev = "high" if peak >= cfg.ssh_threshold * 4 else "medium"
            title = "SSH brute force"
            detail = f"{len(evs)} failed logins (peak {peak} in {cfg.ssh_window}s)"
            evidence = [e.raw for e in burst[:3]]
        yield Finding("ssh-bruteforce", sev, ip, title, len(evs),
                      evs[0].ts, evs[-1].ts, detail, evidence)


def detect_ssh_spray(auth, cfg):
    users, times = collections.defaultdict(set), collections.defaultdict(list)
    for e in auth:
        if not e.ok:
            users[e.ip].add(e.user)
            times[e.ip].append(e.ts)
    for ip, names in users.items():
        if len(names) < cfg.spray_users:
            continue
        sev = "high" if len(names) >= cfg.spray_users * 3 else "medium"
        sample = ", ".join(sorted(names)[:8])
        yield Finding("ssh-username-spray", sev, ip, "Many usernames tried from one address",
                      len(names), min(times[ip]), max(times[ip]),
                      f"{len(names)} distinct usernames (e.g. {sample})")


# --------------------------------------------------------------------------
# Detectors - web access logs
# --------------------------------------------------------------------------
def detect_signatures(web, cfg):
    groups = collections.defaultdict(list)
    for e in web:
        target = decoded(e.path)
        header_target = f"{target} {e.agent} {e.referer}"
        for name, rx, sev in SIGNATURES:
            if rx.search(header_target if name in HEADER_BORNE else target):
                groups[(e.ip, name, sev)].append(e)
    for (ip, name, sev), evs in groups.items():
        hits = sum(_ok(e) for e in evs)
        detail = f"{len(evs)} request(s) matched"
        if hits:
            detail += f"; {hits} returned 2xx (a 2xx does not prove success - review manually)"
        yield Finding("sig-" + name.lower().replace(" ", "-"), sev, ip,
                      f"{name} pattern in request", len(evs),
                      min(e.ts for e in evs), max(e.ts for e in evs), detail,
                      [e.raw for e in evs[:3]])


def detect_probing(web, cfg):
    hits = collections.defaultdict(list)
    for e in web:
        if SENSITIVE_RE.search(decoded(bare(e.path))):
            hits[e.ip].append(e)
    for ip, evs in hits.items():
        paths = {bare(e.path) for e in evs}
        if len(paths) < cfg.probe_paths:
            continue
        served = [e for e in evs if _ok(e)]
        detail = (f"{len(paths)} distinct sensitive paths probed "
                  f"(e.g. {', '.join(sorted(paths)[:5])})")
        if served:
            detail += f"; {len(served)} returned 2xx - check those files were meant to be public"
        yield Finding("sensitive-path-probe", "high" if served else "medium", ip,
                      "Probing for sensitive files and admin panels", len(evs),
                      min(e.ts for e in evs), max(e.ts for e in evs), detail,
                      [e.raw for e in (served or evs)[:3]])


def detect_404_scan(web, cfg):
    by_ip = collections.defaultdict(list)
    for e in sorted(web, key=lambda e: e.ts):
        if e.status == 404:
            by_ip[e.ip].append(e)
    for ip, evs in by_ip.items():
        peak, a, b = densest_window([e.ts for e in evs], cfg.scan_window)
        if peak < cfg.scan_404:
            continue
        sev = "high" if peak >= cfg.scan_404 * 4 else "medium"
        yield Finding("web-404-scan", sev, ip, "Content discovery / directory scanning",
                      len(evs), evs[0].ts, evs[-1].ts,
                      f"{len(evs)} not-found responses (peak {peak} in {cfg.scan_window}s)",
                      [e.raw for e in evs[a:b + 1][:3]])


def detect_scanner_agents(web, cfg):
    groups = collections.defaultdict(list)
    for e in web:
        m = SCANNER_UA_RE.search(e.agent)
        if m:
            groups[(e.ip, m.group(1).lower())].append(e)
    for (ip, tool), evs in groups.items():
        yield Finding("scanner-user-agent", "medium", ip, f"Known scanning tool ({tool})",
                      len(evs), min(e.ts for e in evs), max(e.ts for e in evs),
                      f"user-agent identifies as {tool}", [evs[0].raw])


def detect_rate(web, cfg):
    by_ip = collections.defaultdict(list)
    for e in web:
        by_ip[e.ip].append(e)
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e.ts)
        peak, a, _ = densest_window([e.ts for e in evs], 60)
        if peak >= cfg.rate_limit:
            yield Finding("web-rate", "medium", ip, "Unusually high request rate", len(evs),
                          evs[0].ts, evs[-1].ts, f"peak of {peak} requests in 60s", [evs[a].raw])


def detect_web_auth_failures(web, cfg):
    groups = collections.defaultdict(list)
    for e in sorted(web, key=lambda e: e.ts):
        if e.status in (401, 403):
            groups[(e.ip, bare(e.path))].append(e)
    for (ip, path), evs in groups.items():
        peak, a, b = densest_window([e.ts for e in evs], 300)
        if peak >= cfg.web_auth_fails:
            yield Finding("web-auth-failures", "high", ip,
                          "Repeated 401/403 responses (possible credential guessing)",
                          len(evs), evs[0].ts, evs[-1].ts,
                          f"{len(evs)} denied requests to {path} (peak {peak} in 300s)",
                          [e.raw for e in evs[a:b + 1][:3]])


AUTH_DETECTORS = [detect_ssh_bruteforce, detect_ssh_spray]
WEB_DETECTORS = [detect_signatures, detect_probing, detect_404_scan,
                 detect_scanner_agents, detect_rate, detect_web_auth_failures]


def analyze(auth, web, cfg):
    findings = []
    for det in AUTH_DETECTORS:
        findings.extend(det(auth, cfg))
    for det in WEB_DETECTORS:
        findings.extend(det(web, cfg))
    findings.sort(key=lambda f: (-SEVERITIES.index(f.severity), -f.count, f.ip))
    return findings


def rank_sources(findings):
    per_ip = collections.defaultdict(list)
    for f in findings:
        per_ip[f.ip].append(f)
    rows = [
        {
            "ip": ip,
            "score": sum(WEIGHT[f.severity] for f in fs),
            "worst": max((f.severity for f in fs), key=SEVERITIES.index),
            "findings": len(fs),
            "rules": sorted({f.rule for f in fs}),
        }
        for ip, fs in per_ip.items()
    ]
    rows.sort(key=lambda r: (-r["score"], r["ip"]))
    return rows


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def clean(text: str, limit: int = 200) -> str:
    """Make attacker-controlled log text safe to print (no terminal escapes)."""
    text = "".join(ch if ch.isprintable() else "?" for ch in text)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def fmt_ts(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%d %H:%M:%S")


def render_text(findings, sources, meta) -> str:
    counts = collections.Counter(f.severity for f in findings)
    out = [f"ThreatLens {__version__} - analysis report", "=" * 64,
           f"Analysed: {meta['auth_events']} auth events, {meta['web_events']} web events"
           f" ({meta['web_unparsed']} unparsed web lines ignored)", ""]
    out.append("SUMMARY")
    out.append(f"  findings: {len(findings)}   " + "  ".join(
        f"{s}: {counts.get(s, 0)}" for s in reversed(SEVERITIES)))
    out.append(f"  suspicious sources: {len(sources)}")
    if not findings:
        out += ["", "No findings at or above the selected severity."]
        return "\n".join(out)

    out += ["", "TOP SOURCES", f"  {'#':>2}  {'source':<40} {'score':>5}  {'worst':<9} findings"]
    for i, r in enumerate(sources[:10], 1):
        out.append(f"  {i:>2}  {r['ip']:<40} {r['score']:>5}  {r['worst']:<9} {r['findings']}")

    out += ["", "FINDINGS"]
    for f in findings:
        out.append(f"\n[{f.severity.upper()}] {f.title} - {clean(f.ip, 60)}")
        out.append(f"  when:    {fmt_ts(f.first_seen)} -> {fmt_ts(f.last_seen)}")
        out.append(f"  events:  {f.count}   rule: {f.rule}")
        out.append(f"  detail:  {clean(f.detail)}")
        for line in f.evidence[:3]:
            out.append(f"    | {clean(line)}")
    return "\n".join(out)


def render_json(findings, sources, meta) -> str:
    def enc(o):
        if isinstance(o, dt.datetime):
            return o.isoformat(sep=" ")
        raise TypeError(f"not serialisable: {type(o)}")

    payload = {"tool": "threatlens", "version": __version__, "meta": meta,
               "sources": sources, "findings": [dataclasses.asdict(f) for f in findings]}
    return json.dumps(payload, indent=2, default=enc)


def write_blocklist(path, findings, min_severity):
    floor = SEVERITIES.index(min_severity)
    ips = set()
    for f in findings:
        if SEVERITIES.index(f.severity) >= floor:
            try:
                ips.add(ipaddress.ip_address(f.ip))
            except ValueError:
                pass
    ordered = sorted(ips, key=lambda a: (a.version, int(a)))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f"# ThreatLens {__version__} blocklist (>= {min_severity}). "
                 "Review before applying - this file changes nothing by itself.\n")
        for ip in ordered:
            fh.write(f"{ip}\n")
    return len(ordered)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="threatlens",
        description="Analyse SSH auth logs and web access logs for suspicious activity.",
        epilog="Exit status: 0 = nothing at/above --fail-on, 1 = findings, 2 = usage or I/O error.",
    )
    p.add_argument("-a", "--auth", action="append", default=[], metavar="FILE",
                   help="SSH auth log in syslog format (repeatable; '-' = stdin; .gz supported)")
    p.add_argument("-w", "--web", action="append", default=[], metavar="FILE",
                   help="web access log in Apache/Nginx combined format (repeatable)")
    p.add_argument("--year", type=int, default=dt.date.today().year,
                   help="year to assume for syslog timestamps (default: current year)")
    p.add_argument("--allow", default="", metavar="CIDRS",
                   help="comma-separated IPs/CIDRs to ignore, e.g. 10.0.0.0/8,192.168.1.5")
    p.add_argument("--min-severity", choices=SEVERITIES, default="low",
                   help="hide findings below this level (default: low)")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE")
    p.add_argument("--blocklist", metavar="FILE",
                   help="also write offending IPs to FILE, one per line (nothing is applied)")
    p.add_argument("--block-min", choices=SEVERITIES, default="high",
                   help="minimum severity for --blocklist (default: high)")
    p.add_argument("--fail-on", choices=SEVERITIES + ["never"], default="high",
                   help="exit with status 1 at/above this severity (default: high)")
    p.add_argument("--version", action="version", version=f"threatlens {__version__}")
    g = p.add_argument_group("detection thresholds")
    for f in dataclasses.fields(Config):
        g.add_argument("--" + f.name.replace("_", "-"), type=int, default=f.default,
                       metavar="N", help=f.metadata["help"] + " (default: %(default)s)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not args.auth and not args.web:
        print("threatlens: give at least one --auth or --web log (see --help)", file=sys.stderr)
        return 2
    try:
        allow = make_allowlist(args.allow)
    except ValueError as exc:
        print(f"threatlens: bad --allow value: {exc}", file=sys.stderr)
        return 2
    cfg = Config(**{f.name: getattr(args, f.name) for f in dataclasses.fields(Config)})

    try:
        auth, _ = load(args.auth, lambda line: parse_auth_line(line, args.year))
        web, web_unparsed = load(args.web, parse_web_line)
    except OSError as exc:
        print(f"threatlens: {exc}", file=sys.stderr)
        return 2

    if allow:
        auth = [e for e in auth if not is_allowed(e.ip, allow)]
        web = [e for e in web if not is_allowed(e.ip, allow)]

    floor = SEVERITIES.index(args.min_severity)
    findings = [f for f in analyze(auth, web, cfg) if SEVERITIES.index(f.severity) >= floor]
    sources = rank_sources(findings)
    meta = {"auth_events": len(auth), "web_events": len(web), "web_unparsed": web_unparsed}

    render = render_json if args.format == "json" else render_text
    report = render(findings, sources, meta)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
    else:
        print(report)

    if args.blocklist:
        n = write_blocklist(args.blocklist, findings, args.block_min)
        print(f"threatlens: wrote {n} address(es) to {args.blocklist}", file=sys.stderr)

    if args.fail_on == "never":
        return 0
    limit = SEVERITIES.index(args.fail_on)
    return 1 if any(SEVERITIES.index(f.severity) >= limit for f in findings) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:  # e.g. `threatlens ... | head`
        sys.stderr.close()
        sys.exit(0)
