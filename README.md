# ThreatLens
A security dashboard for keeping an eye on what's happening across a network at a glance; pulling scattered activity into one view so unusual behaviour is easier to spot and act on quickly.

---
A small, dependency-free (Python 3.8+) log analyzer that turns raw SSH auth logs and
web access logs into a ranked list of suspicious sources. It is **read-only** - it reports
and can export a blocklist file, but never changes firewall rules or system state.

## Quick start

```bash
# try it on the bundled sample logs
python threatlens.py -a sample/auth.log -w sample/access.log --year 2026 --allow 10.0.0.0/8

# real logs (Debian/Ubuntu paths shown; rotated .gz files work too)
python threatlens.py -a /var/log/auth.log -w /var/log/nginx/access.log

# JSON for other tools, plus a blocklist of high/critical sources
python threatlens.py -a auth.log -w access.log --format json -o report.json --blocklist block.txt
```

## What it detects

| Rule | Source | Severity |
|------|--------|----------|
| SSH brute force (>= 5 failures / 5 min from one IP) | auth | medium / high |
| SSH brute force **followed by a successful login** | auth | critical |
| Username spraying (>= 5 distinct usernames from one IP) | auth | medium / high |
| Injection patterns in the URL: SQLi, XSS, path traversal, command injection | web | medium / high |
| Log4Shell (`${jndi:`) and Shellshock, also checked in User-Agent / Referer | web | critical / high |
| Probing for `.env`, `.git`, `wp-login.php`, phpMyAdmin, backups, ... | web | medium (high if served) |
| Content discovery (>= 15 x 404 / minute from one IP) | web | medium / high |
| Known scanner User-Agents (nikto, sqlmap, nmap, ...) | web | medium |
| Abnormal request rate (>= 300 / minute from one IP) | web | medium |
| Repeated 401/403 on one path (possible credential guessing) | web | high |

Every threshold is a flag (`--help` lists them): `--ssh-threshold`, `--ssh-window`,
`--spray-users`, `--scan-404`, `--scan-window`, `--probe-paths`, `--rate-limit`, `--web-auth-fails`.

Findings are grouped per source IP and scored (low 1, medium 3, high 7, critical 15) to
produce the **Top sources** table.

## Useful options

- `--allow 10.0.0.0/8,192.168.1.5` - ignore trusted addresses (office, monitoring, your own IP)
- `--min-severity high` - hide lower-severity noise
- `--fail-on high` - exit status 1 when something at/above that level is found (cron / CI friendly; `never` to disable)
- `--year 2025` - syslog timestamps carry no year; set this when analysing an old log
- `-` as a filename reads from stdin

Exit status: `0` clean, `1` findings at/above `--fail-on`, `2` usage or I/O error.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Limitations (read before trusting a report)

- **Signature-based, so expect false positives and misses.** Treat findings as leads to review.
  A 2xx response to an attack pattern does *not* prove the attack worked.
- Only the URL, User-Agent and Referer are inspected - not POST bodies or other headers.
- Only sshd `Failed ...` and `Accepted ...` lines are used; `Invalid user` lines are ignored
  on purpose because sshd logs them next to the matching `Failed` line (double counting).
- "Brute force then success" can also be a real user mistyping a password many times - check the evidence.
- Timestamps: web logs are normalised to UTC; syslog times are shown as written (usually local time).
- Attackers behind many IPs (distributed attacks) stay under per-IP thresholds.
- Log text is attacker-controlled, so ThreatLens strips control characters before printing it.
- The sample logs use reserved documentation addresses (RFC 5737) and are synthetic.
