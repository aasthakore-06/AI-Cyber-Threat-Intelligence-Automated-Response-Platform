"""
auth.log parser for the login module.

Reads Linux/OpenSSH style auth logs (the /var/log/auth.log format) and turns the
login lines into LoginRecord objects. Only two kinds of line matter to us:

    Failed password for [invalid user] <user> from <ip> port <p> ssh2
    Accepted password|publickey for <user> from <ip> port <p> ssh2

Everything else (cron, sudo, session opened ...) is counted as "skipped".
Both the classic syslog timestamp ("Oct 13 10:00:01") and the ISO one that
rsyslog uses on newer distros ("2026-10-13T10:00:01+00:00") are understood.
"""
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

SYSLOG_TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$")
ISO_TS = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<rest>.*)$")

FAILED = re.compile(r"Failed (?P<method>password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F\.:]+) port (?P<port>\d+)")
ACCEPTED = re.compile(r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F\.:]+) port (?P<port>\d+)")


@dataclass
class LoginRecord:
    timestamp: datetime
    user: str
    ip: str
    status: str            # "failed" or "success"
    method: str = "password"
    line_no: int = 0
    event_id: Optional[str] = None


@dataclass
class ParseStats:
    total_lines: int = 0
    parsed: int = 0
    skipped: int = 0
    bad_lines: List[int] = field(default_factory=list)


def _syslog_time(mon: str, day: str, hms: str, year: int) -> Optional[datetime]:
    if mon not in MONTHS:
        return None
    try:
        h, m, s = (int(x) for x in hms.split(":"))
        ts = datetime(year, MONTHS[mon], int(day), h, m, s, tzinfo=timezone.utc)
    except ValueError:
        return None
    # syslog has no year. If that puts us in the future, it was probably last year's log.
    if ts > datetime.now(timezone.utc) + timedelta(days=1):
        ts = ts.replace(year=year - 1)
    return ts


def parse_auth_log(text: str, year: Optional[int] = None) -> Tuple[List[LoginRecord], ParseStats]:
    year = year or datetime.now(timezone.utc).year
    stats = ParseStats()
    records: List[LoginRecord] = []

    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        stats.total_lines += 1

        ts = None
        rest = ""
        m = SYSLOG_TS.match(line)
        if m:
            ts = _syslog_time(m["mon"], m["day"], m["time"], year)
            rest = m["rest"]
        else:
            m = ISO_TS.match(line)
            if m:
                try:
                    ts = datetime.fromisoformat(m["ts"].replace("Z", "+00:00"))
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                except ValueError:
                    ts = None
                rest = m["rest"]

        if ts is None:
            stats.bad_lines.append(n)
            continue

        f = FAILED.search(rest)
        a = ACCEPTED.search(rest) if not f else None
        hit = f or a
        if not hit:
            stats.skipped += 1
            continue

        records.append(LoginRecord(
            timestamp=ts,
            user=hit["user"],
            ip=hit["ip"],
            status="failed" if f else "success",
            method=hit["method"],
            line_no=n,
        ))
        stats.parsed += 1

    records.sort(key=lambda r: r.timestamp)
    return records, stats
