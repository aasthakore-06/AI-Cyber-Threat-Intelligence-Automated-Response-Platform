"""
Parsers for the other uploaded file types. Each one returns a list of SecurityEvent
(auth.log has its own parser in detectors/login/parser.py).

  web_log      Apache / Nginx "combined" access.log
  network_log  CSV:  timestamp,src_ip,dst_ip,dst_port,protocol   (header optional)
  url_list     one URL per line, '#' lines ignored
"""
import csv
import io
import re
import uuid
from datetime import datetime, timezone
from typing import List, Tuple
from urllib.parse import urlsplit

from app.schemas.event import SecurityEvent

COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<uri>\S+)(?: HTTP/[\d.]+)?" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)


def _eid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def parse_web_log(text: str) -> Tuple[List[SecurityEvent], int, int]:
    events, total = [], 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        total += 1
        m = COMBINED.match(line)
        if not m:
            continue
        try:
            ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            continue
        uri = m["uri"]
        path, _, query = uri.partition("?")
        events.append(SecurityEvent(
            event_id=_eid("web"),
            event_type="http_request",
            timestamp=ts,
            source_ip=m["ip"],
            target=uri,
            source_module="web_log",
            evidence={
                "method": m["method"],
                "path": path,
                "query_string": query,
                "status": int(m["status"]),
                "user_agent": m["ua"] or "",
            },
        ))
    return events, total, len(events)


def parse_network_log(text: str) -> Tuple[List[SecurityEvent], int, int]:
    events, total = [], 0
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row or row[0].strip().startswith("#"):
            continue
        total += 1
        if len(row) < 4 or row[0].strip().lower() in ("timestamp", "time"):
            continue
        try:
            ts = datetime.fromisoformat(row[0].strip().replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            port = int(row[3])
        except ValueError:
            continue
        events.append(SecurityEvent(
            event_id=_eid("net"),
            event_type="network_connection",
            timestamp=ts,
            source_ip=row[1].strip(),
            target=row[2].strip(),
            source_module="network_log",
            evidence={
                "destination_ip": row[2].strip(),
                "destination_port": port,
                "protocol": (row[4].strip() if len(row) > 4 else "TCP").upper(),
            },
        ))
    return events, total, len(events)


def parse_url_list(text: str) -> Tuple[List[SecurityEvent], int, int]:
    events, total = [], 0
    now = datetime.now(timezone.utc)
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        total += 1
        if not urlsplit(line if "://" in line else "http://" + line).netloc:
            continue
        events.append(SecurityEvent(
            event_id=_eid("url"),
            event_type="url_submission",
            timestamp=now,
            target=line,
            source_module="url_list",
            evidence={"url": line},
        ))
    return events, total, len(events)
