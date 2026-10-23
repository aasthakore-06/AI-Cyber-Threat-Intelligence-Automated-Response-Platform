from pathlib import Path
from datetime import datetime, timezone, timedelta

from app.schemas.event import SecurityEvent
from app.detectors.phishing.detector import phishing_detector
from app.detectors.login.parser import parse_auth_log, LoginRecord
from app.detectors.login.detector import LoginThreatDetector
from app.detectors.port_scan.detector import PortScanDetector
from app.detectors.web_attack.detector import WebAttackDetector
from app.detectors.honeytoken.detector import HoneytokenDetector

SAMPLES = Path(__file__).resolve().parents[3] / "test_logs"


def test_phishing_benign_and_malicious():
    assert phishing_detector.analyze_url("https://www.google.com/search?q=test")["is_phishing"] is False
    bad = phishing_detector.analyze_url("http://192.168.1.105/login/bank-verify.php")
    assert bad["is_phishing"] is True
    assert phishing_detector.analyze_url("")["valid"] is False


def test_auth_log_parser_both_timestamp_styles():
    text = (
        "Oct 14 10:00:05 web01 sshd[1]: Failed password for invalid user test from 198.51.100.45 port 41000 ssh2\n"
        "2026-10-14T10:00:09+00:00 web01 sshd[2]: Accepted publickey for alice from 10.0.0.11 port 2222 ssh2\n"
        "Oct 14 10:01:00 web01 CRON[9]: session opened\n"
        "garbage line\n"
    )
    recs, stats = parse_auth_log(text, year=2026)
    assert [r.status for r in recs] == ["failed", "success"]
    assert recs[0].user == "test" and recs[0].ip == "198.51.100.45"
    assert stats.parsed == 2 and stats.bad_lines == [4]


def _fails(n, start, ip="1.2.3.4", user="root", gap=5):
    return [LoginRecord(start + timedelta(seconds=i * gap), user, ip, "failed", line_no=i) for i in range(n)]


def test_brute_force_threshold_is_more_than_5_in_2_minutes():
    t0 = datetime(2026, 10, 14, 10, 0, tzinfo=timezone.utc)
    det = LoginThreatDetector()
    assert not [a for a in det.analyze(_fails(5, t0)) if a.evidence.get("rule_matched") == "BRUTE_FORCE_WINDOW"]
    hit = [a for a in det.analyze(_fails(6, t0)) if a.evidence.get("rule_matched") == "BRUTE_FORCE_WINDOW"]
    assert len(hit) == 1 and hit[0].source_ip == "1.2.3.4"
    # same number of failures but spread over 10 minutes -> not a burst
    assert not [a for a in det.analyze(_fails(6, t0, gap=120)) if a.evidence.get("rule_matched") == "BRUTE_FORCE_WINDOW"]


def test_login_sample_file_triggers_all_three_checks():
    recs, _ = parse_auth_log((SAMPLES / "auth.log").read_text(), year=2026)
    rules = {a.evidence["rule_matched"] for a in LoginThreatDetector().analyze(recs)}
    assert {"BRUTE_FORCE_WINDOW", "FAILURES_THEN_SUCCESS", "HIGH_FAILED_SUCCESS_RATIO", "ISOLATION_FOREST_OUTLIER"} <= rules


def test_port_scan_detector():
    det = PortScanDetector(port_threshold=15, window_seconds=60)
    t0 = datetime(2026, 10, 14, 9, 50, tzinfo=timezone.utc)
    alert = None
    for i in range(20):
        ev = SecurityEvent(event_type="network_connection", timestamp=t0 + timedelta(seconds=i), source_ip="9.9.9.9",
                           target="10.0.0.5", evidence={"destination_port": 1000 + i})
        alert = det.process_event(ev) or alert
    assert alert is not None and alert.evidence["distinct_ports_count"] >= 15


def test_web_attack_and_honeytoken():
    web = WebAttackDetector()
    ev = SecurityEvent(event_type="http_request", source_ip="1.1.1.1", target="/p?id=1' OR 1=1--",
                       evidence={"user_agent": "sqlmap"})
    a = web.process_event(ev)
    assert a is not None and a.evidence["attack_type"] == "SQL_INJECTION" and a.evidence["user_agent"] == "sqlmap"
    clean = SecurityEvent(event_type="http_request", source_ip="1.1.1.1", target="/about")
    assert web.process_event(clean) is None

    assert HoneytokenDetector().process_event(SecurityEvent(event_type="http_request", source_ip="2.2.2.2", target="/admin/backup-keys")) is None  # no decoys planted = nothing to trigger
    ht = HoneytokenDetector({"/admin/backup-keys"})
    hit = ht.process_event(SecurityEvent(event_type="http_request", source_ip="2.2.2.2", target="/admin/backup-keys"))
    assert hit is not None and hit.severity.value == "critical"
