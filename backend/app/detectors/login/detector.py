"""
Login Threat Detection (log-upload based)

The admin uploads an auth.log, the parser turns it into LoginRecord objects and
this module runs three checks over the whole file:

  1. brute force      - more than N failed logins from one IP (or against one user)
                        inside a short sliding window (default 5 in 120 s)
  2. failed/success   - users whose failed:successful ratio over the last 7 days is
     ratio              high ("repeated failed authentication"), plus the classic
                        "many failures and then a success" pattern
  3. abnormal login   - Isolation Forest over per-user features (odd hour, odd day,
     (ML)               new IP, failures right before the login)

Each check returns StandardAlert objects, same format as every other module.
"""
import uuid
import math
import statistics
from collections import defaultdict, deque
from datetime import timedelta
from typing import Dict, List, Optional

from app.core.config import settings
from app.detectors.login.parser import LoginRecord
from app.schemas.alert import StandardAlert, AlertCategory, AlertDetector, AlertSeverity

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except Exception:  # scikit-learn missing (e.g. very new python) -> rules still work
    ML_AVAILABLE = False

ANOMALY_THRESHOLD = 0.60   # score_samples based, see _ml_check


def _alert(rec: LoginRecord, **kw) -> StandardAlert:
    return StandardAlert(
        alert_id=f"alt_login_{uuid.uuid4().hex[:8]}",
        event_id=rec.event_id or f"login_line_{rec.line_no}",
        detector=AlertDetector.LOGIN,
        category=AlertCategory.CREDENTIAL_ACCESS,
        target="ssh / auth service",
        **kw,
    )


class LoginThreatDetector:
    def __init__(self, failed_threshold=None, window_seconds=None):
        self.failed_threshold = failed_threshold or settings.LOGIN_FAILED_THRESHOLD
        self.window = timedelta(seconds=window_seconds or settings.LOGIN_WINDOW_SECONDS)

    # ------------------------------------------------------------------
    def analyze(self, records: List[LoginRecord]) -> List[StandardAlert]:
        if not records:
            return []
        records = sorted(records, key=lambda r: r.timestamp)
        alerts: List[StandardAlert] = []
        alerts += self._brute_force(records)
        alerts += self._failure_then_success(records)
        alerts += self._failed_ratio(records)
        alerts += self._ml_check(records)
        alerts.sort(key=lambda a: a.timestamp)
        return alerts

    # ---------------- rule 1: brute force -----------------------------
    def _brute_force(self, records: List[LoginRecord]) -> List[StandardAlert]:
        fails = [r for r in records if r.status == "failed"]
        out = []
        for key_name in ("ip", "user"):
            groups: Dict[str, List[LoginRecord]] = defaultdict(list)
            for r in fails:
                groups[getattr(r, key_name)].append(r)

            for key, items in groups.items():
                win: deque = deque()
                burst: Optional[dict] = None
                for r in items:
                    win.append(r)
                    while win and r.timestamp - win[0].timestamp > self.window:
                        win.popleft()
                    if len(win) > self.failed_threshold:
                        if burst is None:
                            burst = {"start": r, "peak": len(win), "recs": list(win)}
                        else:
                            burst["peak"] = max(burst["peak"], len(win))
                            burst["recs"].append(r)
                    elif burst is not None:
                        out.append(self._brute_alert(key_name, key, burst))
                        burst = None
                if burst is not None:
                    out.append(self._brute_alert(key_name, key, burst))

        # an IP-keyed and a user-keyed alert can describe the same burst; keep the IP one
        # unless the user one covers several different IPs (distributed attack)
        keep, seen = [], set()
        for a in sorted(out, key=lambda a: (a.evidence["key_type"] != "ip", a.timestamp)):
            sig = (a.evidence["key_type"] == "ip", a.source_ip or a.user_id, a.timestamp)
            if a.evidence["key_type"] == "user" and a.evidence["distinct_ips"] <= 1:
                continue
            if sig in seen:
                continue
            seen.add(sig)
            keep.append(a)
        return keep

    def _brute_alert(self, key_type, key, burst) -> StandardAlert:
        recs = burst["recs"]
        start = burst["start"]
        peak = burst["peak"]
        users = sorted({r.user for r in recs})
        ips = sorted({r.ip for r in recs})
        conf = round(min(0.97, 0.55 + 0.025 * peak), 2)
        sev = AlertSeverity.HIGH if peak >= 10 else AlertSeverity.MEDIUM
        who = f"IP {key}" if key_type == "ip" else f"user '{key}'"
        return _alert(
            start,
            severity=sev,
            confidence=conf,
            source_ip=key if key_type == "ip" else (ips[0] if len(ips) == 1 else None),
            user_id=key if key_type == "user" else (users[0] if len(users) == 1 else None),
            timestamp=start.timestamp,
            title=f"Brute force: {peak} failed logins against/from {who} within {int(self.window.total_seconds())}s",
            evidence={
                "rule_matched": "BRUTE_FORCE_WINDOW",
                "key_type": key_type,
                "peak_failed_in_window": peak,
                "threshold": self.failed_threshold,
                "window_seconds": int(self.window.total_seconds()),
                "usernames_tried": users[:15],
                "unique_usernames_tried": len(users),
                "distinct_ips": len(ips),
                "ips": ips[:10],
                "bruteforce_score": conf,
                "first_seen": recs[0].timestamp.isoformat(),
                "last_seen": recs[-1].timestamp.isoformat(),
            },
            recommended_action=(
                f"Rate-limit or block {who}. Check whether any of the tried accounts later logged in successfully."
            ),
        )

    # ---------------- rule 1b: failures then success ------------------
    def _failure_then_success(self, records: List[LoginRecord]) -> List[StandardAlert]:
        out = []
        done = set()
        for i, r in enumerate(records):
            if r.status != "success":
                continue
            prior = [p for p in records[:i]
                     if p.status == "failed" and r.timestamp - p.timestamp <= timedelta(minutes=10)
                     and (p.ip == r.ip or p.user == r.user)]
            if len(prior) >= 3:
                key = (r.ip, r.user)
                if key in done:
                    continue
                done.add(key)
                out.append(_alert(
                    r,
                    severity=AlertSeverity.HIGH,
                    confidence=0.9,
                    source_ip=r.ip,
                    user_id=r.user,
                    timestamp=r.timestamp,
                    title=f"Successful login for '{r.user}' right after {len(prior)} failures (IP {r.ip})",
                    evidence={
                        "rule_matched": "FAILURES_THEN_SUCCESS",
                        "failed_before_success": len(prior),
                        "within_minutes": 10,
                        "failing_ips": sorted({p.ip for p in prior}),
                        "note": "Possible account takeover, verify with the account owner.",
                    },
                    recommended_action=f"Force a password reset for '{r.user}' and review the session opened from {r.ip}.",
                ))
        return out

    # ---------------- rule 2: failed/success ratio over days ----------
    def _failed_ratio(self, records: List[LoginRecord]) -> List[StandardAlert]:
        end = records[-1].timestamp
        start = end - timedelta(days=settings.LOGIN_RATIO_WINDOW_DAYS)
        per_user: Dict[str, List[LoginRecord]] = defaultdict(list)
        for r in records:
            if r.timestamp >= start:
                per_user[r.user].append(r)

        out = []
        for user, recs in per_user.items():
            failed = sum(1 for r in recs if r.status == "failed")
            ok = sum(1 for r in recs if r.status == "success")
            if failed + ok < settings.LOGIN_RATIO_MIN_ATTEMPTS:
                continue
            ratio = failed / max(ok, 1)
            if ratio < settings.LOGIN_RATIO_THRESHOLD:
                continue
            last_fail = [r for r in recs if r.status == "failed"][-1]
            conf = round(min(0.9, 0.5 + 0.05 * ratio), 2)
            out.append(_alert(
                last_fail,
                severity=AlertSeverity.MEDIUM,
                confidence=conf,
                source_ip=None,
                user_id=user,
                timestamp=last_fail.timestamp,
                title=f"Repeated failed authentication for '{user}': {failed} failed vs {ok} successful in {settings.LOGIN_RATIO_WINDOW_DAYS} days",
                evidence={
                    "rule_matched": "HIGH_FAILED_SUCCESS_RATIO",
                    "failed": failed,
                    "successful": ok,
                    "ratio": round(ratio, 2),
                    "ratio_threshold": settings.LOGIN_RATIO_THRESHOLD,
                    "window_days": settings.LOGIN_RATIO_WINDOW_DAYS,
                    "source_ips": sorted({r.ip for r in recs if r.status == "failed"})[:10],
                },
                recommended_action=f"Contact the owner of '{user}' and consider locking the account until verified.",
            ))
        return out

    # ---------------- ML: isolation forest ----------------------------
    @staticmethod
    def _hour(r: LoginRecord) -> float:
        return r.timestamp.hour + r.timestamp.minute / 60.0

    @staticmethod
    def _circ(a: float, b: float) -> float:
        d = abs(a - b) % 24
        return min(d, 24 - d)

    def _features(self, records: List[LoginRecord]):
        """Build one feature row for every successful login."""
        by_user: Dict[str, List[LoginRecord]] = defaultdict(list)
        for r in records:
            if r.status == "success":
                by_user[r.user].append(r)

        rows, owners = [], []
        for user, logins in by_user.items():
            hours = [self._hour(r) for r in logins]
            # typical hour = circular-ish median (good enough for office hours)
            typical = statistics.median(hours) if len(hours) >= 3 else 13.0
            ip_count: Dict[str, int] = defaultdict(int)
            for r in logins:
                ip_count[r.ip] += 1
            for r in logins:
                fails_before = sum(
                    1 for p in records
                    if p.status == "failed" and p.timestamp < r.timestamp
                    and r.timestamp - p.timestamp <= timedelta(minutes=10)
                    and (p.ip == r.ip or p.user == r.user)
                )
                rows.append([
                    self._circ(self._hour(r), typical),          # how far from this user's usual hour
                    1.0 if r.timestamp.weekday() >= 5 else 0.0,   # weekend login
                    ip_count[r.ip] / len(logins),                 # share of this user's logins from this IP
                    float(min(fails_before, 20)),                 # failures just before
                    math.log1p(len(logins)),                      # how active the user is
                ])
                owners.append(r)
        return rows, owners

    def _baseline(self, n=300):
        """
        Small synthetic 'normal behaviour' set so an upload with only a handful of
        logins can still be scored. Office hours, mostly weekdays, same IP, no failures.
        """
        rng = np.random.RandomState(42)
        return np.column_stack([
            np.abs(rng.normal(0, 1.5, n)),
            (rng.rand(n) < 0.12).astype(float),
            np.clip(rng.normal(0.92, 0.08, n), 0.3, 1.0),
            (rng.rand(n) < 0.08).astype(float),
            np.log1p(rng.randint(4, 30, n)),
        ])

    def _ml_check(self, records: List[LoginRecord]) -> List[StandardAlert]:
        if not ML_AVAILABLE:
            return []
        rows, owners = self._features(records)
        if not rows:
            return []

        X = np.array(rows)
        train = np.vstack([self._baseline(), X])
        model = IsolationForest(n_estimators=150, contamination="auto", random_state=7)
        model.fit(train)
        scores = -model.score_samples(X)     # higher = more abnormal (about 0.35 .. 0.8)

        flagged = [(s, o, x) for s, o, x in zip(scores, owners, rows) if s >= ANOMALY_THRESHOLD]
        flagged.sort(key=lambda t: -t[0])
        out = []
        for s, r, x in flagged[:10]:
            reasons = []
            if x[0] >= 4:
                reasons.append(f"login hour is {x[0]:.1f}h away from this user's usual hour")
            if x[1]:
                reasons.append("weekend login")
            if x[2] < 0.35:
                reasons.append("IP rarely used by this user")
            if x[3] >= 3:
                reasons.append(f"{int(x[3])} failed attempts just before")
            out.append(_alert(
                r,
                severity=AlertSeverity.MEDIUM,
                confidence=round(min(0.85, max(0.4, (float(s) - 0.35) * 1.2)), 2),   # 0.60 -> 0.40, 0.80 -> 0.54
                source_ip=r.ip,
                user_id=r.user,
                timestamp=r.timestamp,
                title=f"Abnormal login pattern for '{r.user}' from {r.ip} (anomaly score {s:.2f})",
                evidence={
                    "rule_matched": "ISOLATION_FOREST_OUTLIER",
                    "anomaly_score": round(float(s), 3),
                    "threshold": ANOMALY_THRESHOLD,
                    "features": {
                        "hour_deviation": round(x[0], 2),
                        "weekend": bool(x[1]),
                        "ip_share_for_user": round(x[2], 2),
                        "failed_before": int(x[3]),
                    },
                    "reasons": reasons or ["combination of features unusual for this log"],
                },
                recommended_action=f"Ask '{r.user}' to confirm this login; enforce MFA if it was not them.",
            ))
        return out


login_detector = LoginThreatDetector()
