"""
Shared ingest pipeline. Every upload / API call ends up here:
   events -> detectors -> alerts -> primary correlation -> incident (+ auto response if on)
"""
import uuid
from typing import List, Dict, Any, Tuple

from sqlalchemy.orm import Session

from app.db.models import EventModel, AlertModel, HoneytokenModel
from app.schemas.event import SecurityEvent
from app.schemas.alert import StandardAlert
from app.detectors import dispatch_event_to_detectors
from app.detectors.login.parser import LoginRecord
from app.detectors.login.detector import login_detector
from app.services.correlation import correlator
from app.services.live import live_feed
from datetime import datetime, timezone


def store_event(db: Session, ev: SecurityEvent) -> bool:
    if db.query(EventModel.id).filter(EventModel.id == ev.event_id).first():
        return False
    db.add(EventModel(id=ev.event_id, event_type=ev.event_type, timestamp=ev.timestamp, source_ip=ev.source_ip,
                      user_id=ev.user_id, target=ev.target, source_module=ev.source_module or "upload",
                      evidence=ev.evidence, metadata_json=ev.metadata or {}))
    return True


def store_alert_and_correlate(db: Session, alert: StandardAlert):
    ev = alert.evidence or {}
    db.add(AlertModel(
        id=alert.alert_id, event_id=alert.event_id,
        detector=_v(alert.detector), category=_v(alert.category), severity=_v(alert.severity),
        confidence=alert.confidence, source_ip=alert.source_ip, user_id=alert.user_id, target=alert.target,
        timestamp=alert.timestamp, title=alert.title, evidence=ev,
        recommended_action=alert.recommended_action, incident_id=None))
    db.commit()
    inc = correlator.correlate_alert(db, alert)
    live_feed.push({"type": "alert", "alert": {
        "id": alert.alert_id, "title": alert.title, "detector": _v(alert.detector),
        "severity": _v(alert.severity), "source_ip": alert.source_ip,
        "timestamp": alert.timestamp.isoformat(), "incident_id": inc.id,
        "risk_score": inc.risk_score, "risk_tier": inc.risk_tier}})
    if _v(alert.detector) == "honeytoken":
        mark_honeytoken_triggered(db, ev.get("masked_honeytoken"))
    return inc


def _v(x):
    return x.value if hasattr(x, "value") else str(x)


def mark_honeytoken_triggered(db: Session, masked: str):
    # the alert only carries the masked decoy, so match on the masked form
    from app.core.security import mask_sensitive_token
    for h in db.query(HoneytokenModel).all():
        if mask_sensitive_token(h.decoy_value) == masked:
            h.last_triggered_at = datetime.now(timezone.utc)
    db.commit()


def refresh_honeytokens(db: Session) -> int:
    """Load the decoys from the honeytokens table into the detector (table = single source of truth)."""
    from app.detectors.honeytoken.detector import honeytoken_detector
    values = [h.decoy_value for h in db.query(HoneytokenModel).all()]
    honeytoken_detector.set_tokens(values)
    return len(values)


def process_events(db: Session, events: List[SecurityEvent]) -> Dict[str, Any]:
    """Run non-login events through the detectors."""
    refresh_honeytokens(db)
    created, alerts_n, incident_ids = 0, 0, set()
    for ev in events:
        if store_event(db, ev):
            created += 1
    db.commit()
    for ev in events:
        for alert in dispatch_event_to_detectors(ev):
            inc = store_alert_and_correlate(db, alert)
            incident_ids.add(inc.id)
            alerts_n += 1
    return {"events": created, "alerts": alerts_n, "incident_ids": sorted(incident_ids)}


def process_login_records(db: Session, records: List[LoginRecord]) -> Dict[str, Any]:
    """Login module: one event per parsed log line, then analyse the whole batch."""
    created = 0
    for r in records:
        r.event_id = f"auth_{uuid.uuid4().hex[:10]}"
        ev = SecurityEvent(event_id=r.event_id, event_type="login_attempt", timestamp=r.timestamp,
                           source_ip=r.ip, user_id=r.user, target="ssh / auth service", source_module="auth_log",
                           evidence={"status": r.status, "method": r.method, "log_line": r.line_no})
        if store_event(db, ev):
            created += 1
    db.commit()
    alerts_n, incident_ids = 0, set()
    for alert in login_detector.analyze(records):
        inc = store_alert_and_correlate(db, alert)
        incident_ids.add(inc.id)
        alerts_n += 1
    return {"events": created, "alerts": alerts_n, "incident_ids": sorted(incident_ids)}
