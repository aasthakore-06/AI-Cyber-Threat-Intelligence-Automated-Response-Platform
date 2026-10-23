"""
Response service (workflow step 12)
Owner: Radhika

ONE function, perform_response(), does the real work. It is called from two places:
  - manual mode: the admin clicks a button  -> POST /api/incidents/{id}/respond
  - auto mode:   the correlation job calls it as soon as an incident becomes Malicious
                 (only if settings.auto_response_enabled == true)
Keeping a single function means the two paths can never drift apart.

"Blocking" = inserting the IP/URL into the blocklist table. A firewall or proxy could
read that table; for this prototype we deliberately don't touch real infrastructure.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from sqlalchemy.orm import Session

from app.db.models import (IncidentModel, ResponseActionModel, BlocklistModel,
                           FeedbackModel, AlertModel)
from app.schemas.incident import ResponseActionType, IncidentStatus


def _already_blocked(db: Session, kind: str, value: str) -> bool:
    return db.query(BlocklistModel).filter(BlocklistModel.kind == kind, BlocklistModel.value == value).first() is not None


def _snapshot(db: Session, incident_id: str) -> Dict[str, Any]:
    alerts = db.query(AlertModel).filter(AlertModel.incident_id == incident_id).all()
    return {a.id: {"detector": a.detector, "severity": a.severity, "confidence": a.confidence, "evidence": a.evidence}
            for a in alerts}


def _save_feedback(db: Session, incident: IncidentModel, verdict: str, who: str):
    fb = db.query(FeedbackModel).filter(FeedbackModel.incident_id == incident.id).first()
    snap = _snapshot(db, incident.id)
    if fb:
        fb.verdict, fb.analyst_id, fb.feature_snapshot = verdict, who, snap
        fb.timestamp = datetime.now(timezone.utc)
    else:
        db.add(FeedbackModel(id=f"fb_{uuid.uuid4().hex[:10]}", incident_id=incident.id, verdict=verdict,
                             notes="logged from response action", analyst_id=who, feature_snapshot=snap))


def perform_response(db: Session, incident: IncidentModel, action: ResponseActionType, mode: str = "manual",
                     performed_by: str = "admin", reason: str = "",
                     params: Optional[Dict[str, Any]] = None) -> ResponseActionModel:
    params = dict(params or {})
    ents = incident.related_entities or {}
    action = ResponseActionType(action)

    if action == ResponseActionType.BLOCK_IP:
        ips = ([params["ip"]] if params.get("ip") else list(params.get("ips") or []) or list(ents.get("ips", [])))
        new = []
        for ip in ips:
            if ip and not _already_blocked(db, "ip", ip):
                db.add(BlocklistModel(kind="ip", value=ip, incident_id=incident.id, mode=mode))
                new.append(ip)
        outcome = (f"Added {', '.join(new)} to the blocklist" if new else "IP(s) were already on the blocklist")
        params["blocked_ips"] = ips
        incident.status = IncidentStatus.CONTAINED.value

    elif action == ResponseActionType.BLOCK_URL:
        urls = [params["url"]] if params.get("url") else list(ents.get("urls", []))
        new = []
        for u in urls:
            if u and not _already_blocked(db, "url", u):
                db.add(BlocklistModel(kind="url", value=u, incident_id=incident.id, mode=mode))
                new.append(u)
        outcome = (f"Added {len(new)} URL(s) to the blocklist" if new else "No URL to block in this incident")
        params["blocked_urls"] = urls
        if urls:
            incident.status = IncidentStatus.CONTAINED.value

    elif action == ResponseActionType.ESCALATE:
        incident.status = IncidentStatus.ESCALATED.value
        outcome = "Incident escalated for senior review"
        if mode == "manual":
            _save_feedback(db, incident, "true_positive", performed_by)

    elif action == ResponseActionType.CLOSE_INCIDENT:
        incident.status = IncidentStatus.CLOSED.value
        outcome = "Incident closed"

    else:  # MARK_FALSE_POSITIVE
        incident.status = IncidentStatus.FALSE_POSITIVE.value
        outcome = "Marked as false positive, closed"
        _save_feedback(db, incident, "false_positive", performed_by)

    incident.response_mode = mode
    rec = ResponseActionModel(
        id=f"act_{uuid.uuid4().hex[:10]}", incident_id=incident.id, action_type=action.value,
        mode=mode, performed_by=performed_by if mode == "manual" else "system",
        reason=reason or ("auto response: risk score crossed 71" if mode == "auto" else ""),
        outcome=outcome, parameters=params,
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec


def auto_respond(db: Session, incident: IncidentModel) -> Optional[ResponseActionModel]:
    """Called by the correlator when auto mode is on and the incident is Malicious (>=71)."""
    if incident.response_mode or incident.status != "open":
        return None                      # already handled
    ents = incident.related_entities or {}
    if ents.get("ips"):
        return perform_response(db, incident, ResponseActionType.BLOCK_IP, mode="auto")
    if ents.get("urls"):
        return perform_response(db, incident, ResponseActionType.BLOCK_URL, mode="auto")
    return perform_response(db, incident, ResponseActionType.ESCALATE, mode="auto")
