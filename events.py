from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any
from pydantic import BaseModel

from app.db.session import get_db
from app.db.models import EventModel, AlertModel
from app.schemas.event import SecurityEvent, EventIngestResponse
from app.detectors.phishing.detector import phishing_detector
from app.services.pipeline import process_events

router = APIRouter(tags=["Events & Detection"])

LOGIN_TYPES = ("login_attempt", "authentication", "auth_attempt")


class PhishingUrlRequest(BaseModel):
    url: str


class PhishingUrlResponse(BaseModel):
    valid: bool
    url: str
    is_phishing: bool
    confidence: float
    features: Dict[str, Any]
    evidence: Dict[str, Any]
    alert_generated: bool
    alert_id: Optional[str] = None


@router.post("/events/ingest", response_model=EventIngestResponse)
def ingest_security_event(event: SecurityEvent, db: Session = Depends(get_db)):
    """
    Send ONE event as JSON (web request, network connection, url, honeytoken access).
    Login events are not accepted here: the login module works on uploaded auth.log files
    (POST /api/upload/auth-log).
    """
    if event.event_type in LOGIN_TYPES:
        raise HTTPException(status_code=422, detail="Login events are analysed from uploaded auth.log files, use /api/upload/auth-log")

    if db.query(EventModel).filter(EventModel.id == event.event_id).first():
        existing = db.query(AlertModel).filter(AlertModel.event_id == event.event_id).all()
        return EventIngestResponse(status="duplicate_acknowledged", event_id=event.event_id,
                                   generated_alerts_count=len(existing), alert_ids=[a.id for a in existing],
                                   incident_id=existing[0].incident_id if existing else None,
                                   message="Event already ingested.")

    res = process_events(db, [event])
    alerts = db.query(AlertModel).filter(AlertModel.event_id == event.event_id).all()
    return EventIngestResponse(
        status="processed", event_id=event.event_id, generated_alerts_count=res["alerts"],
        alert_ids=[a.id for a in alerts], incident_id=res["incident_ids"][-1] if res["incident_ids"] else None,
        message=f"Event ingested. Generated {res['alerts']} alert(s).")


@router.post("/detect/phishing-url", response_model=PhishingUrlResponse)
def detect_phishing_url(payload: PhishingUrlRequest, db: Session = Depends(get_db)):
    """Check one URL with the Random Forest model + URL rules. Raises an alert if it looks like phishing."""
    analysis = phishing_detector.analyze_url(payload.url)
    if not analysis.get("valid"):
        raise HTTPException(status_code=400, detail=analysis.get("error", "Invalid URL"))

    alert_id = None
    if analysis["is_phishing"]:
        event = SecurityEvent(event_type="url_submission", target=payload.url, source_module="manual_check",
                              evidence={"url": payload.url})
        res = process_events(db, [event])
        a = db.query(AlertModel).filter(AlertModel.event_id == event.event_id).first()
        alert_id = a.id if a else None

    return PhishingUrlResponse(valid=True, url=analysis["url"], is_phishing=analysis["is_phishing"],
                               confidence=analysis["confidence"], features=analysis["features"],
                               evidence=analysis["evidence"], alert_generated=bool(alert_id), alert_id=alert_id)


@router.get("/events")
def list_events(limit: int = Query(50, ge=1, le=200), event_type: Optional[str] = None,
                db: Session = Depends(get_db)):
    q = db.query(EventModel).order_by(EventModel.timestamp.desc())
    if event_type:
        q = q.filter(EventModel.event_type == event_type)
    return [{"event_id": e.id, "event_type": e.event_type,
             "timestamp": e.timestamp.isoformat() if e.timestamp else None, "source_ip": e.source_ip,
             "user_id": e.user_id, "target": e.target, "source_module": e.source_module, "evidence": e.evidence}
            for e in q.limit(limit).all()]
