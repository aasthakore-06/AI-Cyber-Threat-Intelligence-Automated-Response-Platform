from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.session import get_db
from app.db.models import IncidentModel, AlertModel, EventModel, UploadModel, BlocklistModel
from app.services.settings_store import auto_response_enabled

router = APIRouter(tags=["Dashboard Statistics"])

SOURCE_LABELS = {"auth_log": "Auth log", "web_log": "Web access log", "network_log": "Network log", "url_list": "URL list"}


@router.get("/stats/dashboard")
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_events = db.query(func.count(EventModel.id)).scalar() or 0
    total_alerts = db.query(func.count(AlertModel.id)).scalar() or 0
    total_incidents = db.query(func.count(IncidentModel.id)).scalar() or 0

    status_counts = {"open": 0, "escalated": 0, "contained": 0, "false_positive": 0, "closed": 0}
    for st, n in db.query(IncidentModel.status, func.count(IncidentModel.id)).group_by(IncidentModel.status):
        status_counts[st] = n
    resolved = status_counts["contained"] + status_counts["false_positive"] + status_counts["closed"]
    open_n = status_counts["open"] + status_counts["escalated"]

    tiers = {"Safe": 0, "Suspicious": 0, "Malicious": 0}
    for t, n in db.query(IncidentModel.risk_tier, func.count(IncidentModel.id)).group_by(IncidentModel.risk_tier):
        if t in tiers:
            tiers[t] = n

    det = {}
    for d, n in db.query(AlertModel.detector, func.count(AlertModel.id)).group_by(AlertModel.detector):
        det[d] = {"count": n, "percent": round(100 * n / total_alerts, 1) if total_alerts else 0}

    ev_types = {t: n for t, n in db.query(EventModel.event_type, func.count(EventModel.id)).group_by(EventModel.event_type)}

    incidents = db.query(IncidentModel).order_by(IncidentModel.last_seen.desc()).all()
    recent = incidents[:8]
    trend = [{"id": i.id, "time": i.first_seen.isoformat(), "score": i.risk_score, "base": i.base_risk_score}
             for i in sorted(incidents, key=lambda x: x.first_seen)][-20:]

    sources = []
    for key, label in SOURCE_LABELS.items():
        rows = db.query(UploadModel).filter(UploadModel.source_type == key).all()
        last = max((r.uploaded_at for r in rows), default=None)
        sources.append({"source": label, "files": len(rows), "events": sum(r.events_created for r in rows),
                        "lines_parsed": sum(r.lines_parsed for r in rows), "lines_total": sum(r.lines_total for r in rows),
                        "last_upload": last.isoformat() if last else None})

    recent_alerts = db.query(AlertModel).order_by(AlertModel.timestamp.desc()).limit(10).all()
    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "total_incidents": total_incidents,
        "open_incidents": open_n,
        "resolved_incidents": resolved,
        "malicious_incidents": tiers["Malicious"],
        "blocked_entries": db.query(func.count(BlocklistModel.id)).scalar() or 0,
        "auto_response_enabled": auto_response_enabled(db),
        "incident_status": status_counts,
        "risk_tier_distribution": tiers,
        "alerts_by_type": det,
        "events_by_type": ev_types,
        "risk_trend": trend,
        "log_sources": sources,
        "recent_incidents": [{
            "id": i.id, "title": i.title, "status": i.status, "risk_score": i.risk_score, "risk_tier": i.risk_tier,
            "response_mode": i.response_mode, "last_seen": i.last_seen.isoformat() if i.last_seen else None,
            "alert_count": len(i.alerts) if i.alerts else 0} for i in recent],
        "recent_alerts": [{
            "id": a.id, "title": a.title, "detector": a.detector, "severity": a.severity,
            "confidence": a.confidence, "source_ip": a.source_ip, "incident_id": a.incident_id,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None} for a in recent_alerts],
    }
