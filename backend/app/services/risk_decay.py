"""
Risk Decay (workflow step 10.5)
Owner: Aastha

If an incident gets no new evidence, its score slowly goes down:
    every DECAY_STEP_HOURS (6h) without a new alert  ->  lose DECAY_PERCENT (10%)
The score never goes below a floor (50% of the original score, 60 if the incident has a
honeytoken hit) so a serious incident loses priority but never vanishes.

"No new evidence" is measured from incident.last_evidence_at = the wall-clock time the
last alert was added (NOT the timestamp inside the log, otherwise an old uploaded log
would decay instantly).  New evidence resets the score back to the base score.
"""
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import IncidentModel, AlertModel
from app.services.risk_scoring import tier_for

HONEYTOKEN_FLOOR = 60.0


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def decay_score(base_score: float, idle_hours: float, has_honeytoken: bool = False) -> Dict[str, Any]:
    """Pure function (easy to unit test)."""
    steps = int(max(0.0, idle_hours) // settings.DECAY_STEP_HOURS)
    factor = (1.0 - settings.DECAY_PERCENT / 100.0) ** steps
    floor = base_score * settings.DECAY_FLOOR_RATIO
    if has_honeytoken:
        floor = max(floor, min(base_score, HONEYTOKEN_FLOOR))
    score = max(base_score * factor, floor)
    return {
        "steps": steps,
        "factor": round(factor, 3),
        "floor": round(floor, 1),
        "score": round(min(100.0, score), 1),
        "floor_hit": base_score * factor < floor,
    }


def run_decay_job(db: Session, hours_ahead: float = 0.0, now: Optional[datetime] = None) -> int:
    """
    Apply decay to every active incident. hours_ahead lets the demo fast-forward time
    ("what would this look like 24 hours from now?").
    Returns how many incidents changed.
    """
    now = (now or datetime.now(timezone.utc)) + timedelta(hours=hours_ahead)
    changed = 0
    active = db.query(IncidentModel).filter(IncidentModel.status.in_(["open", "escalated"])).all()
    for inc in active:
        base = inc.base_risk_score or inc.risk_score
        last = _aware(inc.last_evidence_at or inc.last_seen)
        idle_h = (now - last).total_seconds() / 3600.0
        has_ht = db.query(AlertModel).filter(
            AlertModel.incident_id == inc.id, AlertModel.detector == "honeytoken").first() is not None
        res = decay_score(base, idle_h, has_ht)
        if abs(res["score"] - inc.risk_score) < 0.05:
            continue
        old = inc.risk_score
        inc.risk_score = res["score"]
        inc.risk_tier = tier_for(res["score"]).value
        hist = list(inc.decay_history or [])
        hist.append({
            "at": now.isoformat(),
            "from": old,
            "to": res["score"],
            "idle_hours": round(idle_h, 1),
            "steps": res["steps"],
            "note": "floor reached" if res["floor_hit"] else "no new evidence",
        })
        inc.decay_history = hist[-30:]
        changed += 1
    db.commit()
    return changed
