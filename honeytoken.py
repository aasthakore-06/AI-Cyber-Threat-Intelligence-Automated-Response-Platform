"""Honeytoken / deception layer: webhook + list of seeded decoys."""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import HoneytokenModel
from app.schemas.event import SecurityEvent
from app.services.pipeline import process_events

router = APIRouter(tags=["Honeytoken"])          # needs admin token
public_router = APIRouter(tags=["Honeytoken"])   # webhook, decoys call it themselves


class HoneytokenHit(BaseModel):
    token: Optional[str] = None
    token_id: Optional[int] = None      # id from the honeytokens table (used by the dashboard form)
    source_ip: Optional[str] = None
    resource: Optional[str] = None
    user: Optional[str] = None
    user_agent: Optional[str] = None


def record_hit(db: Session, hit: HoneytokenHit):
    if hit.token_id and not hit.token:
        row = db.query(HoneytokenModel).filter(HoneytokenModel.id == hit.token_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Unknown honeytoken")
        hit.token = row.decoy_value
    if not hit.token:
        raise HTTPException(status_code=422, detail="Give token or token_id")
    ev = SecurityEvent(event_type="honeytoken_access", source_ip=hit.source_ip, user_id=hit.user,
                       target=hit.resource or hit.token, source_module="honeytoken_webhook",
                       evidence={"token": hit.token, "user_agent": hit.user_agent or ""})
    return process_events(db, [ev])


@public_router.post("/detect/honeytoken")
def honeytoken_webhook(hit: HoneytokenHit, db: Session = Depends(get_db)):
    """Any access to a decoy ends up here. Every hit is treated as high-confidence (score >= 90)."""
    res = record_hit(db, hit)
    return {"status": "recorded", **res}


@router.get("/honeytokens")
def list_honeytokens(db: Session = Depends(get_db)):
    from app.core.security import mask_sensitive_token
    return [{"id": h.id, "type": h.type, "decoy": mask_sensitive_token(h.decoy_value),
             "resource_path": h.resource_path, "created_at": h.created_at.isoformat(),
             "last_triggered_at": h.last_triggered_at.isoformat() if h.last_triggered_at else None}
            for h in db.query(HoneytokenModel).all()]
