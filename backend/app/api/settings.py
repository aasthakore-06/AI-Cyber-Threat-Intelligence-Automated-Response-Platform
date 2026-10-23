from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import BlocklistModel
from app.services.settings_store import auto_response_enabled, set_setting
from app.services.risk_decay import run_decay_job
from app.services.graph_correlation import run_graph_correlation

router = APIRouter(tags=["Settings & Jobs"])

_last_graph = {"components": [], "nodes": [], "edges": [], "merged": 0}


class AutoResponseBody(BaseModel):
    enabled: bool


@router.get("/settings")
def get_settings(db: Session = Depends(get_db)):
    return {"auto_response_enabled": auto_response_enabled(db)}


@router.put("/settings/auto-response")
def put_auto_response(body: AutoResponseBody, db: Session = Depends(get_db)):
    set_setting(db, "auto_response_enabled", "true" if body.enabled else "false")
    return {"auto_response_enabled": body.enabled}


@router.get("/blocklist")
def get_blocklist(db: Session = Depends(get_db)):
    rows = db.query(BlocklistModel).order_by(BlocklistModel.created_at.desc()).all()
    return [{"id": r.id, "kind": r.kind, "value": r.value, "incident_id": r.incident_id, "mode": r.mode,
             "created_at": r.created_at.isoformat()} for r in rows]


@router.delete("/blocklist/{item_id}")
def unblock(item_id: int, db: Session = Depends(get_db)):
    db.query(BlocklistModel).filter(BlocklistModel.id == item_id).delete()
    db.commit()
    return {"status": "removed"}


@router.post("/jobs/decay")
def decay_now(hours_ahead: float = 0.0, db: Session = Depends(get_db)):
    """Run the decay job right now. hours_ahead=24 shows what scores look like a day from now (demo)."""
    return {"incidents_changed": run_decay_job(db, hours_ahead=hours_ahead)}


@router.post("/jobs/graph")
def graph_now(db: Session = Depends(get_db)):
    """Run the NetworkX batch correlation right now (also runs on a timer)."""
    global _last_graph
    _last_graph = run_graph_correlation(db)
    return _last_graph


@router.get("/graph/global")
def graph_global():
    """Result of the last NetworkX batch run (labelled 'batch' in the UI)."""
    return _last_graph
