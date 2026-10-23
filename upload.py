"""File upload endpoints - the way logs get into the platform."""
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import UploadModel, EventModel, AlertModel, IncidentModel, FeedbackModel, \
    ResponseActionModel, BlocklistModel
from app.detectors.login.parser import parse_auth_log
from app.ingest.parsers import parse_web_log, parse_network_log, parse_url_list
from app.services.pipeline import process_events, process_login_records

router = APIRouter(tags=["Log Upload"])

KINDS = {"auth-log": "auth_log", "web-log": "web_log", "network-log": "network_log", "url-list": "url_list"}
MAX_BYTES = 5 * 1024 * 1024


def _handle(db: Session, kind: str, filename: str, text: str) -> dict:
    if kind == "auth-log":
        records, stats = parse_auth_log(text)
        res = process_login_records(db, records)
        total, parsed = stats.total_lines, stats.parsed
    else:
        parser = {"web-log": parse_web_log, "network-log": parse_network_log, "url-list": parse_url_list}[kind]
        events, total, parsed = parser(text)
        res = process_events(db, events)

    if parsed == 0:
        raise HTTPException(status_code=422, detail=f"No usable lines found, is this really a {kind.replace('-', ' ')}?")

    db.add(UploadModel(filename=filename, source_type=KINDS[kind], lines_total=total, lines_parsed=parsed,
                       events_created=res["events"], alerts_created=res["alerts"]))
    db.commit()
    return {"filename": filename, "source_type": KINDS[kind], "lines_total": total, "lines_parsed": parsed,
            "events_created": res["events"], "alerts_created": res["alerts"], "incident_ids": res["incident_ids"]}


@router.post("/upload/{kind}")
async def upload_file(kind: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    if kind not in KINDS:
        raise HTTPException(status_code=404, detail=f"Unknown upload type. Use one of: {', '.join(KINDS)}")
    raw = await file.read()
    if len(raw) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="File too big (5 MB limit)")
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not read file as text")
    return _handle(db, kind, file.filename or kind, text)


@router.get("/uploads")
def list_uploads(db: Session = Depends(get_db)):
    rows = db.query(UploadModel).order_by(UploadModel.uploaded_at.desc()).limit(30).all()
    return [{"id": r.id, "filename": r.filename, "source_type": r.source_type, "lines_total": r.lines_total,
             "lines_parsed": r.lines_parsed, "events_created": r.events_created,
             "alerts_created": r.alerts_created, "uploaded_at": r.uploaded_at.isoformat()} for r in rows]


@router.delete("/admin/reset")
def reset_all(db: Session = Depends(get_db)):
    """Wipes events/alerts/incidents so the demo can start from a clean dashboard."""
    for model in (ResponseActionModel, FeedbackModel, AlertModel, IncidentModel, EventModel, BlocklistModel, UploadModel):
        db.query(model).delete()
    db.commit()
    from app.detectors.port_scan.detector import port_scan_detector
    from app.detectors.web_attack.detector import web_attack_detector
    port_scan_detector.reset()
    if hasattr(web_attack_detector, "reset"):
        web_attack_detector.reset()
    return {"status": "cleared"}
