"""Tiny key/value helper on the settings table (used for the auto-response toggle)."""
from sqlalchemy.orm import Session
from app.db.models import SettingModel


def get_setting(db: Session, key: str, default: str = "") -> str:
    row = db.query(SettingModel).filter(SettingModel.key == key).first()
    return row.value if row else default


def set_setting(db: Session, key: str, value: str) -> None:
    row = db.query(SettingModel).filter(SettingModel.key == key).first()
    if row:
        row.value = value
    else:
        db.add(SettingModel(key=key, value=value))
    db.commit()


def auto_response_enabled(db: Session) -> bool:
    return get_setting(db, "auto_response_enabled", "false") == "true"
