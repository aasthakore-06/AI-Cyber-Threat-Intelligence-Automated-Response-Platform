from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Float,
    DateTime,
    Text,
    JSON,
    ForeignKey,
    Boolean,
    Integer
)
from sqlalchemy.orm import relationship
from app.db.session import Base


class EventModel(Base):
    __tablename__ = "events"

    id = Column(String(64), primary_key=True, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source_ip = Column(String(64), nullable=True, index=True)
    user_id = Column(String(64), nullable=True, index=True)
    target = Column(String(255), nullable=True)
    source_module = Column(String(64), default="upload")
    evidence = Column(JSON, default=dict)
    metadata_json = Column(JSON, default=dict)


class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(String(64), primary_key=True, index=True)
    event_id = Column(String(64), ForeignKey("events.id", ondelete="CASCADE"), index=True)
    detector = Column(String(64), nullable=False, index=True)
    category = Column(String(64), nullable=False)
    severity = Column(String(32), nullable=False, index=True)
    confidence = Column(Float, nullable=False)
    source_ip = Column(String(64), nullable=True, index=True)
    user_id = Column(String(64), nullable=True, index=True)
    target = Column(String(255), nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    title = Column(String(255), nullable=False)
    evidence = Column(JSON, default=dict)
    recommended_action = Column(Text, nullable=False)
    incident_id = Column(String(64), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)

    incident = relationship("IncidentModel", back_populates="alerts")


class IncidentModel(Base):
    __tablename__ = "incidents"

    id = Column(String(64), primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=False)
    status = Column(String(32), default="open", index=True)
    risk_score = Column(Float, nullable=False, default=0.0)
    risk_tier = Column(String(32), default="Low", index=True)
    related_entities = Column(JSON, default=dict)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    evidence = Column(JSON, default=dict)
    timeline = Column(JSON, default=list)
    risk_score_explanation = Column(JSON, default=list)
    incident_narrative = Column(Text, default="")
    # decay (workflow step 10.5)
    base_risk_score = Column(Float, default=0.0)
    last_evidence_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    decay_history = Column(JSON, default=list)
    # response (step 12)
    response_mode = Column(String(16), nullable=True)   # manual / auto
    correlation_method = Column(String(32), default="time_window")
    explanation = Column(JSON, default=list)

    alerts = relationship("AlertModel", back_populates="incident", cascade="all, delete-orphan", passive_deletes=True)
    feedback = relationship("FeedbackModel", back_populates="incident", uselist=False, cascade="all, delete-orphan")
    response_actions = relationship("ResponseActionModel", back_populates="incident", cascade="all, delete-orphan")


class FeedbackModel(Base):
    __tablename__ = "feedback"

    id = Column(String(64), primary_key=True, index=True)
    incident_id = Column(String(64), ForeignKey("incidents.id", ondelete="CASCADE"), unique=True)
    verdict = Column(String(32), nullable=False)
    notes = Column(Text, default="")
    analyst_id = Column(String(64), nullable=False)
    feature_snapshot = Column(JSON, default=dict)   # alert evidence at the time of the decision
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    incident = relationship("IncidentModel", back_populates="feedback")


class ResponseActionModel(Base):
    __tablename__ = "response_actions"

    id = Column(String(64), primary_key=True, index=True)
    incident_id = Column(String(64), ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    action_type = Column(String(64), nullable=False)
    mode = Column(String(16), default="manual")
    performed_by = Column(String(64), default="admin")
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    reason = Column(Text, default="")
    outcome = Column(Text, default="")
    parameters = Column(JSON, default=dict)

    incident = relationship("IncidentModel", back_populates="response_actions")


class BlocklistModel(Base):
    """IPs / URLs blocked by a response action. A firewall or proxy could read this table."""
    __tablename__ = "blocklist"

    id = Column(Integer, primary_key=True, autoincrement=True)
    kind = Column(String(8), nullable=False)          # ip / url
    value = Column(String(512), nullable=False, index=True)
    incident_id = Column(String(64), nullable=True)
    mode = Column(String(16), default="manual")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class SettingModel(Base):
    __tablename__ = "settings"

    key = Column(String(64), primary_key=True)
    value = Column(String(255), nullable=False)


class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(16), default="admin")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class HoneytokenModel(Base):
    __tablename__ = "honeytokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String(32), nullable=False)
    decoy_value = Column(String(255), nullable=False, unique=True)
    resource_path = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_triggered_at = Column(DateTime, nullable=True)


class UploadModel(Base):
    """One row per uploaded log file, so the dashboard can show log source health."""
    __tablename__ = "uploads"

    id = Column(Integer, primary_key=True, autoincrement=True)
    filename = Column(String(255))
    source_type = Column(String(32))     # auth_log / web_log / network_log / url_list
    lines_total = Column(Integer, default=0)
    lines_parsed = Column(Integer, default=0)
    events_created = Column(Integer, default=0)
    alerts_created = Column(Integer, default=0)
    uploaded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
