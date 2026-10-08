from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON, UniqueConstraint, Index
from sqlalchemy.orm import relationship, synonym
from src.database.session import Base
from src.database.models.base import TimestampMixin, SoftDeleteMixin, utc_now


class Investigation(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(String(64), unique=True, index=True, nullable=False)
    incident_id = Column(String(64), ForeignKey("incidents.incident_id", ondelete="CASCADE"), nullable=True, index=True)
    trigger_incident_id = Column(String(64), nullable=True, index=True)
    trigger_event_id = Column(String(64), ForeignKey("events.event_id", ondelete="SET NULL"), nullable=True, index=True)
    trigger_threat_id = Column(String(64), ForeignKey("threats.threat_id", ondelete="SET NULL"), nullable=True, index=True)
    assigned_user_id = Column(String(64), ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True, index=True)
    investigator_id = synonym("assigned_user_id")

    title = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    status = Column(String(32), default="PENDING", nullable=False, index=True)  # PENDING, ACTIVE, PAUSED, COMPLETED, CANCELLED, FAILED
    priority = Column(String(32), default="MEDIUM", nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    findings = Column(Text, nullable=True)
    schema_version = Column(String(16), default="1.0", nullable=False)
    started_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    concluded_at = synonym("completed_at")
    metadata_json = Column(JSON, nullable=True)

    incident = relationship("Incident", back_populates="investigations")
    assigned_user = relationship("User", foreign_keys=[assigned_user_id])
    investigator = relationship("User", foreign_keys=[assigned_user_id], viewonly=True)
    trigger_event = relationship("Event", foreign_keys=[trigger_event_id])
    trigger_threat = relationship("Threat", foreign_keys=[trigger_threat_id])
    event_links = relationship("InvestigationEvent", back_populates="investigation", cascade="all, delete-orphan")


class InvestigationEvent(Base):
    __tablename__ = "investigation_events"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), nullable=False, index=True)
    event_id = Column(String(64), ForeignKey("events.event_id", ondelete="CASCADE"), nullable=False, index=True)
    added_by_user_id = Column(String(64), ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True, index=True)
    notes = Column(Text, nullable=True)
    added_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    investigation = relationship("Investigation", back_populates="event_links")
    event = relationship("Event", back_populates="investigation_links")
    added_by = relationship("User")

    __table_args__ = (
        UniqueConstraint("investigation_id", "event_id", name="uq_investigation_event"),
        Index("ix_inv_event_composite", "investigation_id", "event_id"),
    )
