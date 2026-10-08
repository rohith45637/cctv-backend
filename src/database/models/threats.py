from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, JSON, Index
from sqlalchemy.orm import relationship, synonym
from src.database.session import Base
from src.database.models.base import TimestampMixin, SoftDeleteMixin, utc_now


class Threat(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(String(64), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    severity = Column(String(32), default="MEDIUM", nullable=False, index=True)  # HIGH, MEDIUM, LOW, UNKNOWN
    threat_level = synonym("severity")  # Backward compatibility
    status = Column(String(32), default="NEW", nullable=False, index=True)  # NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, DISMISSED
    risk_score = Column(Float, default=0.0, nullable=False)
    reason = Column(Text, nullable=True)
    camera_id = Column(String(64), ForeignKey("cameras.camera_id", ondelete="SET NULL"), nullable=True, index=True)
    zone_id = Column(String(64), ForeignKey("zones.zone_id", ondelete="SET NULL"), nullable=True, index=True)
    event_id = Column(String(64), ForeignKey("events.event_id", ondelete="SET NULL"), nullable=True, index=True)
    incident_id = Column(String(64), ForeignKey("incidents.incident_id", ondelete="SET NULL", use_alter=True), nullable=True, index=True)
    confidence = Column(Float, default=0.0, nullable=False)
    schema_version = Column(String(16), default="1.0", nullable=False)
    detected_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    metadata_json = Column(JSON, nullable=True)

    camera = relationship("Camera")
    zone = relationship("Zone", back_populates="threats")
    event = relationship("Event", back_populates="threats")
    incident = relationship("Incident", foreign_keys=[incident_id], back_populates="linked_threats")
    originating_incident = relationship("Incident", foreign_keys="Incident.threat_id", back_populates="originating_threat", uselist=False)

    __table_args__ = (
        Index("ix_threats_severity_status", "severity", "status"),
        Index("ix_threats_camera_event", "camera_id", "event_id"),
    )


class Incident(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    severity = Column(String(32), default="P2", nullable=False, index=True)  # P1, P2, P3, P4
    status = Column(String(32), default="OPEN", nullable=False, index=True)  # OPEN, INVESTIGATING, RESOLVED, CLOSED
    primary_camera_id = Column(String(64), ForeignKey("cameras.camera_id", ondelete="SET NULL"), nullable=True, index=True)
    zone_id = Column(String(64), ForeignKey("zones.zone_id", ondelete="SET NULL"), nullable=True, index=True)
    threat_id = Column(String(64), ForeignKey("threats.threat_id", ondelete="SET NULL"), nullable=True, index=True)
    lead_analyst_id = Column(String(64), ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True, index=True)
    opened_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    start_time = synonym("opened_at")  # Contract alias
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    end_time = synonym("resolved_at")  # Contract alias
    related_event_ids = Column(JSON, default=list, nullable=True)
    related_threat_ids = Column(JSON, default=list, nullable=True)
    schema_version = Column(String(16), default="1.0", nullable=False)
    metadata_json = Column(JSON, nullable=True)

    primary_camera = relationship("Camera")
    lead_analyst = relationship("User")
    zone = relationship("Zone", back_populates="incidents")
    originating_threat = relationship("Threat", foreign_keys=[threat_id], back_populates="originating_incident")
    linked_threats = relationship("Threat", foreign_keys="Threat.incident_id", back_populates="incident")
    investigations = relationship("Investigation", back_populates="incident")

    __table_args__ = (
        Index("ix_incidents_severity_status", "severity", "status"),
    )
