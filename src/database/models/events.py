from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, JSON, Index
from sqlalchemy.orm import relationship
from src.database.session import Base
from src.database.models.base import TimestampMixin, utc_now


class Event(Base, TimestampMixin):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    camera_id = Column(String(64), ForeignKey("cameras.camera_id", ondelete="RESTRICT"), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    entity_id = Column(String(64), nullable=True, index=True)
    zone_id = Column(String(64), ForeignKey("zones.zone_id", ondelete="SET NULL"), nullable=True, index=True)
    confidence = Column(Float, default=0.0, nullable=False)
    evidence_id = Column(String(64), nullable=True, index=True)
    source = Column(String(64), default="ai-video", nullable=False, index=True)
    status = Column(String(32), default="NEW", nullable=False, index=True)
    schema_version = Column(String(16), default="1.0", nullable=False)
    metadata_json = Column(JSON, nullable=True)

    camera = relationship("Camera", back_populates="events")
    zone = relationship("Zone", back_populates="events")
    entities = relationship("EventEntity", back_populates="event", cascade="all, delete-orphan")
    threats = relationship("Threat", back_populates="event")
    investigation_links = relationship("InvestigationEvent", back_populates="event")

    __table_args__ = (
        Index("ix_events_type_timestamp", "event_type", "timestamp"),
        Index("ix_events_camera_timestamp", "camera_id", "timestamp"),
    )


class EventEntity(Base):
    __tablename__ = "event_entities"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), ForeignKey("events.event_id", ondelete="CASCADE"), nullable=False, index=True)
    entity_id = Column(String(64), nullable=False, index=True)
    entity_type = Column(String(64), nullable=False, index=True)
    bounding_box_json = Column(JSON, nullable=True)
    confidence = Column(Float, default=0.0, nullable=False)
    tracking_id = Column(String(64), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    event = relationship("Event", back_populates="entities")
