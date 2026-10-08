from sqlalchemy import Column, Integer, String, Float, DateTime, Text, JSON, Index
from src.database.session import Base
from src.database.models.base import TimestampMixin, SoftDeleteMixin, utc_now


class SecurityMemory(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "security_memory"

    id = Column(Integer, primary_key=True, index=True)
    memory_id = Column(String(64), unique=True, index=True, nullable=False)
    memory_type = Column(String(64), nullable=False, index=True)
    entity_id = Column(String(64), nullable=True, index=True)
    camera_id = Column(String(64), nullable=True, index=True)
    zone_id = Column(String(64), nullable=True, index=True)
    event_id = Column(String(64), nullable=True, index=True)
    incident_id = Column(String(64), nullable=True, index=True)
    content = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    confidence = Column(Float, default=1.0, nullable=False)
    source_reference = Column(String(500), nullable=True)
    identifier_value = Column(String(255), nullable=True, index=True)
    observations_count = Column(Integer, default=1, nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    schema_version = Column(String(16), default="1.0", nullable=False)
    metadata_json = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_memory_type_identifier", "memory_type", "identifier_value"),
    )
