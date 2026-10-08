from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, JSON, Index
from sqlalchemy.orm import relationship
from src.database.session import Base
from src.database.models.base import TimestampMixin, SoftDeleteMixin, utc_now


class Camera(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "cameras"

    id = Column(Integer, primary_key=True, index=True)
    camera_id = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False, index=True)
    stream_url = Column(String(500), nullable=True)
    ip_address = Column(String(45), nullable=True)
    location_description = Column(Text, nullable=True)
    status = Column(String(32), default="ONLINE", nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_demo = Column(Boolean, default=False, nullable=False)
    schema_version = Column(String(16), default="1.0", nullable=False)
    metadata_json = Column(JSON, nullable=True)

    status_history = relationship(
        "CameraStatusHistory",
        back_populates="camera",
        cascade="all, delete-orphan",
        order_by="desc(CameraStatusHistory.recorded_at)",
    )
    zone_mappings = relationship("ZoneCameraMapping", back_populates="camera", cascade="all, delete-orphan")
    events = relationship("Event", back_populates="camera")
    evidence_items = relationship("Evidence", back_populates="camera")

    __table_args__ = (
        Index("ix_cameras_status_active", "status", "is_active"),
    )


class CameraStatusHistory(Base):
    __tablename__ = "camera_status_history"

    id = Column(Integer, primary_key=True, index=True)
    camera_id = Column(String(64), ForeignKey("cameras.camera_id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(32), nullable=False)
    reason = Column(String(255), nullable=True)
    recorded_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    metadata_json = Column(JSON, nullable=True)

    camera = relationship("Camera", back_populates="status_history")
