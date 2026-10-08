from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Text, JSON, UniqueConstraint, Index
from sqlalchemy.orm import relationship
from src.database.session import Base
from src.database.models.base import TimestampMixin, SoftDeleteMixin, utc_now


class Zone(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "zones"

    id = Column(Integer, primary_key=True, index=True)
    zone_id = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    risk_level = Column(String(32), default="MEDIUM", nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_demo = Column(Boolean, default=False, nullable=False)
    schema_version = Column(String(16), default="1.0", nullable=False)
    metadata_json = Column(JSON, nullable=True)

    camera_mappings = relationship("ZoneCameraMapping", back_populates="zone", cascade="all, delete-orphan")
    policies = relationship("SecurityPolicy", back_populates="zone")
    events = relationship("Event", back_populates="zone")
    threats = relationship("Threat", back_populates="zone")
    incidents = relationship("Incident", back_populates="zone")


class ZoneCameraMapping(Base):
    __tablename__ = "zone_camera_mapping"

    id = Column(Integer, primary_key=True, index=True)
    zone_id = Column(String(64), ForeignKey("zones.zone_id", ondelete="CASCADE"), nullable=False, index=True)
    camera_id = Column(String(64), ForeignKey("cameras.camera_id", ondelete="CASCADE"), nullable=False, index=True)
    primary_camera = Column(Boolean, default=False, nullable=False)
    created_at = Column(TimestampMixin.created_at.type, default=utc_now, nullable=False)

    zone = relationship("Zone", back_populates="camera_mappings")
    camera = relationship("Camera", back_populates="zone_mappings")

    __table_args__ = (
        UniqueConstraint("zone_id", "camera_id", name="uq_zone_camera"),
        Index("ix_zone_camera_composite", "zone_id", "camera_id"),
    )


class SecurityPolicy(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "security_policies"

    id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    zone_id = Column(String(64), ForeignKey("zones.zone_id", ondelete="SET NULL"), nullable=True, index=True)
    policy_type = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), default="MEDIUM", nullable=False)
    rules_json = Column(JSON, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_demo = Column(Boolean, default=False, nullable=False)
    schema_version = Column(String(16), default="1.0", nullable=False)

    zone = relationship("Zone", back_populates="policies")
