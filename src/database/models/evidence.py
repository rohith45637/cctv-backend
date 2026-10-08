from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, JSON, Index
from sqlalchemy.orm import relationship, synonym
from src.database.session import Base
from src.database.models.base import TimestampMixin, SoftDeleteMixin, utc_now


class Evidence(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(String(64), unique=True, index=True, nullable=False)
    camera_id = Column(String(64), ForeignKey("cameras.camera_id", ondelete="RESTRICT"), nullable=False, index=True)
    event_id = Column(String(64), ForeignKey("events.event_id", ondelete="SET NULL"), nullable=True, index=True)
    timestamp_start = Column(DateTime(timezone=True), nullable=False, index=True)
    timestamp_end = Column(DateTime(timezone=True), nullable=False, index=True)
    source_reference = Column(String(500), nullable=False)
    clip_reference = Column(String(500), nullable=False)
    confidence = Column(Float, default=0.0, nullable=False)
    verification_status = Column(String(32), default="UNVERIFIED", nullable=False, index=True)  # UNVERIFIED, VERIFIED, REJECTED, INSUFFICIENT_EVIDENCE
    source_type = Column(String(32), default="AI_VIDEO", nullable=False, index=True)  # AI_VIDEO, CAMERA, UPLOAD, SYSTEM
    provenance_json = Column(JSON, nullable=True)
    schema_version = Column(String(16), default="1.0", nullable=False)
    storage_url = Column(String(500), nullable=True)
    hash_sha256 = Column(String(64), nullable=True, index=True)
    metadata_json = Column(JSON, nullable=True)

    camera = relationship("Camera", back_populates="evidence_items")
    event = relationship("Event")
    verifications = relationship(
        "EvidenceVerification",
        back_populates="evidence",
        cascade="all, delete-orphan",
        order_by="desc(EvidenceVerification.verified_at)",
    )

    @property
    def provenance(self) -> dict:
        """Structured provenance trail tracking source origin."""
        if self.provenance_json:
            return self.provenance_json
        return {
            "source_type": self.source_type,
            "source_reference": self.source_reference,
            "camera_id": self.camera_id,
            "event_id": self.event_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    __table_args__ = (
        Index("ix_evidence_camera_time", "camera_id", "timestamp_start", "timestamp_end"),
        Index("ix_evidence_verification", "verification_status"),
    )


class EvidenceVerification(Base):
    __tablename__ = "evidence_verifications"

    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(String(64), ForeignKey("evidence.evidence_id", ondelete="CASCADE"), nullable=False, index=True)
    verified_by_user_id = Column(String(64), ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True, index=True)
    status = Column(String(32), nullable=False)  # VERIFIED, REJECTED, INSUFFICIENT_EVIDENCE
    notes = Column(Text, nullable=True)
    reason = synonym("notes")
    provenance_snapshot_json = Column(JSON, nullable=True)
    verified_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    evidence = relationship("Evidence", back_populates="verifications")
    verified_by = relationship("User")
