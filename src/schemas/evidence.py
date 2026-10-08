from datetime import datetime
from typing import Optional, Any, Dict, List
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator
from src.utils.identifiers import validate_identifier


class EvidenceVerificationResponse(BaseModel):
    """Authoritative evidence verification audit record."""
    id: Optional[int] = None
    evidence_id: str
    verified_by_user_id: Optional[str] = None
    status: str
    notes: Optional[str] = None
    provenance_snapshot_json: Optional[Dict[str, Any]] = None
    verified_at: datetime

    model_config = ConfigDict(from_attributes=True)


class Evidence(BaseModel):
    """
    Common Evidence Schema (Contract v1.0).
    Guarantees strict evidentiary integrity and reference tracking.
    """
    evidence_id: str = Field(..., description="Unique stable evidence identifier (e.g., EVD-XXXX)")
    camera_id: str = Field(..., description="Camera identifier supplying footage (e.g., CAM-XXXX)")
    event_id: Optional[str] = Field(None, description="Optional associated event identifier (e.g., EVT-XXXX)")
    timestamp_start: datetime = Field(..., description="Evidence recording start timestamp (ISO-8601)")
    timestamp_end: datetime = Field(..., description="Evidence recording end timestamp (ISO-8601)")
    source_reference: str = Field(..., min_length=3, description="Authoritative stream or feed reference URL/RTSP")
    clip_reference: str = Field(..., min_length=3, description="Persistent storage reference path or object key")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Verification confidence score")
    verification_status: str = Field(default="UNVERIFIED", description="Evidentiary status (UNVERIFIED, VERIFIED, REJECTED, INSUFFICIENT_EVIDENCE)")
    source_type: str = Field(default="AI_VIDEO", description="Source type (AI_VIDEO, CAMERA, UPLOAD, SYSTEM)")
    provenance: Optional[Dict[str, Any]] = Field(default=None, description="Structured provenance trail")
    storage_url: Optional[str] = None
    hash_sha256: Optional[str] = None
    metadata_json: Optional[Dict[str, Any]] = None
    schema_version: str = Field(default="1.0", description="Contract schema version")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    verifications: Optional[List[EvidenceVerificationResponse]] = None

    @field_validator("evidence_id")
    @classmethod
    def check_evidence_id(cls, v: str) -> str:
        if not validate_identifier(v, "evidence_id") and not v.startswith("EVD-"):
            raise ValueError(f"Invalid evidence_id format '{v}'. Must start with 'EVD-'")
        return v

    @field_validator("camera_id")
    @classmethod
    def check_camera_id(cls, v: str) -> str:
        if not validate_identifier(v, "camera_id") and not v.startswith("CAM-"):
            raise ValueError(f"Invalid camera_id format '{v}'. Must start with 'CAM-'")
        return v

    @model_validator(mode="after")
    def validate_time_range(self) -> "Evidence":
        if self.timestamp_end < self.timestamp_start:
            raise ValueError("timestamp_end cannot precede timestamp_start")
        return self

    model_config = ConfigDict(
        from_attributes=True,
        json_encoders={datetime: lambda dt: dt.isoformat()},
        populate_by_name=True,
    )


class EvidenceCreate(BaseModel):
    evidence_id: Optional[str] = None
    camera_id: str
    event_id: Optional[str] = None
    timestamp_start: datetime
    timestamp_end: datetime
    source_reference: str
    clip_reference: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    verification_status: str = "UNVERIFIED"
    source_type: str = "AI_VIDEO"
    schema_version: str = "1.0"
    storage_url: Optional[str] = None
    hash_sha256: Optional[str] = None
    metadata_json: Optional[Dict[str, Any]] = None

    @field_validator("verification_status")
    @classmethod
    def reject_initial_verified_status(cls, v: str) -> str:
        if v.upper() != "UNVERIFIED":
            raise ValueError("New evidence cannot be created in verified status; initial status must be UNVERIFIED")
        return "UNVERIFIED"

    @model_validator(mode="after")
    def validate_time_range(self) -> "EvidenceCreate":
        if self.timestamp_end < self.timestamp_start:
            raise ValueError("timestamp_end cannot precede timestamp_start")
        return self


class EvidenceVerifyRequest(BaseModel):
    status: str = Field(..., description="Target status: VERIFIED, REJECTED, INSUFFICIENT_EVIDENCE")
    notes: Optional[str] = Field(None, description="Verification notes or reason")
    reason: Optional[str] = Field(None, description="Alias for notes")

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        valid_statuses = {"VERIFIED", "REJECTED", "INSUFFICIENT_EVIDENCE"}
        v_upper = v.upper()
        if v_upper not in valid_statuses:
            raise ValueError(f"Invalid verification status '{v}'. Must be one of: {', '.join(sorted(valid_statuses))}")
        return v_upper


class EvidenceProvenanceResponse(BaseModel):
    evidence_id: str
    provenance: Dict[str, Any]
    verification_status: str
    verifications_count: int = 0
    created_at: Optional[datetime] = None
