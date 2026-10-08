from datetime import datetime, timezone
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, field_validator
from src.utils.identifiers import validate_identifier

SUPPORTED_MEMORY_TYPES = {
    "EVENT_CONTEXT",
    "THREAT_CONTEXT",
    "INCIDENT_CONTEXT",
    "CAMERA_CONTEXT",
    "ZONE_CONTEXT",
    "POLICY_CONTEXT",
    "INVESTIGATION_CONTEXT",
    "KNOWN_PERSON",
    "VEHICLE_PLATE",
    "PATTERN",
    "ANOMALY_BASELINE",
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SecurityMemory(BaseModel):
    memory_id: str = Field(..., description="Unique memory identifier (e.g., MEM-001)")
    memory_type: str = Field(..., description="Context type (EVENT_CONTEXT, THREAT_CONTEXT, etc.)")
    entity_id: Optional[str] = Field(None, description="Entity identifier linked with memory")
    camera_id: Optional[str] = Field(None, description="Camera identifier linked with memory")
    zone_id: Optional[str] = Field(None, description="Zone identifier linked with memory")
    event_id: Optional[str] = Field(None, description="Event identifier linked with memory")
    incident_id: Optional[str] = Field(None, description="Incident identifier linked with memory")
    content: Optional[str] = Field(None, description="Authoritative context payload/narrative")
    description: Optional[str] = Field(None, description="Profile summary and behavioral baseline")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Baseline confidence")
    source_reference: Optional[str] = Field(None, description="Authoritative source reference")
    identifier_value: Optional[str] = Field(None, description="Primary search key e.g. plate number, badge ID")
    observations_count: int = Field(default=1, description="Number of independent historical observations")
    last_seen_at: datetime = Field(default_factory=utc_now)
    expires_at: Optional[datetime] = Field(None, description="Optional TTL expiration timestamp")
    schema_version: str = Field(default="1.0", description="Contract schema version")
    metadata_json: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @field_validator("memory_id")
    @classmethod
    def check_memory_id(cls, v: str) -> str:
        if not validate_identifier(v, "memory_id") and not v.startswith("MEM-"):
            raise ValueError(f"Invalid memory_id format '{v}'. Must start with 'MEM-'")
        return v

    @field_validator("memory_type")
    @classmethod
    def check_memory_type(cls, v: str) -> str:
        v_upper = v.upper()
        if v_upper not in SUPPORTED_MEMORY_TYPES:
            raise ValueError(f"Invalid memory_type '{v}'. Must be one of: {', '.join(sorted(SUPPORTED_MEMORY_TYPES))}")
        return v_upper

    model_config = ConfigDict(
        from_attributes=True,
        json_encoders={datetime: lambda dt: dt.isoformat()},
    )


class SecurityMemoryCreate(BaseModel):
    memory_id: Optional[str] = None
    memory_type: str
    entity_id: Optional[str] = None
    camera_id: Optional[str] = None
    zone_id: Optional[str] = None
    event_id: Optional[str] = None
    incident_id: Optional[str] = None
    content: Optional[str] = None
    description: Optional[str] = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source_reference: Optional[str] = None
    identifier_value: Optional[str] = None
    observations_count: int = 1
    last_seen_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    schema_version: str = "1.0"
    metadata_json: Optional[Dict[str, Any]] = None

    @field_validator("memory_type")
    @classmethod
    def check_memory_type(cls, v: str) -> str:
        v_upper = v.upper()
        if v_upper not in SUPPORTED_MEMORY_TYPES:
            raise ValueError(f"Invalid memory_type '{v}'. Must be one of: {', '.join(sorted(SUPPORTED_MEMORY_TYPES))}")
        return v_upper


class SecurityMemoryUpdate(BaseModel):
    content: Optional[str] = None
    description: Optional[str] = None
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    source_reference: Optional[str] = None
    expires_at: Optional[datetime] = None
    metadata_json: Optional[Dict[str, Any]] = None
