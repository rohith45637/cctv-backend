from datetime import datetime, timezone
from typing import Optional, Any, Dict
from pydantic import BaseModel, Field, ConfigDict, field_validator
from src.utils.identifiers import validate_identifier


class Event(BaseModel):
    """
    Common Event Schema (Contract v1.0).
    Guarantees strict standardization across AI Video, Event Bus, and Security Core.
    """
    event_id: str = Field(..., description="Unique stable event identifier (e.g., EVT-XXXX)")
    camera_id: str = Field(..., description="Unique camera identifier associated with event (e.g., CAM-XXXX)")
    timestamp: datetime = Field(..., description="Event detection timestamp (ISO-8601)")
    event_type: str = Field(..., min_length=2, max_length=100, description="Categorical event type (e.g., INTRUSION, PERSON_DETECTED)")
    entity_id: Optional[str] = Field(None, description="Optional entity identifier (e.g., ENT-XXXX)")
    zone_id: Optional[str] = Field(None, description="Optional zone identifier (e.g., ZONE-XXXX)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence score between 0.0 and 1.0")
    evidence_id: Optional[str] = Field(None, description="Optional evidence identifier (e.g., EVD-XXXX)")
    source: str = Field(default="ai-video", description="System or engine reporting the event")
    status: str = Field(default="NEW", description="Processing lifecycle status (NEW, ACKNOWLEDGED, VERIFIED, DISMISSED)")
    schema_version: str = Field(default="1.0", description="Contract schema version")
    metadata_json: Optional[Dict[str, Any]] = None

    @field_validator("event_id")
    @classmethod
    def check_event_id(cls, v: str) -> str:
        if not validate_identifier(v, "event_id") and not v.startswith("EVT-"):
            raise ValueError(f"Invalid event_id format '{v}'. Must start with 'EVT-'")
        return v

    @field_validator("camera_id")
    @classmethod
    def check_camera_id(cls, v: str) -> str:
        if not validate_identifier(v, "camera_id") and not v.startswith("CAM-"):
            raise ValueError(f"Invalid camera_id format '{v}'. Must start with 'CAM-'")
        return v

    model_config = ConfigDict(
        from_attributes=True,
        json_encoders={datetime: lambda dt: dt.isoformat()},
        populate_by_name=True,
    )


class EventCreate(BaseModel):
    camera_id: str
    event_type: str
    timestamp: Optional[datetime] = None
    entity_id: Optional[str] = None
    zone_id: Optional[str] = None
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence_id: Optional[str] = None
    source: str = "ai-video"
    status: str = "NEW"
    schema_version: str = "1.0"
    metadata_json: Optional[Dict[str, Any]] = None


class EventIngestResponse(BaseModel):
    event: Event
    status: str = Field(default="INGESTED", description="Ingestion result: INGESTED or DUPLICATE")
    deduplicated: bool = Field(default=False, description="True if identical or temporal duplicate was detected")
    message: str = Field(default="Event ingested successfully")
