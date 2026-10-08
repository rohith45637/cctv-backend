from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict


class Incident(BaseModel):
    incident_id: str = Field(..., description="Unique incident identifier (e.g., INC-001)")
    title: str = Field(..., description="Incident operational title")
    description: Optional[str] = Field(None, description="Detailed incident operational narrative")
    severity: str = Field(default="P2", description="Incident severity level (P1, P2, P3, P4)")
    status: str = Field(default="OPEN", description="OPEN, INVESTIGATING, RESOLVED, CLOSED")
    lead_analyst_id: Optional[str] = Field(None, description="Assigned lead security analyst user_id")
    zone_id: Optional[str] = Field(None, description="Primary zone where incident occurred")
    primary_camera_id: Optional[str] = Field(None, description="Primary camera covering the incident")
    threat_id: Optional[str] = Field(None, description="Originating threat identifier")
    related_threat_ids: Optional[List[str]] = Field(default_factory=list, description="All associated threat identifiers")
    related_event_ids: Optional[List[str]] = Field(default_factory=list, description="All associated event identifiers")
    opened_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    schema_version: str = Field(default="1.0", description="Contract schema version")
    metadata_json: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=2, max_length=255)
    description: Optional[str] = None
    severity: str = Field(default="P2", description="P1, P2, P3, P4")
    zone_id: Optional[str] = None
    primary_camera_id: Optional[str] = None
    related_threat_ids: List[str] = Field(default_factory=list)
    related_event_ids: List[str] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    status: Optional[str] = Field(None, description="OPEN, INVESTIGATING, RESOLVED, CLOSED")
    severity: Optional[str] = Field(None, description="P1, P2, P3, P4")
    description: Optional[str] = None
