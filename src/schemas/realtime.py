from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class RealtimeEvent(BaseModel):
    """
    Standardized payload format for WebSocket streaming and event-bus publication.
    """
    event_id: str = Field(..., description="Unique event identifier")
    topic: str = Field(..., description="Channel / Topic e.g. security.events, security.threats")
    event_type: str = Field(..., description="Action/type e.g. EVENT_DETECTED, THREAT_ESCALATED")
    source: str = Field(default="backend-security-core", description="Originating service")
    payload: Dict[str, Any] = Field(..., description="Structured event payload")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Emission timestamp")
    schema_version: str = Field(default="1.0", description="Contract schema version")

    model_config = ConfigDict(from_attributes=True)
