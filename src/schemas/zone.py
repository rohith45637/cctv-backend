from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict


class Zone(BaseModel):
    zone_id: str = Field(..., description="Unique zone identifier (e.g., ZONE-01)")
    name: str = Field(..., description="Human-readable zone label")
    description: Optional[str] = Field(None, description="Detailed physical boundary description")
    risk_level: str = Field(default="MEDIUM", description="Risk baseline (LOW, MEDIUM, HIGH, CRITICAL)")
    is_active: bool = Field(default=True, description="Active status")
    schema_version: str = Field(default="1.0", description="Contract schema version")
    metadata_json: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ZoneCreate(BaseModel):
    zone_id: str
    name: str
    description: Optional[str] = None
    risk_level: str = "MEDIUM"
    is_active: bool = True
    schema_version: str = "1.0"
    camera_ids: Optional[List[str]] = None
    metadata_json: Optional[Dict[str, Any]] = None
