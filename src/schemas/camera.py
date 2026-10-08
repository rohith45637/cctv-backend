from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class Camera(BaseModel):
    camera_id: str = Field(..., description="Unique camera identifier (e.g., CAM-01)")
    name: str = Field(..., description="Human-readable camera label")
    stream_url: Optional[str] = Field(None, description="RTSP / HLS / WebRTC stream URL")
    ip_address: Optional[str] = Field(None, description="IP address of camera device")
    location_description: Optional[str] = Field(None, description="Physical location notes")
    status: str = Field(default="ONLINE", description="ONLINE, OFFLINE, DEGRADED, MAINTENANCE")
    is_active: bool = Field(default=True, description="Administrative operational status")
    schema_version: str = Field(default="1.0", description="Contract schema version")
    metadata_json: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class CameraCreate(BaseModel):
    camera_id: str
    name: str
    stream_url: Optional[str] = None
    ip_address: Optional[str] = None
    location_description: Optional[str] = None
    status: str = "ONLINE"
    is_active: bool = True
    schema_version: str = "1.0"
    metadata_json: Optional[Dict[str, Any]] = None


class CameraUpdate(BaseModel):
    name: Optional[str] = None
    stream_url: Optional[str] = None
    ip_address: Optional[str] = None
    location_description: Optional[str] = None
    status: Optional[str] = None
    is_active: Optional[bool] = None
    metadata_json: Optional[Dict[str, Any]] = None
