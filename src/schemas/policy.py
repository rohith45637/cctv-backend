from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class SecurityPolicy(BaseModel):
    policy_id: str = Field(..., description="Unique policy identifier (e.g., POL-01)")
    name: str = Field(..., description="Human-readable policy name")
    description: Optional[str] = Field(None, description="Detailed policy description")
    zone_id: Optional[str] = Field(None, description="Target zone identifier")
    policy_type: str = Field(..., description="INTRUSION, LOITERING, TAILGATING, ACCESS_CONTROL")
    severity: str = Field(default="MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")
    rules_json: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Configurable rule parameters")
    is_active: bool = Field(default=True, description="Enforcement status")
    schema_version: str = Field(default="1.0", description="Contract schema version")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class SecurityPolicyCreate(BaseModel):
    policy_id: str
    name: str
    description: Optional[str] = None
    zone_id: Optional[str] = None
    policy_type: str
    severity: str = "MEDIUM"
    rules_json: Optional[Dict[str, Any]] = None
    is_active: bool = True
    schema_version: str = "1.0"
