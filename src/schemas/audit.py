from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class AuditLogResponse(BaseModel):
    """
    Authoritative audit record entry.
    All sensitive credentials and secrets are strictly redacted.
    """
    id: int
    user_id: Optional[int] = None
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    ip_address: Optional[str] = None
    status: str = "SUCCESS"
    details_json: Optional[Dict[str, Any]] = None
    created_at: datetime
    schema_version: str = Field(default="1.0", description="Contract schema version")

    model_config = ConfigDict(from_attributes=True)
