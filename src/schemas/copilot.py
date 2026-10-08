from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class CopilotQueryRequest(BaseModel):
    """
    Contract payload for AI Security Copilot queries.
    Enforces bounded, authoritative context filters and user query prompt.
    """
    query: str = Field(..., min_length=1, description="Security inquiry prompt or natural question")
    camera_id: Optional[str] = Field(None, description="Optional target camera ID context")
    zone_id: Optional[str] = Field(None, description="Optional target zone ID context")
    event_id: Optional[str] = Field(None, description="Optional target event ID context")
    threat_id: Optional[str] = Field(None, description="Optional target threat ID context")
    incident_id: Optional[str] = Field(None, description="Optional target incident ID context")
    investigation_id: Optional[str] = Field(None, description="Optional target investigation ID context")
    schema_version: str = Field(default="1.0", description="Contract schema version")

    model_config = ConfigDict(from_attributes=True)


class CopilotQueryResponse(BaseModel):
    """
    Authoritative bounded response returned to Frontend Security Copilot.
    Grounded strictly in backend facts, verifiable evidence, and context memory.
    """
    query: str = Field(..., description="Original input query prompt")
    answer: str = Field(..., description="Fact-grounded synthesis from authoritative records")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Authoritative confidence score")
    status: str = Field(..., description="CONFIRMED | UNKNOWN | INSUFFICIENT_EVIDENCE")
    evidence_references: List[str] = Field(default_factory=list, description="Referenced evidence item IDs")
    event_references: List[str] = Field(default_factory=list, description="Referenced event IDs")
    threat_references: List[str] = Field(default_factory=list, description="Referenced threat IDs")
    incident_references: List[str] = Field(default_factory=list, description="Referenced incident IDs")
    investigation_references: List[str] = Field(default_factory=list, description="Referenced investigation IDs")
    memory_references: List[str] = Field(default_factory=list, description="Referenced security memory IDs")
    limitations: List[str] = Field(default_factory=list, description="Identified limitations or unverified warnings")
    schema_version: str = Field(default="1.0", description="Contract schema version")

    model_config = ConfigDict(from_attributes=True)
