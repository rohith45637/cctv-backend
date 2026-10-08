from typing import Optional, Any, Dict
from pydantic import BaseModel, Field, ConfigDict, field_validator
from src.schemas.event import Event
from src.schemas.evidence import EvidenceCreate

ALLOWED_AI_VIDEO_SOURCES = {"AI_VIDEO", "DEMO", "IMPORTED", "ai-video"}


class AIVideoEventIngestRequest(BaseModel):
    """
    Contract payload sent by AI Video Intelligence to Backend Security Core.
    Embeds the canonical Event contract and explicit operational source mode.
    """
    event: Event
    source: str = Field(default="AI_VIDEO", description="Explicit source origin: AI_VIDEO, DEMO, IMPORTED")
    validate_evidence: bool = Field(default=True, description="Enforce that referenced evidence_id exists in registry")
    schema_version: str = Field(default="1.0", description="Contract schema version")

    @field_validator("source")
    @classmethod
    def validate_source(cls, v: str) -> str:
        v_upper = v.upper()
        if v_upper not in ALLOWED_AI_VIDEO_SOURCES and v not in ALLOWED_AI_VIDEO_SOURCES:
            raise ValueError(f"Invalid AI Video source '{v}'. Must be one of: {', '.join(sorted(ALLOWED_AI_VIDEO_SOURCES))}")
        return v_upper

    model_config = ConfigDict(from_attributes=True)


class AIVideoEventWithEvidenceRequest(BaseModel):
    """
    Compound packet from AI Video emitting an event alongside raw recorded clip evidence.
    Evidence is strictly ingested as UNVERIFIED with origin provenance.
    """
    event: Event
    evidence: EvidenceCreate
    source: str = Field(default="AI_VIDEO", description="Source mode: AI_VIDEO, DEMO, IMPORTED")
    schema_version: str = Field(default="1.0", description="Contract schema version")

    @field_validator("source")
    @classmethod
    def validate_source(cls, v: str) -> str:
        v_upper = v.upper()
        if v_upper not in ALLOWED_AI_VIDEO_SOURCES and v not in ALLOWED_AI_VIDEO_SOURCES:
            raise ValueError(f"Invalid AI Video source '{v}'. Must be one of: {', '.join(sorted(ALLOWED_AI_VIDEO_SOURCES))}")
        return v_upper

    model_config = ConfigDict(from_attributes=True)


class AIVideoContractStatus(BaseModel):
    """Integration gateway health and contract compatibility metadata."""
    module: str = "AI Video Integration Gateway"
    status: str = "ONLINE"
    schema_version: str = "1.0"
    supported_sources: list[str] = list(sorted(ALLOWED_AI_VIDEO_SOURCES))
    idempotency_window_seconds: int = 10
