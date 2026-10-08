from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict, field_validator
from src.utils.identifiers import validate_identifier

VALID_INVESTIGATION_STATUSES = {
    "PENDING",
    "ACTIVE",
    "PAUSED",
    "COMPLETED",
    "CANCELLED",
    "FAILED",
    "OPEN",
    "IN_PROGRESS",
    "CLOSED",
}

VALID_PRIORITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Investigation(BaseModel):
    investigation_id: str = Field(..., description="Unique investigation identifier (e.g., INV-001)")
    title: str = Field(..., description="Investigation dossier title")
    description: Optional[str] = Field(None, description="Detailed scope or trigger explanation")
    status: str = Field(default="PENDING", description="Lifecycle status (PENDING, ACTIVE, PAUSED, COMPLETED, CANCELLED, FAILED)")
    priority: str = Field(default="MEDIUM", description="Operational urgency (LOW, MEDIUM, HIGH, CRITICAL)")
    incident_id: Optional[str] = Field(None, description="Target incident identifier (e.g., INC-001)")
    trigger_incident_id: Optional[str] = Field(None, description="Triggering incident reference")
    trigger_event_id: Optional[str] = Field(None, description="Triggering event reference")
    trigger_threat_id: Optional[str] = Field(None, description="Triggering threat reference")
    assigned_user_id: Optional[str] = Field(None, description="Assigned lead investigator user_id")
    investigator_id: Optional[str] = Field(None, description="Investigator alias identifier")
    findings: Optional[str] = Field(None, description="Authoritative investigative conclusions and timeline")
    schema_version: str = Field(default="1.0", description="Contract schema version")
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: Optional[datetime] = None
    concluded_at: Optional[datetime] = None
    metadata_json: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @field_validator("investigation_id")
    @classmethod
    def check_investigation_id(cls, v: str) -> str:
        if not validate_identifier(v, "investigation_id") and not v.startswith("INV-"):
            raise ValueError(f"Invalid investigation_id format '{v}'. Must start with 'INV-'")
        return v

    model_config = ConfigDict(
        from_attributes=True,
        json_encoders={datetime: lambda dt: dt.isoformat()},
        populate_by_name=True,
    )


class InvestigationCreate(BaseModel):
    title: str
    description: Optional[str] = None
    investigation_id: Optional[str] = None
    priority: str = "MEDIUM"
    incident_id: Optional[str] = None
    trigger_incident_id: Optional[str] = None
    trigger_event_id: Optional[str] = None
    trigger_threat_id: Optional[str] = None
    assigned_user_id: Optional[str] = None
    investigator_id: Optional[str] = None
    status: str = "PENDING"
    findings: Optional[str] = None
    schema_version: str = "1.0"
    metadata_json: Optional[Dict[str, Any]] = None

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: str) -> str:
        v_upper = v.upper()
        if v_upper not in VALID_PRIORITIES:
            raise ValueError(f"Invalid priority '{v}'. Must be one of: {', '.join(sorted(VALID_PRIORITIES))}")
        return v_upper

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        v_upper = v.upper()
        if v_upper not in VALID_INVESTIGATION_STATUSES:
            raise ValueError(f"Invalid status '{v}'. Must be one of: {', '.join(sorted(VALID_INVESTIGATION_STATUSES))}")
        return v_upper


class InvestigationUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_user_id: Optional[str] = None
    findings: Optional[str] = None
    metadata_json: Optional[Dict[str, Any]] = None


class ObservedFact(BaseModel):
    """An observed fact grounded in authoritative evidence."""
    fact_id: str = Field(..., description="Unique identifier for this observed fact")
    description: str = Field(..., description="Human-readable description of the observed fact")
    evidence_references: List[str] = Field(default_factory=list, description="List of evidence_id values supporting this fact")
    event_references: List[str] = Field(default_factory=list, description="List of event_id values supporting this fact")
    camera_id: Optional[str] = Field(None, description="Camera that captured the observation")
    timestamp: Optional[datetime] = Field(None, description="When the observation occurred")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence in this observed fact")
    verification_status: str = Field(default="UNVERIFIED", description="Verification status of supporting evidence")

    model_config = ConfigDict(from_attributes=True)


class Inference(BaseModel):
    """An inference drawn from observed facts with explicit reasoning."""
    inference_id: str = Field(..., description="Unique identifier for this inference")
    description: str = Field(..., description="Human-readable description of the inference")
    supported_by_facts: List[str] = Field(default_factory=list, description="List of fact_id values this inference depends on")
    reasoning: str = Field(..., description="Explicit reasoning chain from facts to inference")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence in this inference")
    inference_type: str = Field(default="LOGICAL", description="Type of inference: LOGICAL, TEMPORAL, BEHAVIORAL, CORRELATIONAL")

    model_config = ConfigDict(from_attributes=True)


class UnknownInformation(BaseModel):
    """Explicitly declared unknown information with reason for absence."""
    unknown_id: str = Field(..., description="Unique identifier for this unknown")
    description: str = Field(..., description="What is unknown and why it matters")
    reason: str = Field(..., description="Why this information is unknown (e.g., 'no camera coverage', 'evidence not retained', 'outside retention window')")
    impact: str = Field(default="UNKNOWN", description="Impact on investigation: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN")
    potential_sources: List[str] = Field(default_factory=list, description="Potential sources that could resolve this unknown")

    model_config = ConfigDict(from_attributes=True)


class InvestigationExecutionResult(BaseModel):
    """
    Complete autonomous investigation result with strict separation of:
    1. OBSERVED FACTS - grounded in authoritative evidence
    2. INFERENCES - logically derived from facts with explicit reasoning
    3. UNKNOWN INFORMATION - explicitly declared gaps
    """
    investigation_id: str
    incident_id: Optional[str] = None
    trigger_event_id: Optional[str] = None
    executed_at: datetime = Field(default_factory=utc_now)
    executed_by: str = Field(default="AUTONOMOUS_INVESTIGATION_ENGINE")

    # Strict separation as required
    observed_facts: List[ObservedFact] = Field(default_factory=list)
    inferences: List[Inference] = Field(default_factory=list)
    unknown_information: List[UnknownInformation] = Field(default_factory=list)

    # Overall assessment
    overall_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    conclusion: str = Field(default="", description="Final investigation conclusion or 'I don\\'t know — insufficient evidence.'")
    evidence_sufficiency: str = Field(default="UNKNOWN", description="SUFFICIENT, INSUFFICIENT, PARTIAL, UNKNOWN")

    # Metadata
    cameras_analyzed: List[str] = Field(default_factory=list)
    zones_analyzed: List[str] = Field(default_factory=list)
    policies_checked: List[str] = Field(default_factory=list)
    evidence_collected: List[str] = Field(default_factory=list)
    cross_camera_tracks: List[Dict[str, Any]] = Field(default_factory=list)
    timeline_events: List[Dict[str, Any]] = Field(default_factory=list)
    schema_version: str = Field(default="1.0")

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class InvestigationExecuteRequest(BaseModel):
    """Request to execute autonomous investigation from an incident or event."""
    investigation_id: str
    incident_id: Optional[str] = None
    trigger_event_id: Optional[str] = None
    lookback_hours: int = Field(default=24, ge=1, le=168, description="Hours to look back for related events")
    cross_camera: bool = Field(default=True, description="Enable cross-camera entity tracking")
    include_zones: bool = Field(default=True, description="Check relevant zone contexts and policies")
    include_evidence: bool = Field(default=True, description="Collect and cross-check evidence")
    min_confidence: float = Field(default=0.4, ge=0.0, le=1.0, description="Minimum confidence for observed facts")
