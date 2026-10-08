from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict


class Threat(BaseModel):
    threat_id: str = Field(..., description="Unique threat identifier (e.g., THR-001)")
    title: str = Field(..., description="Headline of detected security threat")
    description: Optional[str] = Field(None, description="Detailed explanation of detected threat and risk factors")
    severity: str = Field(default="MEDIUM", description="Threat severity: HIGH, MEDIUM, LOW, UNKNOWN")
    status: str = Field(default="NEW", description="Status: NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, DISMISSED")
    risk_score: float = Field(default=0.0, description="Calculated explainable risk score (0-100)")
    reason: Optional[str] = Field(None, description="Human-readable transparent risk factors")
    camera_id: Optional[str] = Field(None, description="Camera associated with threat detection")
    zone_id: Optional[str] = Field(None, description="Zone associated with threat detection")
    event_id: Optional[str] = Field(None, description="Triggering event identifier")
    incident_id: Optional[str] = Field(None, description="Linked incident identifier if escalated")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Detection confidence score")
    schema_version: str = Field(default="1.0", description="Contract schema version")
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata_json: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ThreatCreate(BaseModel):
    event_id: str = Field(..., description="Event identifier to evaluate for threat creation")
    force_escalate: bool = Field(default=False, description="Force create threat regardless of score threshold")


class ThreatUpdate(BaseModel):
    status: Optional[str] = Field(None, description="NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, DISMISSED")
    incident_id: Optional[str] = Field(None, description="Associate threat with incident identifier")


class RiskReasoningObservation(BaseModel):
    """An observation that feeds into risk reasoning."""
    observation_id: str = Field(..., description="Unique identifier for this observation")
    event_id: Optional[str] = Field(None, description="Source event identifier")
    camera_id: Optional[str] = Field(None, description="Camera that captured the observation")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    description: str = Field(..., description="What was observed")
    entity_type: Optional[str] = Field(None, description="Type of entity observed (PERSON, VEHICLE, OBJECT)")
    entity_id: Optional[str] = Field(None, description="Tracked entity identifier")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Observation confidence")
    source: str = Field(default="AI_VIDEO", description="Source of observation")

    model_config = ConfigDict(from_attributes=True)


class RiskReasoningContext(BaseModel):
    """Contextual information for risk reasoning."""
    zone_id: Optional[str] = Field(None, description="Zone where observation occurred")
    zone_risk_level: Optional[str] = Field(None, description="Risk level of the zone")
    zone_name: Optional[str] = Field(None, description="Name of the zone")
    camera_id: Optional[str] = Field(None, description="Camera context")
    camera_location: Optional[str] = Field(None, description="Camera location description")
    time_of_day: Optional[str] = Field(None, description="Time context (e.g., 'business_hours', 'after_hours')")
    active_policies: List[str] = Field(default_factory=list, description="Active policy IDs in this context")
    historical_baseline: Optional[str] = Field(None, description="Behavioral baseline reference")

    model_config = ConfigDict(from_attributes=True)


class RiskReasoningPolicy(BaseModel):
    """Security policy applicable to the risk assessment."""
    policy_id: str = Field(..., description="Policy identifier")
    name: str = Field(..., description="Policy name")
    policy_type: str = Field(..., description="Policy type (e.g., PERIMETER, ACCESS_CONTROL, LOITERING)")
    severity: str = Field(..., description="Policy severity: CRITICAL, HIGH, MEDIUM, LOW")
    description: Optional[str] = Field(None, description="Policy description")
    triggered: bool = Field(default=False, description="Whether this policy was triggered")
    trigger_details: Optional[str] = Field(None, description="Details on how policy was triggered")

    model_config = ConfigDict(from_attributes=True)


class RiskReasoningEvidence(BaseModel):
    """Evidence reference for risk reasoning."""
    evidence_id: str = Field(..., description="Evidence identifier")
    camera_id: Optional[str] = Field(None, description="Camera that captured evidence")
    timestamp_start: Optional[datetime] = None
    timestamp_end: Optional[datetime] = None
    verification_status: str = Field(default="UNVERIFIED", description="Evidence verification status")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Evidence confidence")
    source_type: str = Field(default="AI_VIDEO", description="Evidence source type")
    relevance: str = Field(..., description="Why this evidence is relevant to the risk assessment")

    model_config = ConfigDict(from_attributes=True)


class RiskReasoningResult(BaseModel):
    """
    Complete evidence-grounded risk reasoning result.
    Follows: Observation -> Event -> Context -> Security Policy -> Risk -> Evidence -> Confidence
    Every high-risk result must have explainable inputs.
    """
    reasoning_id: str = Field(..., description="Unique identifier for this risk reasoning")
    event_id: Optional[str] = Field(None, description="Primary event being assessed")
    threat_id: Optional[str] = Field(None, description="Associated threat if escalated")
    incident_id: Optional[str] = Field(None, description="Associated incident if escalated")
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    executed_by: str = Field(default="RISK_REASONING_ENGINE")

    # Chain of reasoning components
    observation: RiskReasoningObservation
    context: RiskReasoningContext
    applicable_policies: List[RiskReasoningPolicy] = Field(default_factory=list)
    evidence_references: List[RiskReasoningEvidence] = Field(default_factory=list)

    # Risk assessment output
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Calculated risk score (0-100)")
    risk_level: str = Field(default="UNKNOWN", description="Risk level: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Overall confidence in risk assessment")

    # Explanation and verification
    reasoning: str = Field(..., description="Complete human-readable reasoning chain")
    evidence_verification_status: str = Field(default="UNVERIFIED", description="Overall evidence verification: VERIFIED, PARTIAL, UNVERIFIED, REJECTED, INSUFFICIENT_EVIDENCE")
    verification_notes: Optional[str] = Field(None, description="Notes on evidence verification status")

    # Decision support
    recommended_actions: List[str] = Field(default_factory=list, description="Recommended actions based on risk level")
    escalation_warranted: bool = Field(default=False, description="Whether escalation to threat/incident is warranted")

    schema_version: str = Field(default="1.0")

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class RiskReasoningExecuteRequest(BaseModel):
    """Request to execute evidence-grounded risk reasoning on an event."""
    event_id: str = Field(..., description="Event to evaluate")
    include_evidence: bool = Field(default=True, description="Include evidence in reasoning")
    include_historical_context: bool = Field(default=True, description="Include historical/behavioral context")
    force_reasoning: bool = Field(default=False, description="Force reasoning even if confidence is low")
