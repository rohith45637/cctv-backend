from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from src.auth.dependencies import require_permission
from src.database.models import User
from src.database.session import get_db
from src.schemas.incident import Incident as IncidentSchema, IncidentCreate, IncidentUpdate
from src.schemas.threat import (
    Threat as ThreatSchema,
    ThreatCreate,
    ThreatUpdate,
    RiskReasoningResult,
    RiskReasoningExecuteRequest,
)
from src.threats.service import ThreatService

threats_router = APIRouter(prefix="/api/threats", tags=["Threats"])
incidents_router = APIRouter(prefix="/api/incidents", tags=["Incidents"])


# ==========================================
# Threats Endpoints
# ==========================================

@threats_router.get(
    "",
    response_model=List[ThreatSchema],
    status_code=status.HTTP_200_OK,
    summary="List active security threats",
)
def list_threats(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    severity_filter: Optional[str] = Query(default=None, alias="severity"),
    current_user: User = Depends(require_permission("threat.read")),
    db: Session = Depends(get_db),
):
    """List detected security threats with optional status and severity filtering."""
    threats = ThreatService.list_threats(
        db=db,
        skip=skip,
        limit=limit,
        status_filter=status_filter,
        severity_filter=severity_filter,
    )
    return [ThreatSchema.model_validate(t) for t in threats]


@threats_router.post(
    "/evaluate",
    response_model=Optional[ThreatSchema],
    status_code=status.HTTP_200_OK,
    summary="Evaluate event and generate threat if criteria are met",
)
def evaluate_event_threat(
    payload: ThreatCreate,
    current_user: User = Depends(require_permission("threat.manage")),
    db: Session = Depends(get_db),
):
    """Evaluates an event using the transparent risk engine. Escalates to Threat if risk >= 50."""
    threat = ThreatService.evaluate_and_create_threat(
        db=db,
        event_id=payload.event_id,
        force_escalate=payload.force_escalate,
    )
    if not threat:
        return None
    return ThreatSchema.model_validate(threat)


@threats_router.get(
    "/{threat_id}",
    response_model=ThreatSchema,
    status_code=status.HTTP_200_OK,
    summary="Get threat by threat_id",
)
def get_threat(
    threat_id: str,
    current_user: User = Depends(require_permission("threat.read")),
    db: Session = Depends(get_db),
):
    """Retrieve security threat by threat_id."""
    threat = ThreatService.get_threat(db=db, threat_id=threat_id)
    if not threat:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Threat '{threat_id}' not found")
    return ThreatSchema.model_validate(threat)


@threats_router.patch(
    "/{threat_id}",
    response_model=ThreatSchema,
    status_code=status.HTTP_200_OK,
    summary="Update threat status or incident association",
)
def update_threat(
    threat_id: str,
    payload: ThreatUpdate,
    current_user: User = Depends(require_permission("threat.manage")),
    db: Session = Depends(get_db),
):
    """Update threat status (NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, DISMISSED) or associate with incident."""
    updated = ThreatService.update_threat(
        db=db,
        threat_id=threat_id,
        status=payload.status,
        incident_id=payload.incident_id,
    )
    return ThreatSchema.model_validate(updated)


@threats_router.post(
    "/risk-reasoning",
    response_model=RiskReasoningResult,
    status_code=status.HTTP_200_OK,
    summary="Execute evidence-grounded risk reasoning for an event",
)
def execute_risk_reasoning(
    payload: RiskReasoningExecuteRequest,
    current_user: User = Depends(require_permission("threat.read")),
    db: Session = Depends(get_db),
):
    """
    Execute evidence-grounded risk reasoning following the chain:
    Observation -> Event -> Context -> Security Policy -> Risk -> Evidence -> Confidence

    Every high-risk result has explainable inputs. Evidence references point to
    real existing evidence records. Risk scores are never generated from
    unexplained or random values.

    Returns:
    - observation: The initial detection observation
    - context: Zone and camera context information
    - applicable_policies: Security policies checked
    - evidence_references: References to real evidence records
    - risk_score: Explainable risk score (0-100)
    - risk_level: Risk level classification
    - confidence: Overall confidence in the assessment
    - reasoning: Complete human-readable reasoning chain
    - evidence_verification_status: Verification status of evidence

    Requires 'threat.read' permission.
    """
    result = ThreatService.execute_evidence_grounded_risk_reasoning(
        db=db,
        request=payload,
        current_user_id=current_user.user_id,
    )
    return result


# ==========================================
# Incidents Endpoints
# ==========================================

@incidents_router.get(
    "",
    response_model=List[IncidentSchema],
    status_code=status.HTTP_200_OK,
    summary="List security incidents",
)
def list_incidents(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    current_user: User = Depends(require_permission("incident.read")),
    db: Session = Depends(get_db),
):
    """List security incidents with pagination and filtering."""
    incidents = ThreatService.list_incidents(
        db=db,
        skip=skip,
        limit=limit,
        status_filter=status_filter,
    )
    return [IncidentSchema.model_validate(inc) for inc in incidents]


@incidents_router.post(
    "",
    response_model=IncidentSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Create security incident and link originating threats",
)
def create_incident(
    payload: IncidentCreate,
    current_user: User = Depends(require_permission("incident.manage")),
    db: Session = Depends(get_db),
):
    """Atomically create a security incident and associate threats/events."""
    incident = ThreatService.create_incident(
        db=db,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        zone_id=payload.zone_id,
        primary_camera_id=payload.primary_camera_id,
        related_threat_ids=payload.related_threat_ids,
        related_event_ids=payload.related_event_ids,
    )
    return IncidentSchema.model_validate(incident)


@incidents_router.get(
    "/{incident_id}",
    response_model=IncidentSchema,
    status_code=status.HTTP_200_OK,
    summary="Get incident by incident_id",
)
def get_incident(
    incident_id: str,
    current_user: User = Depends(require_permission("incident.read")),
    db: Session = Depends(get_db),
):
    """Retrieve security incident by incident_id."""
    incident = ThreatService.get_incident(db=db, incident_id=incident_id)
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found")
    return IncidentSchema.model_validate(incident)


@incidents_router.patch(
    "/{incident_id}",
    response_model=IncidentSchema,
    status_code=status.HTTP_200_OK,
    summary="Update incident status, severity, or description",
)
def update_incident(
    incident_id: str,
    payload: IncidentUpdate,
    current_user: User = Depends(require_permission("incident.manage")),
    db: Session = Depends(get_db),
):
    """Update incident status (OPEN, INVESTIGATING, RESOLVED, CLOSED) or severity."""
    updated = ThreatService.update_incident(
        db=db,
        incident_id=incident_id,
        status=payload.status,
        severity=payload.severity,
        description=payload.description,
    )
    return IncidentSchema.model_validate(updated)
