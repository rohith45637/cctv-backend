from typing import Optional, Union, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from src.auth.dependencies import require_permission
from src.database.models import User, Camera, Zone, Evidence
from src.database.session import get_db
from src.events.service import EventService
from src.evidence.service import EvidenceService
from src.schemas.event import Event as EventSchema, EventIngestResponse
from src.schemas.ai_video import (
    AIVideoEventIngestRequest,
    AIVideoEventWithEvidenceRequest,
    AIVideoContractStatus,
)
from src.audit.service import AuditService

router = APIRouter(prefix="/api/integrations/ai-video", tags=["AI Video Integration"])


@router.post(
    "/events",
    response_model=EventIngestResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest structured event from AI Video Intelligence via Contract",
)
def ingest_ai_video_event(
    payload: Union[AIVideoEventIngestRequest, EventSchema],
    dedup_window_seconds: int = Query(default=10, ge=0, le=300),
    current_user: User = Depends(require_permission("event.read")),
    db: Session = Depends(get_db),
):
    """
    Authoritative integration gateway contract for AI Video Intelligence.
    Validates:
    - camera_id existence (unknown camera -> 404 rejection)
    - zone_id existence (unknown zone -> 404 rejection)
    - confidence bounds (0.0 to 1.0)
    - evidence references (nonexistent evidence -> 400 rejection)
    - explicit source mode (AI_VIDEO, DEMO, IMPORTED)
    - event_id idempotency and temporal deduplication.
    """
    # Normalize input
    if isinstance(payload, AIVideoEventIngestRequest):
        event_obj = payload.event
        source_mode = payload.source
        validate_evd = payload.validate_evidence
    else:
        event_obj = payload
        source_mode = payload.source or "AI_VIDEO"
        validate_evd = True

    # 1. Authoritative camera registry check
    camera = db.query(Camera).filter(
        Camera.camera_id == event_obj.camera_id,
        Camera.is_deleted == False,
    ).first()
    if not camera:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Camera with id '{event_obj.camera_id}' does not exist in registry",
        )

    # 2. Authoritative zone registry check
    if event_obj.zone_id:
        zone = db.query(Zone).filter(
            Zone.zone_id == event_obj.zone_id,
            Zone.is_deleted == False,
        ).first()
        if not zone:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Zone with id '{event_obj.zone_id}' does not exist in registry",
            )

    # 3. Authoritative evidence reference check if specified
    if validate_evd and event_obj.evidence_id:
        evd = db.query(Evidence).filter(
            Evidence.evidence_id == event_obj.evidence_id,
            Evidence.is_deleted == False,
        ).first()
        if not evd:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Referenced evidence '{event_obj.evidence_id}' does not exist in authoritative backend",
            )

    # 4. Delegate to authoritative EventService with idempotency
    event_model, deduplicated, message = EventService.ingest_event(
        db=db,
        event_data=event_obj,
        dedup_window_seconds=dedup_window_seconds,
    )

    AuditService.record_action(
        db=db,
        action="AI_VIDEO_EVENT_INGESTED",
        resource_type="ai_video",
        resource_id=event_model.event_id,
        user_id=current_user.id,
        status="SUCCESS",
        details={"source_mode": source_mode, "deduplicated": deduplicated, "camera_id": event_model.camera_id},
    )

    return EventIngestResponse(
        event=EventSchema.model_validate(event_model),
        status="DUPLICATE" if deduplicated else "INGESTED",
        deduplicated=deduplicated,
        message=message,
    )


@router.post(
    "/events-with-evidence",
    response_model=Dict[str, Any],
    status_code=status.HTTP_201_CREATED,
    summary="Ingest event with accompanying unverified evidence footage",
)
def ingest_event_with_evidence(
    payload: AIVideoEventWithEvidenceRequest,
    current_user: User = Depends(require_permission("evidence.verify")),
    db: Session = Depends(get_db),
):
    """
    Compound AI Video intake: registers clip evidence in UNVERIFIED state,
    and correlates it with the newly ingested surveillance event.
    """
    # 1. Ingest evidence strictly as UNVERIFIED
    evidence_model = EvidenceService.create_evidence(
        db=db,
        evidence_in=payload.evidence,
        current_user_id=current_user.user_id,
    )

    # 2. Associate evidence identifier
    event_data = payload.event
    event_data.evidence_id = evidence_model.evidence_id

    # 3. Ingest event
    event_model, deduplicated, message = EventService.ingest_event(
        db=db,
        event_data=event_data,
        dedup_window_seconds=0,
    )

    return {
        "event": EventSchema.model_validate(event_model).model_dump(mode="json"),
        "evidence_id": evidence_model.evidence_id,
        "evidence_status": evidence_model.verification_status,
        "deduplicated": deduplicated,
        "message": "Event and unverified footage registered successfully",
    }


@router.get(
    "/status",
    response_model=AIVideoContractStatus,
    status_code=status.HTTP_200_OK,
    summary="Get AI Video Integration Gateway contract status",
)
def get_ai_video_gateway_status(
    current_user: User = Depends(require_permission("event.read")),
):
    """Returns integration contract operational status and supported modes."""
    return AIVideoContractStatus()
