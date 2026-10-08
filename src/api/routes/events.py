from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from src.auth.dependencies import get_current_active_user, require_permission
from src.database.models import User
from src.database.session import get_db
from src.events.service import EventService
from src.schemas.event import Event as EventSchema, EventIngestResponse

router = APIRouter(prefix="/api/events", tags=["Events"])


@router.post(
    "",
    response_model=EventIngestResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest structured surveillance event from AI Video Intelligence",
)
@router.post(
    "/ingest",
    response_model=EventIngestResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest structured surveillance event (alias)",
)
def ingest_event(
    event: EventSchema,
    dedup_window_seconds: int = Query(default=10, ge=0, le=300),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """
    Ingest structured event from AI Video Intelligence.
    Enforces RBAC authorization, performs primary identity & temporal deduplication,
    and persists event and entities transactionally.
    """
    # Enforce permission (either event.manage, event.read, or admin)
    if not current_user.has_permission("event.manage") and not current_user.has_permission("event.read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: required permission 'event.read' or 'event.manage'",
        )

    event_model, deduplicated, message = EventService.ingest_event(
        db=db,
        event_data=event,
        dedup_window_seconds=dedup_window_seconds,
    )

    return EventIngestResponse(
        event=EventSchema.model_validate(event_model),
        status="DUPLICATE" if deduplicated else "INGESTED",
        deduplicated=deduplicated,
        message=message,
    )


@router.get(
    "",
    response_model=List[EventSchema],
    status_code=status.HTTP_200_OK,
    summary="List authoritative security events",
)
def list_events(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    camera_id: Optional[str] = Query(default=None),
    event_type: Optional[str] = Query(default=None),
    zone_id: Optional[str] = Query(default=None),
    current_user: User = Depends(require_permission("event.read")),
    db: Session = Depends(get_db),
):
    """List recent surveillance events with filtering by camera, zone, and event_type."""
    events = EventService.list_events(
        db=db,
        skip=skip,
        limit=limit,
        camera_id=camera_id,
        event_type=event_type,
        zone_id=zone_id,
    )
    return [EventSchema.model_validate(e) for e in events]


@router.get(
    "/{event_id}",
    response_model=EventSchema,
    status_code=status.HTTP_200_OK,
    summary="Get event by event_id",
)
def get_event(
    event_id: str,
    current_user: User = Depends(require_permission("event.read")),
    db: Session = Depends(get_db),
):
    """Retrieve authoritative surveillance event by unique event_id."""
    event = EventService.get_event(db=db, event_id=event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event '{event_id}' not found",
        )
    return EventSchema.model_validate(event)
