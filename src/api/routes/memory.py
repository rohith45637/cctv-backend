from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from src.auth.dependencies import require_permission
from src.database.models import User
from src.database.session import get_db
from src.memory.service import SecurityMemoryService
from src.schemas.security_memory import (
    SecurityMemory as MemorySchema,
    SecurityMemoryCreate,
    SecurityMemoryUpdate,
)

router = APIRouter(prefix="/api/memory", tags=["Security Memory"])


@router.post(
    "",
    response_model=MemorySchema,
    status_code=status.HTTP_201_CREATED,
    summary="Create authoritative security context memory",
)
def create_memory(
    payload: SecurityMemoryCreate,
    current_user: User = Depends(require_permission("memory.manage")),
    db: Session = Depends(get_db),
):
    """
    Store authoritative security context memory.
    Associates context with entity, camera, zone, event, or incident.
    Requires 'memory.manage' permission.
    """
    memory = SecurityMemoryService.create_memory(db=db, memory_in=payload)
    return MemorySchema.model_validate(memory)


@router.get(
    "",
    response_model=List[MemorySchema],
    status_code=status.HTTP_200_OK,
    summary="List security context memory records",
)
def list_memories(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    memory_type: Optional[str] = Query(default=None),
    entity_id: Optional[str] = Query(default=None),
    camera_id: Optional[str] = Query(default=None),
    zone_id: Optional[str] = Query(default=None),
    event_id: Optional[str] = Query(default=None),
    incident_id: Optional[str] = Query(default=None),
    active_only: bool = Query(default=False),
    current_user: User = Depends(require_permission("memory.read")),
    db: Session = Depends(get_db),
):
    """List security memory entries with contextual filtering."""
    items = SecurityMemoryService.list_memories(
        db=db,
        skip=skip,
        limit=limit,
        memory_type=memory_type,
        entity_id=entity_id,
        camera_id=camera_id,
        zone_id=zone_id,
        event_id=event_id,
        incident_id=incident_id,
        active_only=active_only,
    )
    return [MemorySchema.model_validate(item) for item in items]


@router.get(
    "/{memory_id}",
    response_model=MemorySchema,
    status_code=status.HTTP_200_OK,
    summary="Get security context memory by memory_id",
)
def get_memory(
    memory_id: str,
    current_user: User = Depends(require_permission("memory.read")),
    db: Session = Depends(get_db),
):
    """Retrieve security context memory item by identifier."""
    memory = SecurityMemoryService.get_memory(db=db, memory_id=memory_id)
    if not memory:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security memory '{memory_id}' not found",
        )
    return MemorySchema.model_validate(memory)


@router.patch(
    "/{memory_id}",
    response_model=MemorySchema,
    status_code=status.HTTP_200_OK,
    summary="Update security context memory item",
)
def update_memory(
    memory_id: str,
    payload: SecurityMemoryUpdate,
    current_user: User = Depends(require_permission("memory.manage")),
    db: Session = Depends(get_db),
):
    """Update context narrative, confidence, or TTL expiration."""
    memory = SecurityMemoryService.update_memory(
        db=db,
        memory_id=memory_id,
        update_in=payload,
    )
    return MemorySchema.model_validate(memory)


@router.delete(
    "/{memory_id}",
    status_code=status.HTTP_200_OK,
    summary="Soft-delete security context memory item",
)
def delete_memory(
    memory_id: str,
    current_user: User = Depends(require_permission("memory.manage")),
    db: Session = Depends(get_db),
):
    """Delete security memory item."""
    SecurityMemoryService.delete_memory(db=db, memory_id=memory_id)
    return {"deleted": True, "memory_id": memory_id}
