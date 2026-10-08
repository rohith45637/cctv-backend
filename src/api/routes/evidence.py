from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from src.auth.dependencies import require_permission
from src.database.models import User
from src.database.session import get_db
from src.evidence.service import EvidenceService
from src.schemas.evidence import (
    Evidence as EvidenceSchema,
    EvidenceCreate,
    EvidenceVerifyRequest,
    EvidenceProvenanceResponse,
)

router = APIRouter(prefix="/api/evidence", tags=["Evidence"])


@router.post(
    "",
    response_model=EvidenceSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Register new surveillance evidence item",
)
def create_evidence(
    payload: EvidenceCreate,
    current_user: User = Depends(require_permission("evidence.verify")),
    db: Session = Depends(get_db),
):
    """
    Register authoritative evidence from surveillance feed or sensor.
    Initial verification status is strictly UNVERIFIED.
    Requires 'evidence.verify' permission.
    """
    evidence = EvidenceService.create_evidence(
        db=db,
        evidence_in=payload,
        current_user_id=current_user.user_id,
    )
    return EvidenceSchema.model_validate(evidence)


@router.get(
    "",
    response_model=List[EvidenceSchema],
    status_code=status.HTTP_200_OK,
    summary="List authoritative surveillance evidence",
)
def list_evidence(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    camera_id: Optional[str] = Query(default=None),
    event_id: Optional[str] = Query(default=None),
    verification_status: Optional[str] = Query(default=None),
    source_type: Optional[str] = Query(default=None),
    current_user: User = Depends(require_permission("evidence.read")),
    db: Session = Depends(get_db),
):
    """List evidence items with optional filtering by camera, event, status, and source type."""
    items = EvidenceService.list_evidence(
        db=db,
        skip=skip,
        limit=limit,
        camera_id=camera_id,
        event_id=event_id,
        verification_status=verification_status,
        source_type=source_type,
    )
    return [EvidenceSchema.model_validate(item) for item in items]


@router.get(
    "/{evidence_id}",
    response_model=EvidenceSchema,
    status_code=status.HTTP_200_OK,
    summary="Get evidence item by evidence_id",
)
def get_evidence(
    evidence_id: str,
    current_user: User = Depends(require_permission("evidence.read")),
    db: Session = Depends(get_db),
):
    """Retrieve authoritative evidence item by unique identifier."""
    evidence = EvidenceService.get_evidence(db=db, evidence_id=evidence_id)
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence '{evidence_id}' not found",
        )
    return EvidenceSchema.model_validate(evidence)


@router.post(
    "/{evidence_id}/verify",
    response_model=EvidenceSchema,
    status_code=status.HTTP_200_OK,
    summary="Explicitly verify, reject, or mark evidence insufficient",
)
def verify_evidence(
    evidence_id: str,
    payload: EvidenceVerifyRequest,
    current_user: User = Depends(require_permission("evidence.verify")),
    db: Session = Depends(get_db),
):
    """
    Explicitly transition evidence status to VERIFIED, REJECTED, or INSUFFICIENT_EVIDENCE.
    Records authenticated verification audit trail with provenance snapshot.
    Requires 'evidence.verify' permission.
    """
    notes = payload.notes or payload.reason
    evidence = EvidenceService.verify_evidence(
        db=db,
        evidence_id=evidence_id,
        target_status=payload.status,
        verified_by_user_id=current_user.user_id,
        notes=notes,
    )
    return EvidenceSchema.model_validate(evidence)


@router.get(
    "/{evidence_id}/provenance",
    response_model=EvidenceProvenanceResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve complete provenance audit trail for evidence item",
)
def get_evidence_provenance(
    evidence_id: str,
    current_user: User = Depends(require_permission("evidence.read")),
    db: Session = Depends(get_db),
):
    """Retrieve origin provenance metadata and verification audit count."""
    prov_data = EvidenceService.get_provenance(db=db, evidence_id=evidence_id)
    return EvidenceProvenanceResponse(**prov_data)
