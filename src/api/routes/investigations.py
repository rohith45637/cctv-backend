from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from src.auth.dependencies import require_permission
from src.database.models import User
from src.database.session import get_db
from src.investigations.service import InvestigationService
from src.schemas.investigation import (
    Investigation as InvestigationSchema,
    InvestigationCreate,
    InvestigationUpdate,
    InvestigationExecutionResult,
    InvestigationExecuteRequest,
)
from src.schemas.ai_agent import (
    AIAgentInvestigationRequest,
    AIAgentInvestigationResponse,
    AIAgentValidationResult,
)

router = APIRouter(prefix="/api/investigations", tags=["Investigations"])


@router.post(
    "",
    response_model=InvestigationSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Create authoritative investigation dossier",
)
def create_investigation(
    payload: InvestigationCreate,
    current_user: User = Depends(require_permission("investigation.create")),
    db: Session = Depends(get_db),
):
    """
    Open a new authoritative security investigation dossier.
    Requires 'investigation.create' permission.
    """
    inv = InvestigationService.create_investigation(
        db=db,
        data=payload,
        current_user_id=current_user.user_id,
    )
    return InvestigationSchema.model_validate(inv)


@router.get(
    "",
    response_model=List[InvestigationSchema],
    status_code=status.HTTP_200_OK,
    summary="List investigations",
)
def list_investigations(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    priority_filter: Optional[str] = Query(default=None, alias="priority"),
    assigned_user_id: Optional[str] = Query(default=None),
    incident_id: Optional[str] = Query(default=None),
    current_user: User = Depends(require_permission("investigation.read")),
    db: Session = Depends(get_db),
):
    """List investigations with lifecycle, priority, and assignment filters."""
    items = InvestigationService.list_investigations(
        db=db,
        skip=skip,
        limit=limit,
        status=status_filter,
        priority=priority_filter,
        assigned_user_id=assigned_user_id,
        incident_id=incident_id,
    )
    return [InvestigationSchema.model_validate(item) for item in items]


@router.get(
    "/{investigation_id}",
    response_model=InvestigationSchema,
    status_code=status.HTTP_200_OK,
    summary="Get investigation by investigation_id",
)
def get_investigation(
    investigation_id: str,
    current_user: User = Depends(require_permission("investigation.read")),
    db: Session = Depends(get_db),
):
    """Retrieve complete investigation dossier by authoritative identifier."""
    inv = InvestigationService.get_investigation(db=db, investigation_id=investigation_id)
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found",
        )
    return InvestigationSchema.model_validate(inv)


@router.patch(
    "/{investigation_id}",
    response_model=InvestigationSchema,
    status_code=status.HTTP_200_OK,
    summary="Update investigation attributes or transition lifecycle state",
)
def update_investigation(
    investigation_id: str,
    payload: InvestigationUpdate,
    current_user: User = Depends(require_permission("investigation.create")),
    db: Session = Depends(get_db),
):
    """
    Update investigation attributes or execute controlled state transition.
    Strictly validates lifecycle state transitions.
    Requires 'investigation.create' permission.
    """
    inv = InvestigationService.update_investigation(
        db=db,
        investigation_id=investigation_id,
        update_in=payload,
    )
    return InvestigationSchema.model_validate(inv)


@router.post(
    "/{investigation_id}/agent-request",
    response_model=AIAgentInvestigationRequest,
    status_code=status.HTTP_200_OK,
    summary="Generate AI Agent investigation request packet",
)
def build_agent_request(
    investigation_id: str,
    requested_action: str = Query(default="ANALYZE_INCIDENT"),
    current_user: User = Depends(require_permission("investigation.read")),
    db: Session = Depends(get_db),
):
    """
    Exposes clean contract for future AI Investigation Agent.
    Prepares authoritative identifiers, incident boundaries, and evidence references.
    """
    return InvestigationService.build_agent_request(
        db=db,
        investigation_id=investigation_id,
        requested_action=requested_action,
    )


@router.post(
    "/{investigation_id}/agent-response",
    response_model=AIAgentValidationResult,
    status_code=status.HTTP_200_OK,
    summary="Validate and apply untrusted AI Agent response",
)
def submit_agent_response(
    investigation_id: str,
    payload: AIAgentInvestigationResponse,
    current_user: User = Depends(require_permission("investigation.create")),
    db: Session = Depends(get_db),
):
    """
    Submits untrusted AI Investigation Agent response to authoritative Backend validation.
    Rejects fabricated evidence IDs, enforces confidence bounds, and preserves human oversight.
    Requires 'investigation.create' permission.
    """
    if payload.investigation_id != investigation_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"URL investigation_id '{investigation_id}' does not match body '{payload.investigation_id}'",
        )

    return InvestigationService.validate_and_apply_agent_response(
        db=db,
        agent_response=payload,
    )


@router.post(
    "/{investigation_id}/execute",
    response_model=InvestigationExecutionResult,
    status_code=status.HTTP_200_OK,
    summary="Execute autonomous security investigation",
)
def execute_investigation(
    investigation_id: str,
    payload: Optional[InvestigationExecuteRequest] = None,
    current_user: User = Depends(require_permission("investigation.read")),
    db: Session = Depends(get_db),
):
    """
    Execute autonomous security investigation from an incident or event.

    Follows mandatory investigation flow:
    Incident → Find relevant cameras → Find detected entities →
    Cross-camera search/tracking → Check zones → Check policies →
    Build timeline → Collect evidence → Cross-check → Calculate confidence →
    Generate explanation → Return result.

    The result strictly separates:
    1. OBSERVED FACTS (evidence-grounded)
    2. INFERENCES (logically derived with reasoning)
    3. UNKNOWN INFORMATION (explicitly declared gaps)

    If evidence is insufficient, returns: "I don't know — insufficient evidence."
    Requires 'investigation.read' permission.
    """
    if payload is None:
        payload = InvestigationExecuteRequest(investigation_id=investigation_id)
    else:
        if payload.investigation_id != investigation_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"URL investigation_id '{investigation_id}' does not match body '{payload.investigation_id}'",
            )

    result = InvestigationService.execute_autonomous_investigation(
        db=db,
        request=payload,
        current_user_id=current_user.user_id,
    )
    return result
