from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from src.auth.dependencies import require_permission
from src.database.models import User
from src.database.session import get_db
from src.audit.service import AuditService
from src.schemas.audit import AuditLogResponse

router = APIRouter(prefix="/api/audit", tags=["Audit"])


@router.get(
    "",
    response_model=List[AuditLogResponse],
    status_code=status.HTTP_200_OK,
    summary="List authoritative system audit logs",
)
def list_audit_logs(
    user_id: Optional[str] = Query(default=None, description="Filter by user identifier or database ID"),
    action: Optional[str] = Query(default=None, description="Filter by security action (e.g. LOGIN, LOGOUT, VERIFY_EVIDENCE)"),
    resource_type: Optional[str] = Query(default=None, description="Filter by resource type (e.g. auth, evidence, investigation)"),
    resource_id: Optional[str] = Query(default=None, description="Filter by target resource identifier"),
    status_filter: Optional[str] = Query(default=None, alias="status", description="Filter by status (SUCCESS, FAILURE)"),
    start_time: Optional[datetime] = Query(default=None, description="Start timestamp ISO8601"),
    end_time: Optional[datetime] = Query(default=None, description="End timestamp ISO8601"),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    current_user: User = Depends(require_permission("audit.read")),
    db: Session = Depends(get_db),
):
    """
    Retrieve authoritative immutable system audit logs.
    Restricted to users holding the 'audit.read' permission (ADMIN, AUDITOR).
    Sensitive credentials and secrets are strictly redacted.
    """
    logs = AuditService.list_logs(
        db=db,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        status=status_filter,
        start_time=start_time,
        end_time=end_time,
        skip=skip,
        limit=limit,
    )
    return [AuditLogResponse.model_validate(log) for log in logs]
