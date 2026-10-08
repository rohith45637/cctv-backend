from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from src.auth.dependencies import get_current_active_user
from src.database.models import User
from src.database.session import get_db
from src.copilot.service import CopilotService
from src.schemas.copilot import CopilotQueryRequest, CopilotQueryResponse

router = APIRouter(prefix="/api/copilot", tags=["Copilot"])


@router.post(
    "/query",
    response_model=CopilotQueryResponse,
    status_code=status.HTTP_200_OK,
    summary="Query AI Security Copilot with authoritative backend context",
)
def query_copilot(
    payload: CopilotQueryRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """
    Controlled query interface for Frontend Security Copilot.
    Grounded strictly in authoritative backend security data, verified evidence,
    and RBAC permissions without autonomous LLM hallucination.
    """
    return CopilotService.query(
        db=db,
        request=payload,
        current_user=current_user,
    )
