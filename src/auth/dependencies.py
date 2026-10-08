from typing import Callable, List, Optional
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from src.auth.security import decode_token
from src.database.models import User
from src.database.session import get_db
from src.schemas.auth import UserStatus

security_scheme = HTTPBearer(auto_error=False)


def get_token_from_header(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> str:
    """Extract raw bearer token from Authorization header or raise 401."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials


def get_current_user(
    token: str = Depends(get_token_from_header),
    db: Session = Depends(get_db),
) -> User:
    """
    Validate access token and return the authenticated User model.
    Rejects expired tokens, invalid signatures, non-access token types, and nonexistent users.
    """
    try:
        payload = decode_token(token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials: token is invalid or expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type: access token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token claims: subject missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.user_id == user_id, User.is_deleted == False).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token no longer exists",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensure the authenticated user is currently ACTIVE and not suspended or disabled."""
    if current_user.status == UserStatus.INACTIVE.value or not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive. Contact system administrator.",
        )
    if current_user.status == UserStatus.SUSPENDED.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended. Contact security administrator.",
        )
    return current_user


def require_permission(permission_code: str) -> Callable:
    """
    FastAPI dependency factory enforcing that the authenticated user
    possesses the specified granular permission code.
    """
    def dependency(
        current_user: User = Depends(get_current_active_user),
    ) -> User:
        if not current_user.has_permission(permission_code):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: required permission '{permission_code}'",
            )
        return current_user

    return dependency


def require_roles(*role_names: str) -> Callable:
    """
    FastAPI dependency factory enforcing that the authenticated user
    holds at least one of the specified roles.
    """
    normalized_expected = {r.strip().upper() for r in role_names}

    def dependency(
        current_user: User = Depends(get_current_active_user),
    ) -> User:
        user_roles = current_user.role_names
        # ADMIN role has root access
        if "ADMIN" in user_roles or "admin" in {r.name for r in current_user.roles}:
            return current_user

        if not user_roles.intersection(normalized_expected):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: required role in {list(role_names)}",
            )
        return current_user

    return dependency
