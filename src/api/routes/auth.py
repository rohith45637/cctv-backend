from typing import Optional
from fastapi import APIRouter, Depends, Header, Request, status
from sqlalchemy.orm import Session

from src.auth.dependencies import get_current_active_user
from src.auth.service import AuthService
from src.database.models import User
from src.database.session import get_db
from src.schemas.auth import (
    LoginRequest,
    LogoutRequest,
    LogoutResponse,
    RefreshTokenRequest,
    TokenRefreshResponse,
    TokenResponse,
    UserOut,
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user and issue JWT token pair",
)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Authenticate user using username or email and password.
    Returns access token, refresh token, and user profile.
    Never exposes password hashes.
    """
    client_ip = request.client.host if request.client else None
    user = AuthService.authenticate_user(
        db=db,
        username_or_email=payload.username,
        password=payload.password,
        client_ip=client_ip,
    )
    return AuthService.create_user_tokens(db=db, user=user)


@router.post(
    "/refresh",
    response_model=TokenRefreshResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token using valid refresh token",
)
def refresh_token(
    payload: RefreshTokenRequest,
    db: Session = Depends(get_db),
):
    """
    Validates the provided refresh token against the database session store.
    If valid and not revoked, returns a newly signed access token.
    """
    return AuthService.refresh_user_tokens(db=db, refresh_token_str=payload.refresh_token)


@router.post(
    "/logout",
    response_model=LogoutResponse,
    status_code=status.HTTP_200_OK,
    summary="Invalidate active session/refresh tokens",
)
def logout(
    request: Request,
    payload: Optional[LogoutRequest] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """
    Revokes the user's active refresh token session(s) and writes a LOGOUT audit log.
    Requires Bearer access token authentication.
    """
    client_ip = request.client.host if request.client else None
    refresh_token_str = payload.refresh_token if payload else None
    AuthService.logout_user(
        db=db,
        user=current_user,
        refresh_token_str=refresh_token_str,
        client_ip=client_ip,
    )
    return LogoutResponse(message="Successfully logged out")


@router.get(
    "/me",
    response_model=UserOut,
    status_code=status.HTTP_200_OK,
    summary="Get authenticated user safe profile",
)
def get_me(
    current_user: User = Depends(get_current_active_user),
):
    """
    Retrieve the current authenticated user's profile, assigned roles, and granular permissions.
    Protected endpoint: rejects unauthenticated requests with HTTP 401.
    Never exposes password hashes or secrets.
    """
    return UserOut(
        user_id=current_user.user_id,
        username=current_user.username,
        email=current_user.email,
        display_name=current_user.effective_display_name,
        full_name=current_user.full_name,
        status=current_user.status,
        is_active=current_user.is_active,
        roles=sorted(list(current_user.role_names)),
        permissions=sorted(list(current_user.permission_codes)),
        created_at=current_user.created_at,
        updated_at=current_user.updated_at,
        last_login_at=current_user.last_login_at,
    )
