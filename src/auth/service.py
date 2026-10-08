import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException, status
from jose import JWTError
from sqlalchemy.orm import Session

from src.auth.rbac.permissions import SystemRole
from src.auth.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    is_rate_limited,
    record_failed_attempt,
    reset_rate_limit,
    verify_password,
)
from src.config.settings import settings
from src.database.models import AuditLog, RefreshToken, User
from src.database.models.base import utc_now
from src.schemas.auth import (
    TokenRefreshResponse,
    TokenResponse,
    UserOut,
    UserStatus,
)

logger = logging.getLogger("backend.auth.service")


class AuthService:
    """Core domain service for user authentication, token rotation, and session management."""

    @staticmethod
    def authenticate_user(
        db: Session,
        username_or_email: str,
        password: str,
        client_ip: Optional[str] = None,
    ) -> User:
        """
        Authenticate a user by username or email and password.
        Records audit logs for LOGIN and FAILED_LOGIN, and enforces rate limits.
        """
        rate_limit_key = f"{client_ip or 'unknown'}:{username_or_email.strip().lower()}"
        if is_rate_limited(rate_limit_key):
            logger.warning(f"Rate limit exceeded for login attempt: {rate_limit_key}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Please try again later.",
            )

        identifier = username_or_email.strip()
        user = (
            db.query(User)
            .filter(
                (User.username == identifier) | (User.email == identifier),
                User.is_deleted == False,
            )
            .first()
        )

        if not user or not verify_password(password, user.hashed_password):
            record_failed_attempt(rate_limit_key)
            audit_entry = AuditLog(
                user_id=user.id if user else None,
                action="FAILED_LOGIN",
                resource_type="auth",
                resource_id=identifier,
                ip_address=client_ip,
                status="FAILURE",
                details_json={"identifier": identifier, "reason": "Invalid credentials"},
            )
            db.add(audit_entry)
            db.commit()
            logger.info(f"Failed login attempt for identifier: {identifier}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Account status validation
        if user.status == UserStatus.INACTIVE.value or not user.is_active:
            record_failed_attempt(rate_limit_key)
            audit_entry = AuditLog(
                user_id=user.id,
                action="FAILED_LOGIN",
                resource_type="auth",
                resource_id=user.user_id,
                ip_address=client_ip,
                status="FAILURE",
                details_json={"identifier": identifier, "reason": "Account is inactive"},
            )
            db.add(audit_entry)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is inactive. Contact system administrator.",
            )

        if user.status == UserStatus.SUSPENDED.value:
            record_failed_attempt(rate_limit_key)
            audit_entry = AuditLog(
                user_id=user.id,
                action="FAILED_LOGIN",
                resource_type="auth",
                resource_id=user.user_id,
                ip_address=client_ip,
                status="FAILURE",
                details_json={"identifier": identifier, "reason": "Account is suspended"},
            )
            db.add(audit_entry)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account has been suspended. Contact security administrator.",
            )

        # Reset rate limit on success
        reset_rate_limit(rate_limit_key)

        # Update last login timestamp
        user.last_login_at = utc_now()

        # Audit log for successful login
        audit_entry = AuditLog(
            user_id=user.id,
            action="LOGIN",
            resource_type="auth",
            resource_id=user.user_id,
            ip_address=client_ip,
            status="SUCCESS",
            details_json={"username": user.username},
        )
        db.add(audit_entry)
        db.commit()
        db.refresh(user)

        logger.info(f"User {user.username} ({user.user_id}) logged in successfully.")
        return user

    @staticmethod
    def create_user_tokens(db: Session, user: User) -> TokenResponse:
        """Issue access and refresh token pair and persist refresh token session."""
        roles_list = sorted(list(user.role_names))
        permissions_list = sorted(list(user.permission_codes))

        token_claims = {
            "sub": user.user_id,
            "username": user.username,
            "email": user.email,
            "roles": roles_list,
            "permissions": permissions_list,
        }

        access_token = create_access_token(data=token_claims)
        refresh_token_str, jti, refresh_exp = create_refresh_token(
            data={"sub": user.user_id, "username": user.username}
        )

        # Persist refresh token in database
        refresh_record = RefreshToken(
            token=refresh_token_str,
            jti=jti,
            user_id=user.id,
            expires_at=refresh_exp,
            is_revoked=False,
        )
        db.add(refresh_record)
        db.commit()

        user_out = UserOut(
            user_id=user.user_id,
            username=user.username,
            email=user.email,
            display_name=user.effective_display_name,
            full_name=user.full_name,
            status=user.status,
            is_active=user.is_active,
            roles=roles_list,
            permissions=permissions_list,
            created_at=user.created_at,
            updated_at=user.updated_at,
            last_login_at=user.last_login_at,
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token_str,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=user_out,
        )

    @staticmethod
    def refresh_user_tokens(db: Session, refresh_token_str: str) -> TokenRefreshResponse:
        """Validate an active refresh token and issue a fresh access token."""
        try:
            payload = decode_token(refresh_token_str)
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token provided is not a refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        jti = payload.get("jti")
        token_record = (
            db.query(RefreshToken)
            .filter(
                (RefreshToken.token == refresh_token_str) | (RefreshToken.jti == jti),
                RefreshToken.is_revoked == False,
            )
            .first()
        )

        if not token_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has been revoked or does not exist",
                headers={"WWW-Authenticate": "Bearer"},
            )

        now = datetime.now(timezone.utc)
        # Handle naive or aware datetime comparison safely
        exp = token_record.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < now:
            token_record.is_revoked = True
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user = db.query(User).filter(User.id == token_record.user_id, User.is_deleted == False).first()
        if not user or user.status != UserStatus.ACTIVE.value or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is inactive or suspended",
                headers={"WWW-Authenticate": "Bearer"},
            )

        roles_list = sorted(list(user.role_names))
        permissions_list = sorted(list(user.permission_codes))
        token_claims = {
            "sub": user.user_id,
            "username": user.username,
            "email": user.email,
            "roles": roles_list,
            "permissions": permissions_list,
        }

        new_access_token = create_access_token(data=token_claims)

        return TokenRefreshResponse(
            access_token=new_access_token,
            refresh_token=refresh_token_str,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    @staticmethod
    def logout_user(
        db: Session,
        user: User,
        refresh_token_str: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> None:
        """Revoke refresh token session and log audit event."""
        now = utc_now()
        if refresh_token_str:
            token_rec = (
                db.query(RefreshToken)
                .filter(RefreshToken.token == refresh_token_str, RefreshToken.user_id == user.id)
                .first()
            )
            if token_rec:
                token_rec.is_revoked = True
                token_rec.revoked_at = now
        else:
            # Revoke all active refresh tokens for this user
            active_tokens = (
                db.query(RefreshToken)
                .filter(RefreshToken.user_id == user.id, RefreshToken.is_revoked == False)
                .all()
            )
            for t in active_tokens:
                t.is_revoked = True
                t.revoked_at = now

        audit_entry = AuditLog(
            user_id=user.id,
            action="LOGOUT",
            resource_type="auth",
            resource_id=user.user_id,
            ip_address=client_ip,
            status="SUCCESS",
            details_json={"username": user.username},
        )
        db.add(audit_entry)
        db.commit()
        logger.info(f"User {user.username} ({user.user_id}) logged out.")
