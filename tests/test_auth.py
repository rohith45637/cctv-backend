from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from jose import jwt
from sqlalchemy.orm import Session

from src.auth.rbac.permissions import SystemRole
from src.auth.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from src.config.settings import settings
from src.database.models import AuditLog, RefreshToken, Role, User
from src.schemas.auth import UserStatus

DEMO_PASSWORD = "AdminSecure!2026"


# ==========================================
# 1. Password Hashing & Verification Tests
# ==========================================

def test_password_hashing():
    raw_pwd = "SuperSecretPassword123!"
    hashed = hash_password(raw_pwd)

    assert hashed != raw_pwd
    assert hashed.startswith("$2b$")
    assert verify_password(raw_pwd, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False
    assert verify_password("", hashed) is False
    assert verify_password(raw_pwd, "") is False


def test_password_truncation_safety():
    # bcrypt max length is 72 bytes
    long_pwd = "A" * 150
    hashed = hash_password(long_pwd)
    assert verify_password(long_pwd, hashed) is True
    assert verify_password("A" * 72, hashed) is True
    assert verify_password("B" * 150, hashed) is False


# ==========================================
# 2. Login & Authentication Flow Tests
# ==========================================

def test_login_successful_with_username(client: TestClient):
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": DEMO_PASSWORD},
    )
    assert response.status_code == 200
    data = response.json()

    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0

    user_info = data["user"]
    assert user_info["username"] == "admin"
    assert user_info["user_id"] == "USR-ADMIN01"
    assert user_info["status"] == "ACTIVE"
    assert "ADMIN" in user_info["roles"]
    assert len(user_info["permissions"]) > 0

    # Ensure password hashes and secrets are never returned
    assert "password_hash" not in user_info
    assert "hashed_password" not in user_info
    assert "password" not in user_info
    assert "jwt_secret" not in data
    assert settings.JWT_SECRET not in str(data)


def test_login_successful_with_email(client: TestClient):
    response = client.post(
        "/api/auth/login",
        json={"username": "admin@security-core.internal", "password": DEMO_PASSWORD},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["user"]["email"] == "admin@security-core.internal"


def test_login_invalid_password(client: TestClient, db_session: Session):
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "IncorrectPassword123!"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"

    # Verify audit log recorded FAILED_LOGIN
    audit = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "FAILED_LOGIN")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.status == "FAILURE"


def test_login_nonexistent_user(client: TestClient):
    response = client.post(
        "/api/auth/login",
        json={"username": "ghost_user", "password": "SomePassword123!"},
    )
    # Never expose whether user exists
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"


def test_login_inactive_user_rejected(client: TestClient, db_session: Session):
    # Create an inactive test user
    inactive_user = User(
        user_id="USR-INACTIVE01",
        username="inactive_user",
        email="inactive@example.com",
        hashed_password=hash_password(DEMO_PASSWORD),
        status=UserStatus.INACTIVE.value,
        is_active=False,
    )
    db_session.add(inactive_user)
    db_session.commit()

    response = client.post(
        "/api/auth/login",
        json={"username": "inactive_user", "password": DEMO_PASSWORD},
    )
    assert response.status_code == 403
    assert "inactive" in response.json()["detail"].lower()


def test_login_suspended_user_rejected(client: TestClient, db_session: Session):
    # Create a suspended test user
    suspended_user = User(
        user_id="USR-SUSPENDED01",
        username="suspended_user",
        email="suspended@example.com",
        hashed_password=hash_password(DEMO_PASSWORD),
        status=UserStatus.SUSPENDED.value,
        is_active=True,
    )
    db_session.add(suspended_user)
    db_session.commit()

    response = client.post(
        "/api/auth/login",
        json={"username": "suspended_user", "password": DEMO_PASSWORD},
    )
    assert response.status_code == 403
    assert "suspended" in response.json()["detail"].lower()


# ==========================================
# 3. Token Operations & Refresh Tests
# ==========================================

def test_access_token_claims_and_validation():
    claims = {"sub": "USR-TEST01", "roles": ["ADMIN"], "permissions": ["camera.read"]}
    token = create_access_token(claims)
    payload = decode_token(token)

    assert payload["sub"] == "USR-TEST01"
    assert payload["type"] == "access"
    assert "ADMIN" in payload["roles"]
    assert "exp" in payload
    assert "iat" in payload
    assert "jti" in payload


def test_expired_token_rejection():
    claims = {"sub": "USR-TEST01"}
    expired_token = create_access_token(claims, expires_delta=timedelta(seconds=-10))

    with pytest.raises(Exception):
        decode_token(expired_token)


def test_token_refresh_successful(client: TestClient):
    # 1. Login to get tokens
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": DEMO_PASSWORD},
    )
    refresh_tok = login_resp.json()["refresh_token"]

    # 2. Refresh token
    refresh_resp = client.post(
        "/api/auth/refresh",
        json={"refresh_token": refresh_tok},
    )
    assert refresh_resp.status_code == 200
    refreshed_data = refresh_resp.json()
    assert "access_token" in refreshed_data
    assert refreshed_data["token_type"] == "bearer"
    assert refreshed_data["expires_in"] > 0


def test_refresh_with_invalid_token_rejected(client: TestClient):
    response = client.post(
        "/api/auth/refresh",
        json={"refresh_token": "invalid.jwt.token"},
    )
    assert response.status_code == 401


def test_refresh_with_access_token_rejected(client: TestClient):
    # An access token should not be accepted on the refresh endpoint
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": DEMO_PASSWORD},
    )
    access_tok = login_resp.json()["access_token"]

    response = client.post(
        "/api/auth/refresh",
        json={"refresh_token": access_tok},
    )
    assert response.status_code == 401
    assert "not a refresh token" in response.json()["detail"].lower()


# ==========================================
# 4. Logout & Session Invalidation Tests
# ==========================================

def test_logout_revokes_token_and_audits(client: TestClient, db_session: Session):
    # 1. Login
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": DEMO_PASSWORD},
    )
    access_token = login_resp.json()["access_token"]
    refresh_token = login_resp.json()["refresh_token"]

    # 2. Logout
    logout_resp = client.post(
        "/api/auth/logout",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"refresh_token": refresh_token},
    )
    assert logout_resp.status_code == 200
    assert logout_resp.json()["message"] == "Successfully logged out"

    # 3. Verify refresh token cannot be used again
    refresh_attempt = client.post(
        "/api/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_attempt.status_code == 401
    assert "revoked" in refresh_attempt.json()["detail"].lower()

    # 4. Verify LOGOUT audit entry was stored
    audit = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "LOGOUT")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.status == "SUCCESS"
