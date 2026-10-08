from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.auth.dependencies import get_current_active_user, require_permission, require_roles
from src.auth.rbac.permissions import (
    PermissionCode,
    ROLE_PERMISSIONS_MAPPING,
    SystemRole,
)
from src.auth.security import create_access_token
from src.config.settings import settings
from src.database.models import Permission, Role, User
from src.main import app

DEMO_PASSWORD = "AdminSecure!2026"

# Create a test-only router with endpoints protected by permissions and roles
dummy_rbac_router = APIRouter(prefix="/api/test-rbac", tags=["TestRBAC"])


@dummy_rbac_router.get("/camera-read")
def endpoint_camera_read(user: User = Depends(require_permission(PermissionCode.CAMERA_READ.value))):
    return {"message": "camera.read granted", "user": user.username}


@dummy_rbac_router.get("/camera-manage")
def endpoint_camera_manage(user: User = Depends(require_permission(PermissionCode.CAMERA_MANAGE.value))):
    return {"message": "camera.manage granted", "user": user.username}


@dummy_rbac_router.get("/user-manage")
def endpoint_user_manage(user: User = Depends(require_permission(PermissionCode.USER_MANAGE.value))):
    return {"message": "user.manage granted", "user": user.username}


@dummy_rbac_router.get("/admin-only")
def endpoint_admin_only(user: User = Depends(require_roles(SystemRole.ADMIN.value))):
    return {"message": "admin only granted", "user": user.username}


# Mount test router on app
app.include_router(dummy_rbac_router)


# ==========================================
# 1. /api/auth/me Endpoint Tests
# ==========================================

def test_auth_me_unauthenticated_rejected(client: TestClient):
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    assert "not provided" in response.json()["detail"].lower() or "credentials" in response.json()["detail"].lower()


def test_auth_me_authenticated_success(client: TestClient):
    # 1. Login to get access token
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": DEMO_PASSWORD},
    )
    token = login_resp.json()["access_token"]

    # 2. Call /api/auth/me
    response = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    user_data = response.json()

    assert user_data["username"] == "admin"
    assert user_data["user_id"] == "USR-ADMIN01"
    assert user_data["status"] == "ACTIVE"
    assert "ADMIN" in user_data["roles"]
    assert len(user_data["permissions"]) >= 20

    # Ensure password hashes and secrets are never returned
    assert "password_hash" not in user_data
    assert "hashed_password" not in user_data
    assert "password" not in user_data
    assert settings.JWT_SECRET not in str(user_data)


def test_auth_me_invalid_token_rejected(client: TestClient):
    response = client.get(
        "/api/auth/me",
        headers={"Authorization": "Bearer totally.invalid.token"},
    )
    assert response.status_code == 401


# ==========================================
# 2. Role-Permission Matrix Verification
# ==========================================

def test_all_baseline_roles_seeded(db_session: Session):
    for role_enum in SystemRole:
        role = db_session.query(Role).filter(Role.name == role_enum.value).first()
        assert role is not None, f"Expected role {role_enum.value} to be seeded"


def test_all_granular_permissions_seeded(db_session: Session):
    for perm_enum in PermissionCode:
        perm = db_session.query(Permission).filter(Permission.code == perm_enum.value).first()
        assert perm is not None, f"Expected permission {perm_enum.value} to be seeded"


def test_role_permission_mappings_in_database(db_session: Session):
    for role_name, expected_perms in ROLE_PERMISSIONS_MAPPING.items():
        role = db_session.query(Role).filter(Role.name == role_name).first()
        assert role is not None, f"Role {role_name} not found"
        role_perm_codes = {p.code for p in role.permissions}
        for exp in expected_perms:
            assert exp in role_perm_codes, f"Role {role_name} missing permission {exp}"


def test_admin_has_all_permissions(db_session: Session):
    admin_role = db_session.query(Role).filter(Role.name == SystemRole.ADMIN.value).first()
    assert admin_role is not None
    admin_perms = {p.code for p in admin_role.permissions}
    all_perms = {p.value for p in PermissionCode}
    assert admin_perms == all_perms


# ==========================================
# 3. Permission Enforcement & Denial Tests
# ==========================================

def test_permission_allowed_for_authorized_user(client: TestClient):
    # Operator has camera.read permission
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "operator", "password": DEMO_PASSWORD},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    response = client.get(
        "/api/test-rbac/camera-read",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["message"] == "camera.read granted"


def test_permission_denied_for_unauthorized_user(client: TestClient):
    # Viewer does NOT have camera.manage permission
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "viewer", "password": DEMO_PASSWORD},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    response = client.get(
        "/api/test-rbac/camera-manage",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    assert "permission denied" in response.json()["detail"].lower()
    assert "camera.manage" in response.json()["detail"]


def test_user_management_denied_for_non_admin(client: TestClient):
    # Operator does NOT have user.manage permission
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "operator", "password": DEMO_PASSWORD},
    )
    token = login_resp.json()["access_token"]

    response = client.get(
        "/api/test-rbac/user-manage",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    assert "user.manage" in response.json()["detail"]


def test_role_enforcement_admin_only(client: TestClient):
    # 1. Admin succeeds
    admin_resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": DEMO_PASSWORD},
    )
    admin_token = admin_resp.json()["access_token"]
    res_admin = client.get(
        "/api/test-rbac/admin-only",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_admin.status_code == 200

    # 2. Analyst is forbidden
    analyst_resp = client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": DEMO_PASSWORD},
    )
    analyst_token = analyst_resp.json()["access_token"]
    res_analyst = client.get(
        "/api/test-rbac/admin-only",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert res_analyst.status_code == 403
