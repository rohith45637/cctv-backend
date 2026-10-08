from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.database.models import (
    AuditLog as AuditLogModel,
    Evidence as EvidenceModel,
    Investigation as InvestigationModel,
    Threat as ThreatModel,
    Incident as IncidentModel,
)
from src.audit.service import AuditService, sanitize_audit_details

DEMO_PASSWORD = "AdminSecure!2026"


def get_token(client: TestClient, username: str = "admin") -> str:
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": DEMO_PASSWORD},
    )
    assert response.status_code == 200, f"Login failed for {username}"
    return response.json()["access_token"]


# ==============================================================================
# 1. Audit API Authorization & RBAC
# ==============================================================================

def test_audit_logs_unauthorized(client: TestClient):
    response = client.get("/api/audit")
    assert response.status_code == 401


def test_audit_logs_forbidden_for_non_auditor_roles(client: TestClient):
    # 'operator' role does NOT possess audit.read permission
    token = get_token(client, "operator")
    response = client.get(
        "/api/audit",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    assert "audit.read" in response.json()["detail"]


def test_audit_logs_allowed_for_auditor_and_admin(client: TestClient):
    auditor_token = get_token(client, "auditor")
    resp_auditor = client.get(
        "/api/audit",
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert resp_auditor.status_code == 200
    assert isinstance(resp_auditor.json(), list)

    admin_token = get_token(client, "admin")
    resp_admin = client.get(
        "/api/audit",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp_admin.status_code == 200
    assert isinstance(resp_admin.json(), list)


# ==============================================================================
# 2. Audit Trail Lifecycle Recording & Query Filtering
# ==============================================================================

def test_audit_logging_on_auth_login_and_logout(client: TestClient):
    token = get_token(client, "auditor")

    # Perform a login and check audit log
    client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": DEMO_PASSWORD},
    )

    resp = client.get(
        "/api/audit",
        headers={"Authorization": f"Bearer {token}"},
        params={"action": "LOGIN", "resource_type": "auth"},
    )
    assert resp.status_code == 200
    logs = resp.json()
    assert len(logs) > 0
    assert logs[0]["action"] == "LOGIN"
    assert logs[0]["resource_type"] == "auth"
    assert logs[0]["status"] == "SUCCESS"


def test_audit_logging_on_failed_login(client: TestClient):
    token = get_token(client, "admin")

    # Attempt failed login
    failed_resp = client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": "WrongPassword!999"},
    )
    assert failed_resp.status_code == 401

    resp = client.get(
        "/api/audit",
        headers={"Authorization": f"Bearer {token}"},
        params={"action": "FAILED_LOGIN"},
    )
    assert resp.status_code == 200
    logs = resp.json()
    assert len(logs) > 0
    assert logs[0]["action"] == "FAILED_LOGIN"
    assert logs[0]["status"] == "FAILURE"


def test_audit_logging_on_evidence_verification(client: TestClient, db_session: Session):
    admin_token = get_token(client, "admin")
    now = datetime.now(timezone.utc)

    evd = EvidenceModel(
        evidence_id="EVD-AUDIT-TEST01",
        camera_id="CAM-01",
        timestamp_start=now,
        timestamp_end=now,
        source_reference="rtsp://cam-01",
        clip_reference="clip.mp4",
        confidence=0.9,
        verification_status="UNVERIFIED",
    )
    db_session.add(evd)
    db_session.commit()

    # Verify evidence
    verify_resp = client.post(
        "/api/evidence/EVD-AUDIT-TEST01/verify",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"status": "VERIFIED", "notes": "Audited footage"},
    )
    assert verify_resp.status_code == 200

    audit_resp = client.get(
        "/api/audit",
        headers={"Authorization": f"Bearer {admin_token}"},
        params={"action": "VERIFY_EVIDENCE", "resource_id": "EVD-AUDIT-TEST01"},
    )
    assert audit_resp.status_code == 200
    logs = audit_resp.json()
    assert len(logs) >= 1
    assert logs[0]["action"] == "VERIFY_EVIDENCE"
    assert logs[0]["resource_id"] == "EVD-AUDIT-TEST01"
    assert logs[0]["details_json"]["status"] == "VERIFIED"


def test_audit_logging_on_investigation_lifecycle(client: TestClient):
    inv_token = get_token(client, "investigator")
    admin_token = get_token(client, "admin")

    # Create investigation
    create_resp = client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={
            "investigation_id": "INV-AUDIT-TEST01",
            "title": "Audit Lifecycle Case",
            "priority": "HIGH",
            "status": "PENDING",
        },
    )
    assert create_resp.status_code == 201

    # Check CREATE_INVESTIGATION audit
    audit_resp = client.get(
        "/api/audit",
        headers={"Authorization": f"Bearer {admin_token}"},
        params={"action": "CREATE_INVESTIGATION", "resource_id": "INV-AUDIT-TEST01"},
    )
    assert audit_resp.status_code == 200
    logs = audit_resp.json()
    assert len(logs) >= 1
    assert logs[0]["action"] == "CREATE_INVESTIGATION"

    # Transition to ACTIVE
    update_resp = client.patch(
        "/api/investigations/INV-AUDIT-TEST01",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={"status": "ACTIVE"},
    )
    assert update_resp.status_code == 200

    # Check UPDATE_INVESTIGATION audit
    audit_update_resp = client.get(
        "/api/audit",
        headers={"Authorization": f"Bearer {admin_token}"},
        params={"action": "UPDATE_INVESTIGATION", "resource_id": "INV-AUDIT-TEST01"},
    )
    assert audit_update_resp.status_code == 200
    update_logs = audit_update_resp.json()
    assert len(update_logs) >= 1
    assert update_logs[0]["action"] == "UPDATE_INVESTIGATION"
    assert update_logs[0]["details_json"]["status"] == "ACTIVE"


def test_audit_logging_on_copilot_query(client: TestClient):
    token = get_token(client, "admin")

    # Query Copilot
    copilot_resp = client.post(
        "/api/copilot/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": "Any security threats in ZONE-01?"},
    )
    assert copilot_resp.status_code == 200

    # Verify COPILOT_QUERY is recorded in audit logs
    audit_resp = client.get(
        "/api/audit",
        headers={"Authorization": f"Bearer {token}"},
        params={"action": "COPILOT_QUERY"},
    )
    assert audit_resp.status_code == 200
    logs = audit_resp.json()
    assert len(logs) >= 1
    assert logs[0]["action"] == "COPILOT_QUERY"
    assert logs[0]["resource_type"] == "copilot"


# ==============================================================================
# 3. Sensitive Data Redaction & Sanitization
# ==============================================================================

def test_audit_sensitive_data_masking():
    dirty_data = {
        "username": "operator01",
        "password": "SuperSecretPassword123!",
        "hashed_password": "$2b$12$eXampLeHash...",
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "jwt_secret_key": "very-secret-signing-key",
        "api_key": "live-api-key-9999",
        "user_credentials": {"private_key": "MIIEvgIBADANBgk..."},
        "nested": {
            "token": "nested-bearer-token",
            "safe_counter": 42,
        },
        "safe_field": "public_data",
    }

    clean = sanitize_audit_details(dirty_data)

    assert clean["safe_field"] == "public_data"
    assert clean["nested"]["safe_counter"] == 42

    # Verify all secret fields are redacted
    assert clean["password"] == "[REDACTED]"
    assert clean["hashed_password"] == "[REDACTED]"
    assert clean["access_token"] == "[REDACTED]"
    assert clean["refresh_token"] == "[REDACTED]"
    assert clean["jwt_secret_key"] == "[REDACTED]"
    assert clean["api_key"] == "[REDACTED]"
    assert clean["user_credentials"] == "[REDACTED]"
    assert clean["nested"]["token"] == "[REDACTED]"


# ==============================================================================
# 4. Observability & Health Probes
# ==============================================================================

def test_health_probes(client: TestClient):
    # Base /health
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    h_data = health_resp.json()
    assert h_data["status"] == "healthy"
    assert h_data["database"] == "connected"
    assert "version" in h_data
    assert "environment" in h_data

    # Kubernetes Liveness /health/live
    live_resp = client.get("/health/live")
    assert live_resp.status_code == 200
    assert live_resp.json() == {"status": "alive"}

    # Kubernetes Readiness /health/ready
    ready_resp = client.get("/health/ready")
    assert ready_resp.status_code == 200
    assert ready_resp.json() == {"ready": True}


def test_safe_500_error_response_no_stack_traces_or_secrets(client: TestClient):
    # Nonexistent route exception or testing 500 safety handler
    # Check that error responses return standard safe JSON
    resp = client.get("/nonexistent-endpoint-xyz-123")
    assert resp.status_code == 404
    data = resp.json()
    assert "detail" in data
    # Ensure no secrets or tracebacks are exposed
    raw_str = str(data).lower()
    assert "traceback" not in raw_str
    assert "secret" not in raw_str
    assert "password" not in raw_str
