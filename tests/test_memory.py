from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.database.models import SecurityMemory as SecurityMemoryModel

DEMO_PASSWORD = "AdminSecure!2026"


def get_token(client: TestClient, username: str = "admin") -> str:
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": DEMO_PASSWORD},
    )
    assert response.status_code == 200, f"Login failed for {username}"
    return response.json()["access_token"]


# ==========================================
# 1. Memory Creation Tests
# ==========================================

@pytest.mark.parametrize(
    "mem_type",
    [
        "EVENT_CONTEXT",
        "THREAT_CONTEXT",
        "INCIDENT_CONTEXT",
        "CAMERA_CONTEXT",
        "ZONE_CONTEXT",
        "POLICY_CONTEXT",
        "INVESTIGATION_CONTEXT",
    ],
)
def test_create_supported_memory_types(client: TestClient, mem_type: str):
    token = get_token(client, "admin")
    payload = {
        "memory_type": mem_type,
        "content": f"Authoritative context storage for {mem_type}",
        "confidence": 0.95,
        "source_reference": f"audit://baseline/{mem_type.lower()}",
    }

    response = client.post(
        "/api/memory",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["memory_type"] == mem_type
    assert data["memory_id"].startswith("MEM-")
    assert data["confidence"] == 0.95
    assert data["content"] == f"Authoritative context storage for {mem_type}"


def test_create_memory_with_custom_id(client: TestClient, db_session: Session):
    token = get_token(client, "admin")
    payload = {
        "memory_id": "MEM-CUSTOM-001",
        "memory_type": "CAMERA_CONTEXT",
        "camera_id": "CAM-01",
        "content": "Camera covers blindspot near east gate.",
        "confidence": 0.99,
        "source_reference": "site-survey-2026-q3",
    }

    response = client.post(
        "/api/memory",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["memory_id"] == "MEM-CUSTOM-001"
    assert data["camera_id"] == "CAM-01"

    # Verify DB persistence
    db_mem = db_session.query(SecurityMemoryModel).filter(SecurityMemoryModel.memory_id == "MEM-CUSTOM-001").first()
    assert db_mem is not None
    assert db_mem.content == "Camera covers blindspot near east gate."


def test_create_memory_duplicate_id_rejected(client: TestClient):
    token = get_token(client, "admin")
    payload = {
        "memory_id": "MEM-DUP-001",
        "memory_type": "ZONE_CONTEXT",
        "zone_id": "ZONE-01",
        "content": "High security perimeter zone.",
        "confidence": 0.9,
    }
    resp1 = client.post("/api/memory", headers={"Authorization": f"Bearer {token}"}, json=payload)
    assert resp1.status_code == 201

    resp2 = client.post("/api/memory", headers={"Authorization": f"Bearer {token}"}, json=payload)
    assert resp2.status_code == 409


def test_create_memory_invalid_type_rejected(client: TestClient):
    token = get_token(client, "admin")
    payload = {
        "memory_type": "INVALID_AI_DREAM",
        "content": "Fabricated content",
    }
    response = client.post(
        "/api/memory",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert response.status_code == 422


# ==========================================
# 2. Memory Retrieval & Filtering Tests
# ==========================================

def test_memory_get_by_id_and_not_found(client: TestClient):
    admin_token = get_token(client, "admin")
    viewer_token = get_token(client, "viewer")

    # Non-existent
    resp_404 = client.get("/api/memory/MEM-NONEXISTENT", headers={"Authorization": f"Bearer {viewer_token}"})
    assert resp_404.status_code == 404

    # Create memory with admin
    payload = {
        "memory_id": "MEM-FETCH-001",
        "memory_type": "EVENT_CONTEXT",
        "content": "Known benign maintenance window context.",
        "confidence": 1.0,
    }
    client.post("/api/memory", headers={"Authorization": f"Bearer {admin_token}"}, json=payload)

    # Fetch with viewer
    resp_get = client.get("/api/memory/MEM-FETCH-001", headers={"Authorization": f"Bearer {viewer_token}"})
    assert resp_get.status_code == 200
    data = resp_get.json()
    assert data["memory_id"] == "MEM-FETCH-001"
    assert data["content"] == "Known benign maintenance window context."


def test_memory_filtering(client: TestClient):
    admin_token = get_token(client, "admin")
    viewer_token = get_token(client, "viewer")

    # Seed distinct memories
    client.post(
        "/api/memory",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "memory_id": "MEM-FILTER-ZONE",
            "memory_type": "ZONE_CONTEXT",
            "zone_id": "ZONE-01",
            "content": "Zone context filter test",
            "confidence": 0.85,
        },
    )
    client.post(
        "/api/memory",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "memory_id": "MEM-FILTER-CAM",
            "memory_type": "CAMERA_CONTEXT",
            "camera_id": "CAM-01",
            "content": "Camera context filter test",
            "confidence": 0.90,
        },
    )

    # Filter by memory_type
    resp_zone = client.get("/api/memory?memory_type=ZONE_CONTEXT", headers={"Authorization": f"Bearer {viewer_token}"})
    assert resp_zone.status_code == 200
    items_zone = resp_zone.json()
    assert any(m["memory_id"] == "MEM-FILTER-ZONE" for m in items_zone)
    assert not any(m["memory_id"] == "MEM-FILTER-CAM" for m in items_zone)

    # Filter by camera_id
    resp_cam = client.get("/api/memory?camera_id=CAM-01", headers={"Authorization": f"Bearer {viewer_token}"})
    assert resp_cam.status_code == 200
    items_cam = resp_cam.json()
    assert any(m["memory_id"] == "MEM-FILTER-CAM" for m in items_cam)


def test_memory_active_only_expiration_filter(client: TestClient):
    admin_token = get_token(client, "admin")
    viewer_token = get_token(client, "viewer")

    now = datetime.now(timezone.utc)
    expired_time = now - timedelta(hours=1)
    future_time = now + timedelta(days=1)

    # Expired memory
    client.post(
        "/api/memory",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "memory_id": "MEM-EXP-PAST",
            "memory_type": "EVENT_CONTEXT",
            "content": "Temporary alert context (expired)",
            "expires_at": expired_time.isoformat(),
        },
    )
    # Active memory
    client.post(
        "/api/memory",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "memory_id": "MEM-EXP-FUTURE",
            "memory_type": "EVENT_CONTEXT",
            "content": "Active persistent context",
            "expires_at": future_time.isoformat(),
        },
    )

    # Query with active_only=true
    resp = client.get("/api/memory?active_only=true", headers={"Authorization": f"Bearer {viewer_token}"})
    assert resp.status_code == 200
    mem_ids = [m["memory_id"] for m in resp.json()]
    assert "MEM-EXP-FUTURE" in mem_ids
    assert "MEM-EXP-PAST" not in mem_ids


# ==========================================
# 3. Referential Integrity Tests
# ==========================================

def test_memory_reference_validation_failures(client: TestClient):
    admin_token = get_token(client, "admin")

    # Invalid camera
    resp_cam = client.post(
        "/api/memory",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "memory_type": "CAMERA_CONTEXT",
            "camera_id": "CAM-NONEXISTENT",
            "content": "Bad camera link",
        },
    )
    assert resp_cam.status_code == 404
    assert "Camera 'CAM-NONEXISTENT' not found" in resp_cam.json()["detail"]

    # Invalid zone
    resp_zone = client.post(
        "/api/memory",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "memory_type": "ZONE_CONTEXT",
            "zone_id": "ZONE-NONEXISTENT",
            "content": "Bad zone link",
        },
    )
    assert resp_zone.status_code == 404
    assert "Zone 'ZONE-NONEXISTENT' not found" in resp_zone.json()["detail"]

    # Invalid event
    resp_evt = client.post(
        "/api/memory",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "memory_type": "EVENT_CONTEXT",
            "event_id": "EVT-NONEXISTENT",
            "content": "Bad event link",
        },
    )
    assert resp_evt.status_code == 404
    assert "Event 'EVT-NONEXISTENT' not found" in resp_evt.json()["detail"]


# ==========================================
# 4. Memory Update & Deletion Tests
# ==========================================

def test_memory_update_and_soft_delete(client: TestClient, db_session: Session):
    admin_token = get_token(client, "admin")

    # 1. Create
    client.post(
        "/api/memory",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "memory_id": "MEM-LIFECYCLE-01",
            "memory_type": "POLICY_CONTEXT",
            "content": "Initial policy baseline",
            "confidence": 0.8,
        },
    )

    # 2. Update
    patch_resp = client.patch(
        "/api/memory/MEM-LIFECYCLE-01",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "content": "Updated policy baseline narrative",
            "confidence": 0.95,
        },
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["content"] == "Updated policy baseline narrative"
    assert patch_resp.json()["confidence"] == 0.95

    # 3. Delete
    del_resp = client.delete(
        "/api/memory/MEM-LIFECYCLE-01",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True

    # 4. Verify subsequently not found
    get_resp = client.get(
        "/api/memory/MEM-LIFECYCLE-01",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert get_resp.status_code == 404

    # Verify soft-delete in database
    db_mem = db_session.query(SecurityMemoryModel).filter(SecurityMemoryModel.memory_id == "MEM-LIFECYCLE-01").first()
    assert db_mem is not None
    assert db_mem.is_deleted is True


# ==========================================
# 5. RBAC Authorization Tests
# ==========================================

def test_memory_unauthenticated_rejected(client: TestClient):
    resp_get = client.get("/api/memory")
    assert resp_get.status_code == 401

    resp_post = client.post("/api/memory", json={})
    assert resp_post.status_code == 401


def test_memory_viewer_denied_management(client: TestClient):
    viewer_token = get_token(client, "viewer")

    # Viewer cannot create memory
    resp_create = client.post(
        "/api/memory",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"memory_type": "EVENT_CONTEXT", "content": "Unauthorized create"},
    )
    assert resp_create.status_code == 403
    assert "memory.manage" in resp_create.json()["detail"]

    # Viewer cannot delete memory
    resp_delete = client.delete(
        "/api/memory/MEM-CUSTOM-001",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp_delete.status_code == 403
    assert "memory.manage" in resp_delete.json()["detail"]

    # Viewer CAN read memory
    resp_read = client.get("/api/memory", headers={"Authorization": f"Bearer {viewer_token}"})
    assert resp_read.status_code == 200
