from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.database.models import Event as EventModel, Evidence as EvidenceModel

DEMO_PASSWORD = "AdminSecure!2026"


def get_token(client: TestClient, username: str = "operator") -> str:
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": DEMO_PASSWORD},
    )
    assert response.status_code == 200, f"Login failed for {username}"
    return response.json()["access_token"]


# ==========================================
# Step 10 — AI Video Integration Contract Tests
# ==========================================

def test_valid_ai_video_event_ingestion(client: TestClient, db_session: Session):
    token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    payload = {
        "event": {
            "event_id": "EVT-AIVIDEO-001",
            "camera_id": "CAM-01",
            "timestamp": now.isoformat(),
            "event_type": "PERSON_DETECTED",
            "entity_id": "ENT-PERSON-001",
            "zone_id": "ZONE-01",
            "confidence": 0.94,
            "source": "AI_VIDEO",
            "status": "NEW",
            "schema_version": "1.0",
            "metadata_json": {"bounding_box": [10, 20, 100, 200], "model": "yolo-surveillance-v8"},
        },
        "source": "AI_VIDEO",
        "validate_evidence": False,
    }

    response = client.post(
        "/api/integrations/ai-video/events",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "INGESTED"
    assert data["deduplicated"] is False
    assert data["event"]["event_id"] == "EVT-AIVIDEO-001"
    assert data["event"]["confidence"] == 0.94

    # Verify DB persistence
    db_evt = db_session.query(EventModel).filter(EventModel.event_id == "EVT-AIVIDEO-001").first()
    assert db_evt is not None
    assert db_evt.camera_id == "CAM-01"
    assert db_evt.zone_id == "ZONE-01"


def test_ai_video_event_invalid_schema_rejected(client: TestClient):
    token = get_token(client, "operator")

    # Missing required camera_id and event_type
    bad_payload = {
        "event": {
            "event_id": "EVT-BAD-001",
            "confidence": 0.8,
        }
    }
    response = client.post(
        "/api/integrations/ai-video/events",
        headers={"Authorization": f"Bearer {token}"},
        json=bad_payload,
    )
    assert response.status_code == 422


def test_ai_video_unknown_camera_rejected(client: TestClient):
    token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    payload = {
        "event": {
            "event_id": "EVT-AIVIDEO-NOCAM-01",
            "camera_id": "CAM-NONEXISTENT",
            "timestamp": now.isoformat(),
            "event_type": "VEHICLE_DETECTED",
            "confidence": 0.85,
        }
    }
    response = client.post(
        "/api/integrations/ai-video/events",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert response.status_code == 404
    assert "Camera with id 'CAM-NONEXISTENT' does not exist" in response.json()["detail"]


def test_ai_video_unknown_zone_rejected(client: TestClient):
    token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    payload = {
        "event": {
            "event_id": "EVT-AIVIDEO-NOZONE-01",
            "camera_id": "CAM-01",
            "zone_id": "ZONE-NONEXISTENT",
            "timestamp": now.isoformat(),
            "event_type": "ZONE_ENTRY",
            "confidence": 0.85,
        }
    }
    response = client.post(
        "/api/integrations/ai-video/events",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert response.status_code == 404
    assert "Zone with id 'ZONE-NONEXISTENT' does not exist" in response.json()["detail"]


def test_ai_video_invalid_confidence_rejected(client: TestClient):
    token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    # Confidence > 1.0
    payload = {
        "event": {
            "event_id": "EVT-AIVIDEO-CONF-01",
            "camera_id": "CAM-01",
            "timestamp": now.isoformat(),
            "event_type": "SUSPICIOUS_ACTIVITY",
            "confidence": 1.5,
        }
    }
    response = client.post(
        "/api/integrations/ai-video/events",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert response.status_code == 422


def test_ai_video_event_idempotency_and_deduplication(client: TestClient, db_session: Session):
    token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    payload = {
        "event": {
            "event_id": "EVT-AIVIDEO-DUP-01",
            "camera_id": "CAM-01",
            "timestamp": now.isoformat(),
            "event_type": "OBJECT_DETECTED",
            "confidence": 0.90,
            "source": "AI_VIDEO",
        }
    }

    # 1. First emission
    resp1 = client.post(
        "/api/integrations/ai-video/events",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert resp1.status_code == 200
    assert resp1.json()["deduplicated"] is False
    assert resp1.json()["status"] == "INGESTED"

    # 2. Second emission with same event_id
    resp2 = client.post(
        "/api/integrations/ai-video/events",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert resp2.status_code == 200
    assert resp2.json()["deduplicated"] is True
    assert resp2.json()["status"] == "DUPLICATE"

    # Verify no duplicate rows in database
    count = db_session.query(EventModel).filter(EventModel.event_id == "EVT-AIVIDEO-DUP-01").count()
    assert count == 1


def test_ai_video_valid_evidence_reference(client: TestClient):
    token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    # 1. Seed valid evidence
    evd_payload = {
        "evidence_id": "EVD-AIVIDEO-REF-01",
        "camera_id": "CAM-01",
        "timestamp_start": now.isoformat(),
        "timestamp_end": now.isoformat(),
        "source_reference": "rtsp://live/cam-01",
        "clip_reference": "storage/clips/clip_valid.mp4",
        "confidence": 0.92,
    }
    client.post("/api/evidence", headers={"Authorization": f"Bearer {token}"}, json=evd_payload)

    # 2. Emit event citing existing evidence
    event_payload = {
        "event": {
            "event_id": "EVT-AIVIDEO-EVD-VALID-01",
            "camera_id": "CAM-01",
            "timestamp": now.isoformat(),
            "event_type": "EVIDENCE_AVAILABLE",
            "confidence": 0.95,
            "evidence_id": "EVD-AIVIDEO-REF-01",
            "source": "AI_VIDEO",
        },
        "validate_evidence": True,
    }

    response = client.post(
        "/api/integrations/ai-video/events",
        headers={"Authorization": f"Bearer {token}"},
        json=event_payload,
    )
    assert response.status_code == 200
    assert response.json()["event"]["evidence_id"] == "EVD-AIVIDEO-REF-01"


def test_ai_video_invalid_evidence_reference_rejected(client: TestClient):
    token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    event_payload = {
        "event": {
            "event_id": "EVT-AIVIDEO-EVD-BAD-01",
            "camera_id": "CAM-01",
            "timestamp": now.isoformat(),
            "event_type": "EVIDENCE_AVAILABLE",
            "confidence": 0.90,
            "evidence_id": "EVD-NONEXISTENT-999",
            "source": "AI_VIDEO",
        },
        "validate_evidence": True,
    }

    response = client.post(
        "/api/integrations/ai-video/events",
        headers={"Authorization": f"Bearer {token}"},
        json=event_payload,
    )
    assert response.status_code == 400
    assert "Referenced evidence 'EVD-NONEXISTENT-999' does not exist" in response.json()["detail"]


def test_ai_video_compound_event_with_evidence_ingestion(client: TestClient, db_session: Session):
    token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    payload = {
        "event": {
            "event_id": "EVT-AIVIDEO-COMPOUND-01",
            "camera_id": "CAM-02",
            "timestamp": now.isoformat(),
            "event_type": "SUSPICIOUS_ACTIVITY",
            "confidence": 0.88,
            "source": "AI_VIDEO",
        },
        "evidence": {
            "evidence_id": "EVD-AIVIDEO-COMPOUND-01",
            "camera_id": "CAM-02",
            "timestamp_start": now.isoformat(),
            "timestamp_end": now.isoformat(),
            "source_reference": "rtsp://live/cam-02",
            "clip_reference": "storage/clips/cam-02/compound.mp4",
            "confidence": 0.88,
        },
        "source": "AI_VIDEO",
    }

    response = client.post(
        "/api/integrations/ai-video/events-with-evidence",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["evidence_id"] == "EVD-AIVIDEO-COMPOUND-01"
    # Strictly registered as UNVERIFIED
    assert data["evidence_status"] == "UNVERIFIED"

    # Verify both DB records
    db_evt = db_session.query(EventModel).filter(EventModel.event_id == "EVT-AIVIDEO-COMPOUND-01").first()
    assert db_evt is not None
    assert db_evt.evidence_id == "EVD-AIVIDEO-COMPOUND-01"

    db_evd = db_session.query(EvidenceModel).filter(EvidenceModel.evidence_id == "EVD-AIVIDEO-COMPOUND-01").first()
    assert db_evd is not None
    assert db_evd.verification_status == "UNVERIFIED"


def test_ai_video_rbac_unauthenticated_rejected(client: TestClient):
    resp = client.post("/api/integrations/ai-video/events", json={})
    assert resp.status_code == 401


def test_ai_video_gateway_status_endpoint(client: TestClient):
    token = get_token(client, "viewer")
    response = client.get(
        "/api/integrations/ai-video/status",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ONLINE"
    assert data["schema_version"] == "1.0"
    assert "AI_VIDEO" in data["supported_sources"]


def test_ai_video_compatibility_with_existing_event_ingestion(client: TestClient, db_session: Session):
    token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    # Ingest event through AI Video contract
    payload = {
        "event": {
            "event_id": "EVT-AIVIDEO-COMPAT-01",
            "camera_id": "CAM-01",
            "timestamp": now.isoformat(),
            "event_type": "BLINDSPOT_DETECTED",
            "confidence": 0.91,
            "source": "AI_VIDEO",
        }
    }
    client.post(
        "/api/integrations/ai-video/events",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )

    # Verify event is queryable via standard /api/events endpoint
    resp_get = client.get(
        "/api/events/EVT-AIVIDEO-COMPAT-01",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp_get.status_code == 200
    assert resp_get.json()["event_id"] == "EVT-AIVIDEO-COMPAT-01"
    assert resp_get.json()["event_type"] == "BLINDSPOT_DETECTED"
