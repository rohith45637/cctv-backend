from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.database.models import Event as EventModel, EventEntity
from src.events.types import EventType

DEMO_PASSWORD = "AdminSecure!2026"


def get_auth_token(client: TestClient, username: str = "operator") -> str:
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": DEMO_PASSWORD},
    )
    assert response.status_code == 200, f"Login failed for {username}"
    return response.json()["access_token"]


# ==========================================
# Step 5 Event Ingestion & Deduplication Tests
# ==========================================

def test_valid_event_ingestion(client: TestClient, db_session: Session):
    token = get_auth_token(client, "operator")
    now = datetime.now(timezone.utc)

    payload = {
        "event_id": "EVT-TEST-INGEST-01",
        "camera_id": "CAM-01",
        "timestamp": now.isoformat(),
        "event_type": EventType.PERSON_DETECTED.value,
        "entity_id": "ENT-PERSON-101",
        "zone_id": "ZONE-01",
        "confidence": 0.94,
        "evidence_id": "EVD-CLIP-101",
        "source": "ai-video",
        "status": "NEW",
        "schema_version": "1.0",
        "metadata_json": {"bounding_box": [10, 20, 100, 200]},
    }

    response = client.post(
        "/api/events",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "INGESTED"
    assert data["deduplicated"] is False
    assert data["event"]["event_id"] == "EVT-TEST-INGEST-01"
    assert data["event"]["camera_id"] == "CAM-01"
    assert data["event"]["confidence"] == 0.94

    # Verify database persistence
    db_event = db_session.query(EventModel).filter(EventModel.event_id == "EVT-TEST-INGEST-01").first()
    assert db_event is not None
    assert db_event.event_type == "PERSON_DETECTED"
    assert db_event.camera.name == "[DEMO] CAM-01 Main Gate"
    assert db_event.zone.name == "[DEMO] Perimeter - Main Gate"

    # Verify relational EventEntity was created
    entity = db_session.query(EventEntity).filter(EventEntity.event_id == "EVT-TEST-INGEST-01").first()
    assert entity is not None
    assert entity.entity_id == "ENT-PERSON-101"
    assert entity.entity_type == "PERSON"


def test_malformed_event_rejection(client: TestClient):
    token = get_auth_token(client, "operator")
    now = datetime.now(timezone.utc)

    # 1. Invalid confidence (> 1.0)
    bad_confidence = {
        "event_id": "EVT-BAD-CONF",
        "camera_id": "CAM-01",
        "timestamp": now.isoformat(),
        "event_type": "PERSON_DETECTED",
        "confidence": 1.8,
    }
    res1 = client.post("/api/events", headers={"Authorization": f"Bearer {token}"}, json=bad_confidence)
    assert res1.status_code == 422

    # 2. Invalid event_id format (must start with EVT-)
    bad_id = {
        "event_id": "INVALID-FORMAT-ID",
        "camera_id": "CAM-01",
        "timestamp": now.isoformat(),
        "event_type": "PERSON_DETECTED",
        "confidence": 0.85,
    }
    res2 = client.post("/api/events", headers={"Authorization": f"Bearer {token}"}, json=bad_id)
    assert res2.status_code == 422

    # 3. Nonexistent camera_id
    bad_cam = {
        "event_id": "EVT-BAD-CAM-99",
        "camera_id": "CAM-NONEXISTENT-999",
        "timestamp": now.isoformat(),
        "event_type": "PERSON_DETECTED",
        "confidence": 0.85,
    }
    res3 = client.post("/api/events", headers={"Authorization": f"Bearer {token}"}, json=bad_cam)
    assert res3.status_code == 404
    assert "does not exist" in res3.json()["detail"].lower()


def test_duplicate_event_id_deduplication(client: TestClient, db_session: Session):
    token = get_auth_token(client, "operator")
    now = datetime.now(timezone.utc)

    payload = {
        "event_id": "EVT-DEDUP-TEST-01",
        "camera_id": "CAM-01",
        "timestamp": now.isoformat(),
        "event_type": EventType.ZONE_ENTRY.value,
        "confidence": 0.88,
        "source": "ai-video",
        "schema_version": "1.0",
    }

    # First ingestion -> INGESTED
    res1 = client.post("/api/events", headers={"Authorization": f"Bearer {token}"}, json=payload)
    assert res1.status_code == 200
    assert res1.json()["status"] == "INGESTED"
    assert res1.json()["deduplicated"] is False

    # Second ingestion with same event_id -> DUPLICATE
    res2 = client.post("/api/events", headers={"Authorization": f"Bearer {token}"}, json=payload)
    assert res2.status_code == 200
    assert res2.json()["status"] == "DUPLICATE"
    assert res2.json()["deduplicated"] is True
    assert res2.json()["event"]["event_id"] == "EVT-DEDUP-TEST-01"

    # Verify only 1 database record exists
    count = db_session.query(EventModel).filter(EventModel.event_id == "EVT-DEDUP-TEST-01").count()
    assert count == 1


def test_temporal_deduplication(client: TestClient, db_session: Session):
    token = get_auth_token(client, "operator")
    now = datetime.now(timezone.utc)

    # First event
    payload1 = {
        "event_id": "EVT-TEMP-01",
        "camera_id": "CAM-02",
        "timestamp": now.isoformat(),
        "event_type": EventType.VEHICLE_DETECTED.value,
        "entity_id": "ENT-CAR-01",
        "zone_id": "ZONE-02",
        "confidence": 0.91,
        "source": "ai-video",
        "schema_version": "1.0",
    }
    res1 = client.post("/api/events", headers={"Authorization": f"Bearer {token}"}, json=payload1)
    assert res1.status_code == 200
    assert res1.json()["deduplicated"] is False

    # Second event 2 seconds later with different event_id but identical camera/zone/entity/event_type
    payload2 = {
        "event_id": "EVT-TEMP-02",
        "camera_id": "CAM-02",
        "timestamp": now.isoformat(),
        "event_type": EventType.VEHICLE_DETECTED.value,
        "entity_id": "ENT-CAR-01",
        "zone_id": "ZONE-02",
        "confidence": 0.91,
        "source": "ai-video",
        "schema_version": "1.0",
    }
    res2 = client.post(
        "/api/events?dedup_window_seconds=10",
        headers={"Authorization": f"Bearer {token}"},
        json=payload2,
    )
    assert res2.status_code == 200
    assert res2.json()["status"] == "DUPLICATE"
    assert res2.json()["deduplicated"] is True
    assert res2.json()["event"]["event_id"] == "EVT-TEMP-01"


def test_event_retrieval_endpoints(client: TestClient):
    token = get_auth_token(client, "operator")
    now = datetime.now(timezone.utc)

    # Ingest an event to ensure at least one event exists
    ingest_payload = {
        "event_id": "EVT-RETRIEVAL-01",
        "camera_id": "CAM-01",
        "timestamp": now.isoformat(),
        "event_type": "ZONE_ENTRY",
        "confidence": 0.89,
        "source": "ai-video",
        "schema_version": "1.0",
    }
    ingest_res = client.post("/api/events", headers={"Authorization": f"Bearer {token}"}, json=ingest_payload)
    assert ingest_res.status_code == 200

    # 1. List events
    res_list = client.get("/api/events", headers={"Authorization": f"Bearer {token}"})
    assert res_list.status_code == 200
    events = res_list.json()
    assert isinstance(events, list)
    assert len(events) >= 1

    # 2. Get single event
    res_single = client.get("/api/events/EVT-RETRIEVAL-01", headers={"Authorization": f"Bearer {token}"})
    assert res_single.status_code == 200
    assert res_single.json()["event_id"] == "EVT-RETRIEVAL-01"

    # 3. Nonexistent event -> 404
    res_404 = client.get("/api/events/EVT-NONEXISTENT-999", headers={"Authorization": f"Bearer {token}"})
    assert res_404.status_code == 404


def test_unauthenticated_event_ingest_rejected(client: TestClient):
    now = datetime.now(timezone.utc)
    payload = {
        "event_id": "EVT-UNAUTH-01",
        "camera_id": "CAM-01",
        "timestamp": now.isoformat(),
        "event_type": "PERSON_DETECTED",
        "confidence": 0.8,
    }
    response = client.post("/api/events", json=payload)
    assert response.status_code == 401
