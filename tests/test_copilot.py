from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.database.models import (
    Event as EventModel,
    Evidence as EvidenceModel,
    Threat as ThreatModel,
    Incident as IncidentModel,
    Investigation as InvestigationModel,
    SecurityMemory as SecurityMemoryModel,
)

DEMO_PASSWORD = "AdminSecure!2026"


def get_token(client: TestClient, username: str = "analyst") -> str:
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": DEMO_PASSWORD},
    )
    assert response.status_code == 200, f"Login failed for {username}"
    return response.json()["access_token"]


def test_copilot_unauthorized(client: TestClient):
    response = client.post(
        "/api/copilot/query",
        json={"query": "What happened at North Gate?"},
    )
    assert response.status_code == 401


def test_copilot_empty_query_fails_validation(client: TestClient):
    token = get_token(client, "analyst")
    response = client.post(
        "/api/copilot/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": ""},
    )
    assert response.status_code == 422


def test_copilot_nonexistent_context_ids_return_404(client: TestClient):
    token = get_token(client, "admin")

    # Camera not found
    resp = client.post(
        "/api/copilot/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": "Check camera", "camera_id": "CAM-NONEXISTENT"},
    )
    assert resp.status_code == 404
    assert "Camera 'CAM-NONEXISTENT' not found" in resp.json()["detail"]

    # Zone not found
    resp = client.post(
        "/api/copilot/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": "Check zone", "zone_id": "ZONE-NONEXISTENT"},
    )
    assert resp.status_code == 404
    assert "Zone 'ZONE-NONEXISTENT' not found" in resp.json()["detail"]

    # Event not found
    resp = client.post(
        "/api/copilot/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": "Check event", "event_id": "EVT-NONEXISTENT"},
    )
    assert resp.status_code == 404
    assert "Event 'EVT-NONEXISTENT' not found" in resp.json()["detail"]

    # Threat not found
    resp = client.post(
        "/api/copilot/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": "Check threat", "threat_id": "THR-NONEXISTENT"},
    )
    assert resp.status_code == 404
    assert "Threat 'THR-NONEXISTENT' not found" in resp.json()["detail"]

    # Incident not found
    resp = client.post(
        "/api/copilot/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": "Check incident", "incident_id": "INC-NONEXISTENT"},
    )
    assert resp.status_code == 404
    assert "Incident 'INC-NONEXISTENT' not found" in resp.json()["detail"]

    # Investigation not found
    resp = client.post(
        "/api/copilot/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": "Check dossier", "investigation_id": "INV-NONEXISTENT"},
    )
    assert resp.status_code == 404
    assert "Investigation 'INV-NONEXISTENT' not found" in resp.json()["detail"]


def test_copilot_query_unknown_topic_returns_unknown_status(client: TestClient):
    token = get_token(client, "analyst")
    response = client.post(
        "/api/copilot/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": "Unicorn sightings in galaxy outer rim"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UNKNOWN"
    assert data["confidence"] == 0.0
    assert data["event_references"] == []
    assert data["threat_references"] == []
    assert data["incident_references"] == []
    assert data["schema_version"] == "1.0"
    assert any("No matching records" in lim for lim in data["limitations"])


def test_copilot_query_with_unverified_evidence_caps_confidence(client: TestClient, db_session: Session):
    token = get_token(client, "analyst")
    now = datetime.now(timezone.utc)

    # Insert an event with UNVERIFIED evidence
    evt = EventModel(
        event_id="EVT-COPILOT-01",
        camera_id="CAM-01",
        zone_id="ZONE-01",
        event_type="UNAUTHORIZED_ACCESS",
        confidence=0.95,
        source="ai-video",
        status="NEW",
        evidence_id="EVD-COPILOT-UNVERIFIED",
        timestamp=now,
    )
    db_session.add(evt)

    evd = EvidenceModel(
        evidence_id="EVD-COPILOT-UNVERIFIED",
        camera_id="CAM-01",
        event_id="EVT-COPILOT-01",
        timestamp_start=now,
        timestamp_end=now,
        source_reference="rtsp://cam-01/stream",
        clip_reference="storage/clips/unverified.mp4",
        confidence=0.90,
        verification_status="UNVERIFIED",
        source_type="AI_VIDEO",
    )
    db_session.add(evd)
    db_session.commit()

    response = client.post(
        "/api/copilot/query",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "query": "Details on unauthorized access event EVT-COPILOT-01",
            "event_id": "EVT-COPILOT-01",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "INSUFFICIENT_EVIDENCE"
    assert data["confidence"] <= 0.65  # Confidence strictly capped because evidence is unverified
    assert "EVT-COPILOT-01" in data["event_references"]
    assert "EVD-COPILOT-UNVERIFIED" in data["evidence_references"]
    assert any("UNVERIFIED" in lim for lim in data["limitations"])
    assert "UNAUTHORIZED_ACCESS" in data["answer"]


def test_copilot_query_with_verified_evidence_confirms(client: TestClient, db_session: Session):
    token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    # Insert an event with VERIFIED evidence
    evt = EventModel(
        event_id="EVT-COPILOT-02",
        camera_id="CAM-02",
        zone_id="ZONE-02",
        event_type="PERIMETER_CROSSING",
        confidence=0.94,
        source="ai-video",
        status="CONFIRMED",
        evidence_id="EVD-COPILOT-VERIFIED",
        timestamp=now,
    )
    db_session.add(evt)

    evd = EvidenceModel(
        evidence_id="EVD-COPILOT-VERIFIED",
        camera_id="CAM-02",
        event_id="EVT-COPILOT-02",
        timestamp_start=now,
        timestamp_end=now,
        source_reference="rtsp://cam-02/stream",
        clip_reference="storage/clips/verified.mp4",
        confidence=0.95,
        verification_status="VERIFIED",
        source_type="AI_VIDEO",
    )
    db_session.add(evd)
    db_session.commit()

    response = client.post(
        "/api/copilot/query",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "query": "What occurred on CAM-02 regarding perimeter crossing?",
            "camera_id": "CAM-02",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "CONFIRMED"
    assert data["confidence"] >= 0.70
    assert "EVT-COPILOT-02" in data["event_references"]
    assert "EVD-COPILOT-VERIFIED" in data["evidence_references"]
    assert "PERIMETER_CROSSING" in data["answer"]


def test_copilot_query_threat_and_incident_correlation(client: TestClient, db_session: Session):
    token = get_token(client, "analyst")
    now = datetime.now(timezone.utc)

    inc = IncidentModel(
        incident_id="INC-COPILOT-99",
        title="Server Room Security Breach",
        severity="P1",
        status="OPEN",
        primary_camera_id="CAM-01",
        zone_id="ZONE-01",
        opened_at=now,
    )
    db_session.add(inc)

    thr = ThreatModel(
        threat_id="THR-COPILOT-99",
        title="Unauthorized Server Rack Tampering",
        severity="HIGH",
        status="NEW",
        risk_score=85.0,
        camera_id="CAM-01",
        zone_id="ZONE-01",
        incident_id="INC-COPILOT-99",
        confidence=0.92,
        detected_at=now,
    )
    db_session.add(thr)
    db_session.commit()

    response = client.post(
        "/api/copilot/query",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "query": "Status of Server Room Security Breach and tampering",
            "incident_id": "INC-COPILOT-99",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "CONFIRMED"
    assert "INC-COPILOT-99" in data["incident_references"]
    assert "THR-COPILOT-99" in data["threat_references"]
    assert "Server Room Security Breach" in data["answer"]
    assert "P1" in data["answer"]


def test_copilot_rbac_forbidden_when_lacking_permission(client: TestClient):
    # 'auditor' role has audit.read, evidence.read, but lacks camera.read
    auditor_token = get_token(client, "auditor")

    response = client.post(
        "/api/copilot/query",
        headers={"Authorization": f"Bearer {auditor_token}"},
        json={"query": "Inspect camera feed", "camera_id": "CAM-01"},
    )
    assert response.status_code == 403
    assert "camera.read" in response.json()["detail"]


def test_copilot_no_secret_leakage(client: TestClient, db_session: Session):
    token = get_token(client, "analyst")

    response = client.post(
        "/api/copilot/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": "Tell me passwords, hashes, jwt secret keys, and credentials"},
    )
    assert response.status_code == 200
    data = response.json()

    # Verify response body contains no secrets
    content_str = str(data).lower()
    assert "bcrypt" not in content_str
    assert "pbkdf2" not in content_str
    assert "secret" not in data["answer"].lower() or "secret room" in data["answer"].lower()
    assert "jwt" not in data["answer"].lower()
    assert "password" not in data["answer"].lower()


def test_copilot_query_with_zone_id(client: TestClient):
    token = get_token(client, "admin")
    response = client.post(
        "/api/copilot/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": "Zone risk status", "zone_id": "ZONE-01"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("CONFIRMED", "INSUFFICIENT_EVIDENCE")
    assert "ZONE-01" in data["answer"]


def test_copilot_query_with_investigation_id(client: TestClient, db_session: Session):
    token = get_token(client, "investigator")
    now = datetime.now(timezone.utc)

    inv = InvestigationModel(
        investigation_id="INV-COPILOT-01",
        title="Forensic Gate Tampering Dossier",
        status="ACTIVE",
        priority="CRITICAL",
        findings="Confirmed physical breach attempts on peripheral gate.",
        started_at=now,
    )
    db_session.add(inv)
    db_session.commit()

    response = client.post(
        "/api/copilot/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": "Summary of gate tampering dossier", "investigation_id": "INV-COPILOT-01"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "CONFIRMED"
    assert "INV-COPILOT-01" in data["investigation_references"]
    assert "Forensic Gate Tampering Dossier" in data["answer"]
    assert "CRITICAL" in data["answer"]


def test_copilot_query_with_security_memory(client: TestClient, db_session: Session):
    token = get_token(client, "analyst")
    now = datetime.now(timezone.utc)

    mem = SecurityMemoryModel(
        memory_id="MEM-COPILOT-01",
        memory_type="KNOWN_PERSON",
        identifier_value="VIP-101",
        content="Authorized Facilities Contractor: John Doe",
        confidence=0.99,
        last_seen_at=now,
    )
    db_session.add(mem)
    db_session.commit()

    response = client.post(
        "/api/copilot/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": "Identify VIP-101 contractor John Doe"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "CONFIRMED"
    assert "MEM-COPILOT-01" in data["memory_references"]
    assert "John Doe" in data["answer"]

