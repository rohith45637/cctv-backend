from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.database.models import (
    Investigation as InvestigationModel,
    Incident as IncidentModel,
    Event as EventModel,
    Threat as ThreatModel,
    Evidence as EvidenceModel,
)

DEMO_PASSWORD = "AdminSecure!2026"


def get_token(client: TestClient, username: str = "investigator") -> str:
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": DEMO_PASSWORD},
    )
    assert response.status_code == 200, f"Login failed for {username}"
    return response.json()["access_token"]


# ==========================================
# 1. Investigation Creation & Relationships
# ==========================================

def test_investigation_creation_success(client: TestClient, db_session: Session):
    token = get_token(client, "investigator")

    payload = {
        "investigation_id": "INV-TEST-001",
        "title": "Perimeter Breach Dossier",
        "description": "Investigating suspicious line crossing at North Gate",
        "priority": "HIGH",
        "status": "PENDING",
    }

    response = client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert response.status_code == 201
    data = response.json()

    assert data["investigation_id"] == "INV-TEST-001"
    assert data["title"] == "Perimeter Breach Dossier"
    assert data["status"] == "PENDING"
    assert data["priority"] == "HIGH"
    assert data["started_at"] is not None
    assert data["completed_at"] is None

    # Verify DB persistence
    db_inv = db_session.query(InvestigationModel).filter(InvestigationModel.investigation_id == "INV-TEST-001").first()
    assert db_inv is not None
    assert db_inv.title == "Perimeter Breach Dossier"
    assert db_inv.priority == "HIGH"


def test_investigation_creation_with_relationships(client: TestClient, db_session: Session):
    op_token = get_token(client, "operator")
    inv_token = get_token(client, "investigator")
    now = datetime.now(timezone.utc)

    # 1. Ingest event with operator
    evt_payload = {
        "event_id": "EVT-INV-LINK-01",
        "camera_id": "CAM-01",
        "timestamp": now.isoformat(),
        "event_type": "LINE_CROSSING",
        "confidence": 0.95,
        "source": "ai-video",
        "status": "NEW",
    }
    client.post("/api/events", headers={"Authorization": f"Bearer {op_token}"}, json=evt_payload)

    # 2. Evaluate threat with operator (operator has threat.manage)
    client.post(
        "/api/threats/evaluate",
        headers={"Authorization": f"Bearer {op_token}"},
        json={"event_id": "EVT-INV-LINK-01", "force_escalate": True},
    )

    # Fetch created threat
    threat = db_session.query(ThreatModel).filter(ThreatModel.event_id == "EVT-INV-LINK-01").first()
    threat_id = threat.threat_id if threat else None

    # 3. Create Incident with operator (operator has incident.manage)
    inc_payload = {
        "title": "Perimeter Breach Incident",
        "severity": "P1",
        "primary_camera_id": "CAM-01",
        "threat_id": threat_id,
    }
    resp_inc = client.post("/api/incidents", headers={"Authorization": f"Bearer {op_token}"}, json=inc_payload)
    assert resp_inc.status_code in (200, 201), f"Incident creation failed: {resp_inc.text}"
    inc_id = resp_inc.json()["incident_id"]

    # 4. Create Investigation linking incident, event, threat, assigned user with investigator
    inv_payload = {
        "investigation_id": "INV-REL-001",
        "title": "Linked Forensic Case",
        "incident_id": inc_id,
        "trigger_event_id": "EVT-INV-LINK-01",
        "trigger_threat_id": threat_id,
        "assigned_user_id": "USR-INVESTIGATOR01",
        "priority": "CRITICAL",
    }
    resp_inv = client.post("/api/investigations", headers={"Authorization": f"Bearer {inv_token}"}, json=inv_payload)
    assert resp_inv.status_code == 201
    inv_data = resp_inv.json()
    assert inv_data["incident_id"] == inc_id
    assert inv_data["trigger_event_id"] == "EVT-INV-LINK-01"
    assert inv_data["assigned_user_id"] == "USR-INVESTIGATOR01"

    # Verify DB relationship
    db_inv = db_session.query(InvestigationModel).filter(InvestigationModel.investigation_id == "INV-REL-001").first()
    assert db_inv.incident is not None
    assert db_inv.trigger_event is not None
    assert db_inv.assigned_user.username == "investigator"


def test_investigation_creation_nonexistent_reference_rejected(client: TestClient):
    token = get_token(client, "investigator")
    payload = {
        "title": "Bad Link Investigation",
        "incident_id": "INC-NONEXISTENT",
    }
    resp = client.post("/api/investigations", headers={"Authorization": f"Bearer {token}"}, json=payload)
    assert resp.status_code == 404
    assert "Incident 'INC-NONEXISTENT' not found" in resp.json()["detail"]


# ==========================================
# 2. Investigation Retrieval & Filtering
# ==========================================

def test_investigation_retrieval(client: TestClient):
    token = get_token(client, "viewer")
    inv_token = get_token(client, "investigator")

    # Create one
    client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={"investigation_id": "INV-GET-001", "title": "Retrieval Test Case", "priority": "LOW"},
    )

    # Get by ID with viewer
    resp_get = client.get("/api/investigations/INV-GET-001", headers={"Authorization": f"Bearer {token}"})
    assert resp_get.status_code == 200
    assert resp_get.json()["investigation_id"] == "INV-GET-001"

    # List with filtering
    resp_list = client.get("/api/investigations?priority=LOW", headers={"Authorization": f"Bearer {token}"})
    assert resp_list.status_code == 200
    ids = [i["investigation_id"] for i in resp_list.json()]
    assert "INV-GET-001" in ids


# ==========================================
# 3. Lifecycle State Transitions
# ==========================================

def test_valid_investigation_state_transitions(client: TestClient, db_session: Session):
    token = get_token(client, "investigator")

    # 1. Create PENDING
    resp_create = client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {token}"},
        json={"investigation_id": "INV-LIFECYCLE-001", "title": "Lifecycle Test"},
    )
    assert resp_create.status_code == 201
    assert resp_create.json()["status"] == "PENDING"

    # 2. Transition PENDING -> ACTIVE
    resp_active = client.patch(
        "/api/investigations/INV-LIFECYCLE-001",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "ACTIVE"},
    )
    assert resp_active.status_code == 200
    assert resp_active.json()["status"] == "ACTIVE"

    # 3. Transition ACTIVE -> PAUSED
    resp_paused = client.patch(
        "/api/investigations/INV-LIFECYCLE-001",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "PAUSED"},
    )
    assert resp_paused.status_code == 200
    assert resp_paused.json()["status"] == "PAUSED"

    # 4. Transition PAUSED -> ACTIVE
    resp_resume = client.patch(
        "/api/investigations/INV-LIFECYCLE-001",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "ACTIVE"},
    )
    assert resp_resume.status_code == 200
    assert resp_resume.json()["status"] == "ACTIVE"

    # 5. Transition ACTIVE -> COMPLETED
    resp_complete = client.patch(
        "/api/investigations/INV-LIFECYCLE-001",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "COMPLETED", "findings": "Root cause identified: faulty magnetic door latch."},
    )
    assert resp_complete.status_code == 200
    data = resp_complete.json()
    assert data["status"] == "COMPLETED"
    assert data["completed_at"] is not None
    assert "faulty magnetic door latch" in data["findings"]


def test_invalid_investigation_state_transition_rejected(client: TestClient):
    token = get_token(client, "investigator")

    # 1. Create PENDING
    client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {token}"},
        json={"investigation_id": "INV-INVALID-TRANS-01", "title": "Invalid Transition Test"},
    )

    # 2. Attempt illegal transition PENDING -> COMPLETED directly (must be ACTIVE first)
    resp_illegal = client.patch(
        "/api/investigations/INV-INVALID-TRANS-01",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "COMPLETED"},
    )
    assert resp_illegal.status_code == 400
    assert "Invalid state transition" in resp_illegal.json()["detail"]


# ==========================================
# 4. RBAC Authorization
# ==========================================

def test_investigation_rbac_unauthenticated_rejected(client: TestClient):
    resp = client.get("/api/investigations")
    assert resp.status_code == 401

    resp_post = client.post("/api/investigations", json={})
    assert resp_post.status_code == 401


def test_investigation_rbac_viewer_denied_creation_and_update(client: TestClient):
    viewer_token = get_token(client, "viewer")
    inv_token = get_token(client, "investigator")

    # Seed one investigation with investigator
    client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={"investigation_id": "INV-RBAC-VIEWER-01", "title": "RBAC Case"},
    )

    # Viewer cannot create
    resp_create = client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"title": "Unauthorized Dossier"},
    )
    assert resp_create.status_code == 403
    assert "investigation.create" in resp_create.json()["detail"]

    # Viewer cannot update
    resp_patch = client.patch(
        "/api/investigations/INV-RBAC-VIEWER-01",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"status": "ACTIVE"},
    )
    assert resp_patch.status_code == 403
    assert "investigation.create" in resp_patch.json()["detail"]

    # Viewer CAN read
    resp_read = client.get("/api/investigations", headers={"Authorization": f"Bearer {viewer_token}"})
    assert resp_read.status_code == 200


# ==========================================
# 5. AI Agent Integration Contract Tests
# ==========================================

def test_ai_agent_request_packet_generation(client: TestClient):
    token = get_token(client, "investigator")

    # Seed investigation
    client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {token}"},
        json={"investigation_id": "INV-AGENT-REQ-01", "title": "Agent Packet Case"},
    )

    resp_req = client.post(
        "/api/investigations/INV-AGENT-REQ-01/agent-request",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp_req.status_code == 200
    packet = resp_req.json()
    assert packet["investigation_id"] == "INV-AGENT-REQ-01"
    assert packet["requested_action"] == "ANALYZE_INCIDENT"
    assert packet["schema_version"] == "1.0"
    assert isinstance(packet["evidence_ids"], list)


def test_ai_agent_response_validation_and_safety(client: TestClient, db_session: Session):
    token = get_token(client, "investigator")

    # 1. Seed investigation
    client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {token}"},
        json={"investigation_id": "INV-AGENT-RESP-01", "title": "Agent Response Case"},
    )

    # 2. Seed valid evidence to reference
    t_now = datetime.now(timezone.utc)
    evd_payload = {
        "evidence_id": "EVD-AGENT-001",
        "camera_id": "CAM-01",
        "timestamp_start": t_now.isoformat(),
        "timestamp_end": t_now.isoformat(),
        "source_reference": "rtsp://feed/agent",
        "clip_reference": "storage/agent_clip.mp4",
        "confidence": 0.95,
    }
    client.post("/api/evidence", headers={"Authorization": f"Bearer {token}"}, json=evd_payload)

    # 3. Agent response with valid evidence reference and high confidence
    agent_response_payload = {
        "investigation_id": "INV-AGENT-RESP-01",
        "analysis": "AI Agent identified consistent clothing and vehicle license plate match.",
        "findings": "Vehicle XYZ-123 exited south gate 2 minutes post-trigger.",
        "confidence": 0.92,
        "evidence_references": ["EVD-AGENT-001"],
        "recommended_actions": ["Dispatch security officer", "Preserve camera feed"],
        "schema_version": "1.0",
    }

    resp = client.post(
        "/api/investigations/INV-AGENT-RESP-01/agent-response",
        headers={"Authorization": f"Bearer {token}"},
        json=agent_response_payload,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_valid"] is True
    assert data["status"] == "ACCEPTED"
    assert data["confidence"] == 0.92
    assert "EVD-AGENT-001" in data["validated_evidence_ids"]

    # Verify that the Backend has recorded the unverified suggestion in investigation metadata
    inv = db_session.query(InvestigationModel).filter(InvestigationModel.investigation_id == "INV-AGENT-RESP-01").first()
    assert inv.metadata_json is not None
    assert len(inv.metadata_json["ai_agent_reports"]) >= 1
    assert "AI Agent Report (ACCEPTED)" in inv.findings


def test_ai_agent_fabricated_evidence_rejected(client: TestClient):
    token = get_token(client, "investigator")

    # Seed investigation
    client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {token}"},
        json={"investigation_id": "INV-AGENT-FAKE-01", "title": "Fake Evidence Case"},
    )

    agent_response_payload = {
        "investigation_id": "INV-AGENT-FAKE-01",
        "analysis": "AI Agent claiming nonexistent evidence proves breach.",
        "confidence": 0.95,
        "evidence_references": ["EVD-FAKE-NONEXISTENT-999"],  # Fabricated reference
    }

    resp = client.post(
        "/api/investigations/INV-AGENT-FAKE-01/agent-response",
        headers={"Authorization": f"Bearer {token}"},
        json=agent_response_payload,
    )
    assert resp.status_code == 400
    assert "Fabricated or nonexistent evidence reference" in resp.json()["detail"]


def test_ai_agent_insufficient_evidence_handling(client: TestClient):
    token = get_token(client, "investigator")

    # Seed investigation
    client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {token}"},
        json={"investigation_id": "INV-AGENT-INSUF-01", "title": "Insufficient Evidence Case"},
    )

    # Agent analysis with low confidence (< 0.5)
    low_conf_payload = {
        "investigation_id": "INV-AGENT-INSUF-01",
        "analysis": "Inconclusive low light analysis.",
        "confidence": 0.35,  # Low confidence
        "evidence_references": [],
    }

    resp = client.post(
        "/api/investigations/INV-AGENT-INSUF-01/agent-response",
        headers={"Authorization": f"Bearer {token}"},
        json=low_conf_payload,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "INSUFFICIENT_EVIDENCE"
    assert data["is_valid"] is False
    assert "insufficient evidence/confidence" in data["notes"].lower()
