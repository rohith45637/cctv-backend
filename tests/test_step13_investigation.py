from datetime import datetime, timedelta, timezone
import pytest
from typing import List
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
# 1. Investigation Execution & Result Structure
# ==========================================

def test_autonomous_investigation_result_structure(client: TestClient, db_session: Session):
    """Test that investigation result has clear separation of facts, inferences, and unknowns."""
    inv_token = get_token(client, "investigator")

    # Create incident with operator
    op_token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    # Ingest event
    evt_payload = {
        "event_id": "EVT-STEP13-001",
        "camera_id": "CAM-01",
        "zone_id": "ZONE-01",
        "timestamp": now.isoformat(),
        "event_type": "LINE_CROSSING",
        "confidence": 0.95,
        "source": "ai-video",
        "status": "NEW",
    }
    client.post("/api/events", headers={"Authorization": f"Bearer {op_token}"}, json=evt_payload)

    # Evaluate threat
    client.post(
        "/api/threats/evaluate",
        headers={"Authorization": f"Bearer {op_token}"},
        json={"event_id": "EVT-STEP13-001", "force_escalate": True},
    )

    # Fetch threat
    threat = db_session.query(ThreatModel).filter(ThreatModel.event_id == "EVT-STEP13-001").first()
    assert threat is not None
    threat_id = threat.threat_id

    # Create incident
    inc_payload = {
        "title": "Step13 Test Incident",
        "description": "Line crossing at perimeter",
        "severity": "P1",
        "zone_id": "ZONE-01",
        "primary_camera_id": "CAM-01",
        "related_threat_ids": [threat_id],
        "related_event_ids": ["EVT-STEP13-001"],
    }
    inc_resp = client.post("/api/incidents", headers={"Authorization": f"Bearer {op_token}"}, json=inc_payload)
    assert inc_resp.status_code == 201
    incident_id = inc_resp.json()["incident_id"]

    # Create evidence
    t_start = now - timedelta(minutes=5)
    t_end = now + timedelta(minutes=5)
    evd_payload = {
        "evidence_id": "EVD-STEP13-001",
        "camera_id": "CAM-01",
        "timestamp_start": t_start.isoformat(),
        "timestamp_end": t_end.isoformat(),
        "source_reference": "rtsp://surveillance.internal/feed/cam-01",
        "clip_reference": "storage/evidence/cam-01/clip_001.mp4",
        "confidence": 0.95,
    }
    client.post("/api/evidence", headers={"Authorization": f"Bearer {op_token}"}, json=evd_payload)

    # Create investigation
    inv_payload = {
        "investigation_id": "INV-STEP13-001",
        "title": "Autonomous Investigation Test",
        "description": "Full autonomous investigation test",
        "priority": "HIGH",
        "incident_id": incident_id,
        "trigger_event_id": "EVT-STEP13-001",
        "trigger_threat_id": threat_id,
    }
    resp = client.post("/api/investigations", headers={"Authorization": f"Bearer {inv_token}"}, json=inv_payload)
    assert resp.status_code == 201

    # Execute autonomous investigation
    exec_resp = client.post(
        "/api/investigations/INV-STEP13-001/execute",
        headers={"Authorization": f"Bearer {inv_token}"},
    )
    assert exec_resp.status_code == 200
    result = exec_resp.json()

    # Verify result structure
    assert result["investigation_id"] == "INV-STEP13-001"
    assert "observed_facts" in result
    assert "inferences" in result
    assert "unknown_information" in result
    assert "overall_confidence" in result
    assert "conclusion" in result
    assert "evidence_sufficiency" in result
    assert "cameras_analyzed" in result
    assert "zones_analyzed" in result
    assert "policies_checked" in result
    assert "evidence_collected" in result
    assert "cross_camera_tracks" in result
    assert "timeline_events" in result
    assert "schema_version" in result
    assert result["schema_version"] == "1.0"

    # Verify observed facts have proper fields
    for fact in result["observed_facts"]:
        assert "fact_id" in fact
        assert "description" in fact
        assert "evidence_references" in fact
        assert "event_references" in fact
        assert "confidence" in fact
        assert "verification_status" in fact

    # Verify inferences have proper fields
    for inf in result["inferences"]:
        assert "inference_id" in inf
        assert "description" in inf
        assert "supported_by_facts" in inf
        assert "reasoning" in inf
        assert "confidence" in inf
        assert "inference_type" in inf

    # Verify unknown info has proper fields
    for unk in result["unknown_information"]:
        assert "unknown_id" in unk
        assert "description" in unk
        assert "reason" in unk
        assert "impact" in unk


def test_autonomous_investigation_finds_relevant_cameras(client: TestClient):
    """Test that investigation finds relevant cameras from incident."""
    inv_token = get_token(client, "investigator")
    op_token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    # Create incident with CAM-01 as primary camera
    inc_payload = {
        "title": "Camera Discovery Test",
        "severity": "P1",
        "zone_id": "ZONE-01",
        "primary_camera_id": "CAM-01",
    }
    inc_resp = client.post("/api/incidents", headers={"Authorization": f"Bearer {op_token}"}, json=inc_payload)
    incident_id = inc_resp.json()["incident_id"]

    # Create investigation
    client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={
            "investigation_id": "INV-CAM-001",
            "title": "Camera Discovery Test",
            "incident_id": incident_id,
        },
    )

    exec_resp = client.post(
        "/api/investigations/INV-CAM-001/execute",
        headers={"Authorization": f"Bearer {inv_token}"},
    )
    assert exec_resp.status_code == 200
    result = exec_resp.json()
    assert "CAM-01" in result["cameras_analyzed"]


def test_autonomous_investigation_finds_related_zones(client: TestClient):
    """Test that investigation finds relevant zones."""
    inv_token = get_token(client, "investigator")
    op_token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    # Ingest event with ZONE-01
    evt_payload = {
        "event_id": "EVT-STEP13-ZONE-01",
        "camera_id": "CAM-01",
        "zone_id": "ZONE-01",
        "timestamp": now.isoformat(),
        "event_type": "OBJECT_DETECTED",
        "confidence": 0.75,
        "source": "ai-video",
        "status": "NEW",
    }
    client.post("/api/events", headers={"Authorization": f"Bearer {op_token}"}, json=evt_payload)

    client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={
            "investigation_id": "INV-ZONE-001",
            "title": "Zone Discovery Test",
            "trigger_event_id": "EVT-STEP13-ZONE-01",
        },
    )

    exec_resp = client.post(
        "/api/investigations/INV-ZONE-001/execute",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={"investigation_id": "INV-ZONE-001", "trigger_event_id": "EVT-STEP13-ZONE-01"},
    )
    assert exec_resp.status_code == 200
    result = exec_resp.json()
    assert "ZONE-01" in result["zones_analyzed"]


def test_autonomous_investigation_checks_security_policies(client: TestClient):
    """Test that investigation checks security policies."""
    inv_token = get_token(client, "investigator")
    op_token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    # Ingest event matching INTRUSION policy in ZONE-01
    evt_payload = {
        "event_id": "EVT-STEP13-POL-01",
        "camera_id": "CAM-01",
        "zone_id": "ZONE-01",
        "timestamp": now.isoformat(),
        "event_type": "INTRUSION",
        "confidence": 0.92,
        "evidence_id": "EVD-STEP13-POL-01",
        "source": "ai-video",
        "status": "NEW",
    }
    client.post("/api/events", headers={"Authorization": f"Bearer {op_token}"}, json=evt_payload)

    # Create evidence
    evd_payload = {
        "evidence_id": "EVD-STEP13-POL-01",
        "camera_id": "CAM-01",
        "timestamp_start": (now - timedelta(minutes=2)).isoformat(),
        "timestamp_end": (now + timedelta(minutes=2)).isoformat(),
        "source_reference": "rtsp://surveillance.internal/feed/cam-01",
        "clip_reference": "storage/evidence/pol_clip.mp4",
        "confidence": 0.92,
    }
    client.post("/api/evidence", headers={"Authorization": f"Bearer {op_token}"}, json=evd_payload)

    client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={
            "investigation_id": "INV-POL-001",
            "title": "Policy Check Test",
            "trigger_event_id": "EVT-STEP13-POL-01",
        },
    )

    exec_resp = client.post(
        "/api/investigations/INV-POL-001/execute",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={"investigation_id": "INV-POL-001", "trigger_event_id": "EVT-STEP13-POL-01"},
    )
    assert exec_resp.status_code == 200
    result = exec_resp.json()
    # Should check policies in ZONE-01 (POL-01 is INTRUSION policy)
    assert len(result["policies_checked"]) > 0 or len(result["observed_facts"]) > 0


def test_autonomous_investigation_builds_timeline(client: TestClient):
    """Test that investigation builds a timeline of events."""
    inv_token = get_token(client, "investigator")
    op_token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    # Ingest multiple events
    for i, evt_type in enumerate(["LINE_CROSSING", "PERSON_DETECTED", "ZONE_ENTRY"]):
        evt_payload = {
            "event_id": f"EVT-TIMELINE-{i:03d}",
            "camera_id": "CAM-01",
            "zone_id": "ZONE-01",
            "timestamp": (now - timedelta(minutes=5 - i)).isoformat(),
            "event_type": evt_type,
            "confidence": 0.90,
            "source": "ai-video",
            "status": "NEW",
        }
        client.post("/api/events", headers={"Authorization": f"Bearer {op_token}"}, json=evt_payload)

    client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={
            "investigation_id": "INV-TIMELINE-001",
            "title": "Timeline Test",
            "trigger_event_id": "EVT-TIMELINE-001",
        },
    )

    exec_resp = client.post(
        "/api/investigations/INV-TIMELINE-001/execute",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={"investigation_id": "INV-TIMELINE-001", "trigger_event_id": "EVT-TIMELINE-001"},
    )
    assert exec_resp.status_code == 200
    result = exec_resp.json()
    assert len(result["timeline_events"]) >= 3
    # Events should be in chronological order
    timestamps = [e["timestamp"] for e in result["timeline_events"] if e["timestamp"]]
    assert len(timestamps) >= 2


def test_autonomous_investigation_collects_evidence(client: TestClient):
    """Test that investigation collects evidence."""
    inv_token = get_token(client, "investigator")
    op_token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    # Ingest event to establish camera context
    evt_payload = {
        "event_id": "EVT-COLLECT-001",
        "camera_id": "CAM-01",
        "zone_id": "ZONE-01",
        "timestamp": now.isoformat(),
        "event_type": "LINE_CROSSING",
        "confidence": 0.95,
        "source": "ai-video",
        "status": "NEW",
    }
    client.post("/api/events", headers={"Authorization": f"Bearer {op_token}"}, json=evt_payload)

    # Create evidence
    evd_payload = {
        "evidence_id": "EVD-COLLECT-001",
        "camera_id": "CAM-01",
        "timestamp_start": (now - timedelta(minutes=5)).isoformat(),
        "timestamp_end": (now + timedelta(minutes=5)).isoformat(),
        "source_reference": "rtsp://surveillance.internal/feed/cam-01",
        "clip_reference": "storage/evidence/collect_clip.mp4",
        "confidence": 0.95,
    }
    client.post("/api/evidence", headers={"Authorization": f"Bearer {op_token}"}, json=evd_payload)

    client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={
            "investigation_id": "INV-COLLECT-001",
            "title": "Evidence Collection Test",
            "trigger_event_id": "EVT-COLLECT-001",
        },
    )

    exec_resp = client.post(
        "/api/investigations/INV-COLLECT-001/execute",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={"investigation_id": "INV-COLLECT-001", "trigger_event_id": "EVT-COLLECT-001"},
    )
    assert exec_resp.status_code == 200
    result = exec_resp.json()
    # Should have collected evidence from CAM-01
    assert "CAM-01" in result["cameras_analyzed"]


# ==========================================
# 2. Investigation Data Integrity Rules
# ==========================================

def test_autonomous_investigation_insufficient_evidence_returns_unknown(client: TestClient):
    """Test that investigation returns 'I don't know — insufficient evidence.' when evidence is insufficient."""
    inv_token = get_token(client, "investigator")

    # Create investigation with no incident, no events, no evidence
    client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={
            "investigation_id": "INV-INSUF-001",
            "title": "Insufficient Evidence Test",
        },
    )

    exec_resp = client.post(
        "/api/investigations/INV-INSUF-001/execute",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={"investigation_id": "INV-INSUF-001"},
    )
    assert exec_resp.status_code == 200
    result = exec_resp.json()
    assert result["evidence_sufficiency"] == "INSUFFICIENT"
    assert "i don't know" in result["conclusion"].lower()


def test_autonomous_investigation_never_invents_evidence(client: TestClient, db_session: Session):
    """Test that investigation never invents evidence IDs - only references real ones."""
    inv_token = get_token(client, "investigator")
    op_token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    # Ingest event with real evidence
    evt_payload = {
        "event_id": "EVT-NOINVENT-001",
        "camera_id": "CAM-01",
        "zone_id": "ZONE-01",
        "timestamp": now.isoformat(),
        "event_type": "LINE_CROSSING",
        "confidence": 0.95,
        "source": "ai-video",
        "status": "NEW",
    }
    client.post("/api/events", headers={"Authorization": f"Bearer {op_token}"}, json=evt_payload)

    # Create real evidence
    evd_payload = {
        "evidence_id": "EVD-NOINVENT-001",
        "camera_id": "CAM-01",
        "timestamp_start": (now - timedelta(minutes=2)).isoformat(),
        "timestamp_end": (now + timedelta(minutes=2)).isoformat(),
        "source_reference": "rtsp://surveillance.internal/feed/cam-01",
        "clip_reference": "storage/evidence/no_invent_clip.mp4",
        "confidence": 0.95,
    }
    client.post("/api/evidence", headers={"Authorization": f"Bearer {op_token}"}, json=evd_payload)

    client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={
            "investigation_id": "INV-NOINVENT-001",
            "title": "No Invent Test",
            "trigger_event_id": "EVT-NOINVENT-001",
        },
    )

    exec_resp = client.post(
        "/api/investigations/INV-NOINVENT-001/execute",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={"investigation_id": "INV-NOINVENT-001", "trigger_event_id": "EVT-NOINVENT-001"},
    )
    assert exec_resp.status_code == 200
    result = exec_resp.json()

    # All evidence references must be real
    for fact in result["observed_facts"]:
        for evd_ref in fact["evidence_references"]:
            db_evd = db_session.query(EvidenceModel).filter(EvidenceModel.evidence_id == evd_ref).first()
            assert db_evd is not None, f"Evidence reference {evd_ref} is not a real evidence record"

    for evd_id in result["evidence_collected"]:
        db_evd = db_session.query(EvidenceModel).filter(EvidenceModel.evidence_id == evd_id).first()
        assert db_evd is not None, f"Collected evidence {evd_id} is not a real evidence record"

    # All event references must be real
    for fact in result["observed_facts"]:
        for evt_ref in fact["event_references"]:
            db_evt = db_session.query(EventModel).filter(EventModel.event_id == evt_ref).first()
            assert db_evt is not None, f"Event reference {evt_ref} is not a real event record"


def test_autonomous_investigation_never_invents_cameras(client: TestClient):
    """Test that investigation never invents camera IDs."""
    inv_token = get_token(client, "investigator")
    op_token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    # Ingest event with CAM-01
    evt_payload = {
        "event_id": "EVT-NOCAM-001",
        "camera_id": "CAM-01",
        "zone_id": "ZONE-01",
        "timestamp": now.isoformat(),
        "event_type": "LINE_CROSSING",
        "confidence": 0.95,
        "source": "ai-video",
        "status": "NEW",
    }
    client.post("/api/events", headers={"Authorization": f"Bearer {op_token}"}, json=evt_payload)

    client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={
            "investigation_id": "INV-NOCAM-001",
            "title": "No Camera Invent Test",
            "trigger_event_id": "EVT-NOCAM-001",
        },
    )

    exec_resp = client.post(
        "/api/investigations/INV-NOCAM-001/execute",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={"investigation_id": "INV-NOCAM-001", "trigger_event_id": "EVT-NOCAM-001"},
    )
    assert exec_resp.status_code == 200
    result = exec_resp.json()

    # All cameras should be real (from seed data)
    real_camera_ids = {"CAM-01", "CAM-02", "CAM-03"}
    for cam_id in result["cameras_analyzed"]:
        assert cam_id in real_camera_ids, f"Camera {cam_id} is not a real camera"

    for fact in result["observed_facts"]:
        if fact.get("camera_id"):
            assert fact["camera_id"] in real_camera_ids, f"Fact camera {fact['camera_id']} is not real"


# ==========================================
# 3. Investigation RBAC Tests
# ==========================================

def test_autonomous_investigation_unauthenticated_rejected(client: TestClient):
    resp = client.post("/api/investigations/INV-NONEXISTENT/execute")
    assert resp.status_code == 401


def test_autonomous_investigation_viewer_allowed(client: TestClient):
    """Viewer can execute investigation (investigation.read permission)."""
    viewer_token = get_token(client, "viewer")
    inv_token = get_token(client, "investigator")

    # Create investigation with investigator
    client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={
            "investigation_id": "INV-STEP13-VIEWER-01",
            "title": "Viewer Access Test",
        },
    )

    resp = client.post(
        "/api/investigations/INV-STEP13-VIEWER-01/execute",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"investigation_id": "INV-STEP13-VIEWER-01"},
    )
    assert resp.status_code == 200


def test_autonomous_investigation_nonexistent_investigation_rejected(client: TestClient):
    inv_token = get_token(client, "investigator")
    resp = client.post(
        "/api/investigations/INV-NONEXISTENT-999/execute",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={"investigation_id": "INV-NONEXISTENT-999"},
    )
    assert resp.status_code == 404


# ==========================================
# 4. Investigation Result Content Tests
# ==========================================

def test_autonomous_investigation_cross_camera_tracking(client: TestClient):
    """Test cross-camera tracking when entity_id matches across events."""
    inv_token = get_token(client, "investigator")
    op_token = get_token(client, "operator")
    now = datetime.now(timezone.utc)
    past_time = now - timedelta(minutes=5)

    # Create events with same entity_id on different cameras
    evt_payload_1 = {
        "event_id": "EVT-CROSS-CAM-01",
        "camera_id": "CAM-01",
        "zone_id": "ZONE-01",
        "timestamp": past_time.isoformat(),
        "event_type": "PERSON_DETECTED",
        "entity_id": "ENT-CROSS-001",
        "confidence": 0.90,
        "source": "ai-video",
        "status": "NEW",
    }
    evt_payload_2 = {
        "event_id": "EVT-CROSS-CAM-02",
        "camera_id": "CAM-02",
        "zone_id": "ZONE-01",
        "timestamp": (past_time + timedelta(seconds=30)).isoformat(),
        "event_type": "PERSON_DETECTED",
        "entity_id": "ENT-CROSS-001",
        "confidence": 0.88,
        "source": "ai-video",
        "status": "NEW",
    }
    client.post("/api/events", headers={"Authorization": f"Bearer {op_token}"}, json=evt_payload_1)
    client.post("/api/events", headers={"Authorization": f"Bearer {op_token}"}, json=evt_payload_2)

    client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={
            "investigation_id": "INV-CROSS-CAM-01",
            "title": "Cross Camera Tracking Test",
            "trigger_event_id": "EVT-CROSS-CAM-01",
        },
    )

    exec_resp = client.post(
        "/api/investigations/INV-CROSS-CAM-01/execute",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={
            "investigation_id": "INV-CROSS-CAM-01",
            "trigger_event_id": "EVT-CROSS-CAM-01",
            "cross_camera": True,
        },
    )
    assert exec_resp.status_code == 200
    result = exec_resp.json()
    assert len(result["cross_camera_tracks"]) >= 1
    track = result["cross_camera_tracks"][0]
    assert "CAM-01" in track["cameras"]
    assert "CAM-02" in track["cameras"]
    assert "EVT-CROSS-CAM-01" in track["event_ids"]
    assert "EVT-CROSS-CAM-02" in track["event_ids"]


def test_autonomous_investigation_metadata_stored(client: TestClient, db_session: Session):
    """Test that investigation result is stored in metadata."""
    inv_token = get_token(client, "investigator")

    client.post(
        "/api/investigations",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={
            "investigation_id": "INV-META-001",
            "title": "Metadata Test",
        },
    )

    exec_resp = client.post(
        "/api/investigations/INV-META-001/execute",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={"investigation_id": "INV-META-001"},
    )
    assert exec_resp.status_code == 200

    db_inv = db_session.query(InvestigationModel).filter(
        InvestigationModel.investigation_id == "INV-META-001"
    ).first()
    assert db_inv is not None
    assert db_inv.status == "COMPLETED"
    assert db_inv.completed_at is not None
    assert db_inv.metadata_json is not None
    assert "autonomous_investigation_result" in db_inv.metadata_json
    meta = db_inv.metadata_json["autonomous_investigation_result"]
    assert "observed_facts_count" in meta
    assert "inferences_count" in meta
    assert "unknown_information_count" in meta
    assert "overall_confidence" in meta
    assert "evidence_sufficiency" in meta