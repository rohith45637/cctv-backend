from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.database.models import (
    Camera,
    Event as EventModel,
    Incident as IncidentModel,
    SecurityPolicy,
    Threat as ThreatModel,
    Zone,
)
from src.threats.risk_engine import RiskEngine

DEMO_PASSWORD = "AdminSecure!2026"


def get_auth_token(client: TestClient, username: str = "operator") -> str:
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": DEMO_PASSWORD},
    )
    assert response.status_code == 200, f"Login failed for {username}"
    return response.json()["access_token"]


# ==========================================
# 1. Risk Evaluation & Explainability Tests
# ==========================================

def test_risk_evaluation_explainable_reasons(db_session: Session):
    now = datetime.now(timezone.utc)
    zone = db_session.query(Zone).filter(Zone.zone_id == "ZONE-01").first()
    camera = db_session.query(Camera).filter(Camera.camera_id == "CAM-01").first()
    policies = db_session.query(SecurityPolicy).filter(SecurityPolicy.zone_id == "ZONE-01").all()

    event = EventModel(
        event_id="EVT-RISK-01",
        camera_id="CAM-01",
        zone_id="ZONE-01",
        timestamp=now,
        event_type="INTRUSION",
        confidence=0.92,
        evidence_id="EVD-CLIP-01",
        source="ai-video",
        status="NEW",
    )

    eval_result = RiskEngine.evaluate(event=event, zone=zone, camera=camera, policies=policies)

    assert eval_result.is_threat is True
    assert eval_result.risk_score >= 70.0
    assert eval_result.severity in ("HIGH", "CRITICAL")
    assert len(eval_result.reasons) >= 3

    reasons_text = " ".join(eval_result.reasons).lower()
    assert "intrusion" in reasons_text
    assert "perimeter" in reasons_text or "zone" in reasons_text
    assert "evidence" in reasons_text
    assert "confidence" in reasons_text


def test_risk_evaluation_unknown_low_confidence():
    now = datetime.now(timezone.utc)
    event = EventModel(
        event_id="EVT-LOW-CONF",
        camera_id="CAM-01",
        timestamp=now,
        event_type="INTRUSION",
        confidence=0.25,  # Very low confidence
        source="ai-video",
        status="NEW",
    )

    eval_result = RiskEngine.evaluate(event=event)

    assert eval_result.is_threat is False
    assert eval_result.risk_score == 0.0
    assert eval_result.severity == "UNKNOWN"
    assert "insufficient detection confidence" in eval_result.reasons[0].lower()


def test_risk_evaluation_insufficient_evidence_handling(db_session: Session):
    now = datetime.now(timezone.utc)
    zone = db_session.query(Zone).filter(Zone.zone_id == "ZONE-01").first()
    policies = db_session.query(SecurityPolicy).filter(SecurityPolicy.zone_id == "ZONE-01").all()

    # Event with missing evidence_id
    event = EventModel(
        event_id="EVT-NO-EVD",
        camera_id="CAM-01",
        zone_id="ZONE-01",
        timestamp=now,
        event_type="INTRUSION",
        confidence=0.88,
        evidence_id=None,
        source="ai-video",
        status="NEW",
    )

    eval_result = RiskEngine.evaluate(event=event, zone=zone, policies=policies)
    reasons_text = " ".join(eval_result.reasons)
    assert "INSUFFICIENT_EVIDENCE" in reasons_text


# ==========================================
# 2. Threat Creation & Status Tests
# ==========================================

def test_threat_creation_and_event_relationship(client: TestClient, db_session: Session):
    token = get_auth_token(client, "operator")
    now = datetime.now(timezone.utc)

    # 1. Ingest event that qualifies for threat escalation
    event_payload = {
        "event_id": "EVT-THREAT-EVENT-01",
        "camera_id": "CAM-01",
        "zone_id": "ZONE-01",
        "timestamp": now.isoformat(),
        "event_type": "INTRUSION",
        "confidence": 0.95,
        "evidence_id": "EVD-CLIP-THREAT-01",
        "source": "ai-video",
        "schema_version": "1.0",
    }
    ingest_resp = client.post("/api/events", headers={"Authorization": f"Bearer {token}"}, json=event_payload)
    assert ingest_resp.status_code == 200

    # 2. Evaluate for threat
    eval_resp = client.post(
        "/api/threats/evaluate",
        headers={"Authorization": f"Bearer {token}"},
        json={"event_id": "EVT-THREAT-EVENT-01"},
    )
    assert eval_resp.status_code == 200
    threat_data = eval_resp.json()
    assert threat_data is not None

    threat_id = threat_data["threat_id"]
    assert threat_id.startswith("THR-")
    assert threat_data["severity"] in ("HIGH", "MEDIUM")
    assert threat_data["risk_score"] > 50
    assert threat_data["status"] == "NEW"
    assert "reason" in threat_data

    # 3. Verify event -> threat relationship in DB
    db_threat = db_session.query(ThreatModel).filter(ThreatModel.threat_id == threat_id).first()
    assert db_threat is not None
    assert db_threat.event.event_id == "EVT-THREAT-EVENT-01"


def test_threat_status_lifecycle(client: TestClient, db_session: Session):
    token = get_auth_token(client, "operator")
    now = datetime.now(timezone.utc)

    # Create threat
    threat = ThreatModel(
        threat_id="THR-LIFECYCLE-01",
        title="Test Threat Lifecycle",
        severity="HIGH",
        risk_score=85.0,
        status="NEW",
        camera_id="CAM-01",
        detected_at=now,
    )
    db_session.add(threat)
    db_session.commit()

    # Update to ACKNOWLEDGED
    res1 = client.patch(
        "/api/threats/THR-LIFECYCLE-01",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "ACKNOWLEDGED"},
    )
    assert res1.status_code == 200
    assert res1.json()["status"] == "ACKNOWLEDGED"

    # Update to RESOLVED
    res2 = client.patch(
        "/api/threats/THR-LIFECYCLE-01",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "RESOLVED"},
    )
    assert res2.status_code == 200
    assert res2.json()["status"] == "RESOLVED"


# ==========================================
# 3. Incident Creation & Threat Linkage Tests
# ==========================================

def test_incident_creation_and_threat_linkage(client: TestClient, db_session: Session):
    token = get_auth_token(client, "operator")
    now = datetime.now(timezone.utc)

    # Create threat
    threat = ThreatModel(
        threat_id="THR-INCIDENT-LINK-01",
        title="Threat for incident link",
        severity="HIGH",
        risk_score=90.0,
        status="NEW",
        camera_id="CAM-01",
        detected_at=now,
    )
    db_session.add(threat)
    db_session.commit()

    # Create Incident linking the threat
    incident_payload = {
        "title": "Perimeter Gate Breach Incident",
        "description": "Multi-event physical perimeter crossing alarm",
        "severity": "P1",
        "zone_id": "ZONE-01",
        "primary_camera_id": "CAM-01",
        "related_threat_ids": ["THR-INCIDENT-LINK-01"],
        "related_event_ids": ["EVT-SAMPLE-01"],
    }
    inc_resp = client.post(
        "/api/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json=incident_payload,
    )
    assert inc_resp.status_code == 201
    inc_data = inc_resp.json()

    incident_id = inc_data["incident_id"]
    assert incident_id.startswith("INC-")
    assert inc_data["status"] == "OPEN"
    assert inc_data["severity"] == "P1"
    assert "THR-INCIDENT-LINK-01" in inc_data["related_threat_ids"]

    # Verify threat -> incident link in DB
    db_threat = db_session.query(ThreatModel).filter(ThreatModel.threat_id == "THR-INCIDENT-LINK-01").first()
    assert db_threat.incident_id == incident_id
    assert db_threat.status == "INVESTIGATING"


def test_incident_status_update(client: TestClient, db_session: Session):
    token = get_auth_token(client, "operator")
    now = datetime.now(timezone.utc)

    incident = IncidentModel(
        incident_id="INC-STATUS-TEST-01",
        title="Status test incident",
        severity="P2",
        status="OPEN",
        opened_at=now,
    )
    db_session.add(incident)
    db_session.commit()

    # Update to RESOLVED
    patch_resp = client.patch(
        "/api/incidents/INC-STATUS-TEST-01",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "RESOLVED"},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "RESOLVED"
    assert patch_resp.json()["resolved_at"] is not None


# ==========================================
# 4. RBAC Authorization Tests for Step 6
# ==========================================

def test_viewer_denied_threat_and_incident_modifications(client: TestClient):
    viewer_token = get_auth_token(client, "viewer")

    # Viewer has threat.read -> GET allowed
    res_get = client.get("/api/threats", headers={"Authorization": f"Bearer {viewer_token}"})
    assert res_get.status_code == 200

    # Viewer lacks threat.manage -> PATCH denied
    res_patch_thr = client.patch(
        "/api/threats/THR-DUMMY",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"status": "ACKNOWLEDGED"},
    )
    assert res_patch_thr.status_code == 403

    # Viewer lacks incident.manage -> POST denied
    res_post_inc = client.post(
        "/api/incidents",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"title": "Unauthorized incident"},
    )
    assert res_post_inc.status_code == 403
