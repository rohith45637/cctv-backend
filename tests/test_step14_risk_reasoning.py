from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

DEMO_PASSWORD = "AdminSecure!2026"


def get_token(client: TestClient, username: str = "operator") -> str:
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": DEMO_PASSWORD},
    )
    assert response.status_code == 200, f"Login failed for {username}"
    return response.json()["access_token"]


def _seed_event(client: TestClient, token: str, event_id: str = "EVT-RR-001",
                event_type: str = "INTRUSION", confidence: float = 0.92) -> dict:
    now = datetime.now(timezone.utc)
    payload = {
        "event_id": event_id,
        "camera_id": "CAM-01",
        "zone_id": "ZONE-01",
        "timestamp": now.isoformat(),
        "event_type": event_type,
        "confidence": confidence,
        "source": "ai-video",
        "status": "NEW",
    }
    resp = client.post("/api/events", headers={"Authorization": f"Bearer {token}"}, json=payload)
    assert resp.status_code == 200
    return resp.json()


def test_risk_reasoning_endpoint_returns_200(client: TestClient):
    token = get_token(client, "operator")
    _seed_event(client, token)
    resp = client.post(
        "/api/threats/risk-reasoning",
        headers={"Authorization": f"Bearer {token}"},
        json={"event_id": "EVT-RR-001", "include_evidence": True},
    )
    assert resp.status_code == 200


def test_risk_reasoning_response_matches_schema(client: TestClient):
    token = get_token(client, "operator")
    _seed_event(client, token)
    resp = client.post(
        "/api/threats/risk-reasoning",
        headers={"Authorization": f"Bearer {token}"},
        json={"event_id": "EVT-RR-001", "include_evidence": True},
    )
    data = resp.json()
    assert "reasoning_id" in data
    assert "risk_score" in data
    assert "risk_level" in data
    assert "confidence" in data
    assert "reasoning" in data
    assert "observation" in data
    assert "context" in data
    assert "applicable_policies" in data
    assert "evidence_references" in data
    assert "evidence_verification_status" in data
    assert "recommended_actions" in data
    assert "escalation_warranted" in data
    assert "schema_version" in data
    assert data["schema_version"] == "1.0"
    assert data["event_id"] == "EVT-RR-001"


def test_risk_reasoning_invalid_event_returns_404(client: TestClient):
    token = get_token(client, "operator")
    resp = client.post(
        "/api/threats/risk-reasoning",
        headers={"Authorization": f"Bearer {token}"},
        json={"event_id": "EVT-NONEXISTENT-999", "include_evidence": True},
    )
    assert resp.status_code == 404