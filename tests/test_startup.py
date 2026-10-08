from fastapi.testclient import TestClient


def test_root_endpoint(client: TestClient):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "version" in data
    assert "health" in data


def test_health_check_endpoint(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
    assert data["demo_mode"] is True


def test_health_liveness_and_readiness(client: TestClient):
    live_resp = client.get("/health/live")
    assert live_resp.status_code == 200
    assert live_resp.json() == {"status": "alive"}

    ready_resp = client.get("/health/ready")
    assert ready_resp.status_code == 200
    assert ready_resp.json() == {"ready": True}


def test_api_v1_cameras_endpoint(client: TestClient):
    response = client.get("/api/v1/cameras")
    assert response.status_code == 200
    cameras = response.json()
    assert len(cameras) >= 3
    cam_ids = [c["camera_id"] for c in cameras]
    assert "CAM-01" in cam_ids
    assert "CAM-02" in cam_ids
    assert "CAM-03" in cam_ids
    for c in cameras:
        assert c["schema_version"] == "1.0"


def test_api_v1_zones_endpoint(client: TestClient):
    response = client.get("/api/v1/zones")
    assert response.status_code == 200
    zones = response.json()
    assert len(zones) >= 3
    zone_ids = [z["zone_id"] for z in zones]
    assert "ZONE-01" in zone_ids
    assert "ZONE-02" in zone_ids
    assert "ZONE-03" in zone_ids
    for z in zones:
        assert z["schema_version"] == "1.0"


def test_api_v1_policies_endpoint(client: TestClient):
    response = client.get("/api/v1/policies")
    assert response.status_code == 200
    policies = response.json()
    assert len(policies) >= 3
    pol_ids = [p["policy_id"] for p in policies]
    assert "POL-01" in pol_ids
    for p in policies:
        assert p["schema_version"] == "1.0"
