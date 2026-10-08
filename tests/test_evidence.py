from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.database.models import Evidence as EvidenceModel, Camera as CameraModel, Event as EventModel
from src.database.models.evidence import EvidenceVerification

DEMO_PASSWORD = "AdminSecure!2026"


def get_token(client: TestClient, username: str = "operator") -> str:
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": DEMO_PASSWORD},
    )
    assert response.status_code == 200, f"Login failed for {username}"
    return response.json()["access_token"]


# ==========================================
# 1. Evidence Creation Tests
# ==========================================

def test_evidence_creation_success(client: TestClient, db_session: Session):
    token = get_token(client, "operator")
    t_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    t_end = datetime.now(timezone.utc) - timedelta(minutes=1)

    payload = {
        "evidence_id": "EVD-TEST-001",
        "camera_id": "CAM-01",
        "timestamp_start": t_start.isoformat(),
        "timestamp_end": t_end.isoformat(),
        "source_reference": "rtsp://surveillance.internal/feed/cam-01",
        "clip_reference": "storage/evidence/cam-01/clip_001.mp4",
        "confidence": 0.95,
        "source_type": "AI_VIDEO",
        "storage_url": "http://storage.internal/evidence/clip_001.mp4",
        "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "metadata_json": {"resolution": "1080p", "fps": 30},
    }

    response = client.post(
        "/api/evidence",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert response.status_code == 201
    data = response.json()

    assert data["evidence_id"] == "EVD-TEST-001"
    assert data["camera_id"] == "CAM-01"
    # Must always be initialized as UNVERIFIED
    assert data["verification_status"] == "UNVERIFIED"
    assert data["confidence"] == 0.95
    assert data["source_type"] == "AI_VIDEO"
    assert data["provenance"] is not None
    assert data["provenance"]["camera_id"] == "CAM-01"
    assert data["provenance"]["source_type"] == "AI_VIDEO"

    # Verify DB persistence
    db_item = db_session.query(EvidenceModel).filter(EvidenceModel.evidence_id == "EVD-TEST-001").first()
    assert db_item is not None
    assert db_item.verification_status == "UNVERIFIED"
    assert db_item.camera.name == "[DEMO] CAM-01 Main Gate"


def test_evidence_cannot_be_created_as_verified(client: TestClient):
    token = get_token(client, "operator")
    t_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    t_end = datetime.now(timezone.utc) - timedelta(minutes=1)

    payload = {
        "evidence_id": "EVD-TEST-AUTO-VERIFY",
        "camera_id": "CAM-01",
        "timestamp_start": t_start.isoformat(),
        "timestamp_end": t_end.isoformat(),
        "source_reference": "rtsp://surveillance.internal/feed/cam-01",
        "clip_reference": "storage/evidence/cam-01/clip_auto.mp4",
        "confidence": 0.98,
        "verification_status": "VERIFIED",  # Illegal on initial creation
    }

    response = client.post(
        "/api/evidence",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert response.status_code == 422
    assert "UNVERIFIED" in response.text


def test_evidence_creation_invalid_time_range(client: TestClient):
    token = get_token(client, "operator")
    t_start = datetime.now(timezone.utc)
    t_end = t_start - timedelta(seconds=30)  # end before start

    payload = {
        "evidence_id": "EVD-TEST-TIME-ERR",
        "camera_id": "CAM-01",
        "timestamp_start": t_start.isoformat(),
        "timestamp_end": t_end.isoformat(),
        "source_reference": "rtsp://surveillance.internal/feed/cam-01",
        "clip_reference": "storage/evidence/clip_bad_time.mp4",
        "confidence": 0.85,
    }

    response = client.post(
        "/api/evidence",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert response.status_code == 422


def test_evidence_creation_nonexistent_camera(client: TestClient):
    token = get_token(client, "operator")
    t_start = datetime.now(timezone.utc) - timedelta(minutes=1)
    t_end = datetime.now(timezone.utc)

    payload = {
        "evidence_id": "EVD-TEST-NOCAM",
        "camera_id": "CAM-NONEXISTENT",
        "timestamp_start": t_start.isoformat(),
        "timestamp_end": t_end.isoformat(),
        "source_reference": "rtsp://surveillance.internal/feed/cam-none",
        "clip_reference": "storage/evidence/clip_nocam.mp4",
        "confidence": 0.80,
    }

    response = client.post(
        "/api/evidence",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert response.status_code == 404
    assert "Camera 'CAM-NONEXISTENT' not found" in response.json()["detail"]


def test_evidence_creation_duplicate_id_rejected(client: TestClient):
    token = get_token(client, "operator")
    t_start = datetime.now(timezone.utc) - timedelta(minutes=1)
    t_end = datetime.now(timezone.utc)

    payload = {
        "evidence_id": "EVD-TEST-DUP-01",
        "camera_id": "CAM-01",
        "timestamp_start": t_start.isoformat(),
        "timestamp_end": t_end.isoformat(),
        "source_reference": "rtsp://feed/1",
        "clip_reference": "storage/clip1.mp4",
        "confidence": 0.90,
    }

    resp1 = client.post("/api/evidence", headers={"Authorization": f"Bearer {token}"}, json=payload)
    assert resp1.status_code == 201

    resp2 = client.post("/api/evidence", headers={"Authorization": f"Bearer {token}"}, json=payload)
    assert resp2.status_code == 409


# ==========================================
# 2. Evidence Retrieval & Filtering Tests
# ==========================================

def test_evidence_get_by_id_and_not_found(client: TestClient):
    token = get_token(client, "viewer")

    # Get non-existent
    resp_404 = client.get("/api/evidence/EVD-UNKNOWN-999", headers={"Authorization": f"Bearer {token}"})
    assert resp_404.status_code == 404

    # Create one with operator and fetch with viewer
    op_token = get_token(client, "operator")
    t_start = datetime.now(timezone.utc) - timedelta(minutes=5)
    t_end = datetime.now(timezone.utc) - timedelta(minutes=4)
    create_payload = {
        "evidence_id": "EVD-TEST-GET-01",
        "camera_id": "CAM-02",
        "timestamp_start": t_start.isoformat(),
        "timestamp_end": t_end.isoformat(),
        "source_reference": "rtsp://feed/2",
        "clip_reference": "storage/clip2.mp4",
        "confidence": 0.88,
    }
    client.post("/api/evidence", headers={"Authorization": f"Bearer {op_token}"}, json=create_payload)

    resp_get = client.get("/api/evidence/EVD-TEST-GET-01", headers={"Authorization": f"Bearer {token}"})
    assert resp_get.status_code == 200
    data = resp_get.json()
    assert data["evidence_id"] == "EVD-TEST-GET-01"
    assert data["camera_id"] == "CAM-02"


def test_evidence_list_and_filtering(client: TestClient):
    token = get_token(client, "viewer")
    resp = client.get("/api/evidence?camera_id=CAM-01", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)
    for item in items:
        assert item["camera_id"] == "CAM-01"


# ==========================================
# 3. Explicit Verification Lifecycle Tests
# ==========================================

def test_evidence_explicit_verification_workflow(client: TestClient, db_session: Session):
    op_token = get_token(client, "operator")
    inv_token = get_token(client, "investigator")

    # 1. Create UNVERIFIED evidence
    t_start = datetime.now(timezone.utc) - timedelta(minutes=10)
    t_end = datetime.now(timezone.utc) - timedelta(minutes=9)
    create_payload = {
        "evidence_id": "EVD-TEST-VERIFY-01",
        "camera_id": "CAM-01",
        "timestamp_start": t_start.isoformat(),
        "timestamp_end": t_end.isoformat(),
        "source_reference": "rtsp://feed/cam-01",
        "clip_reference": "storage/clip_verify.mp4",
        "confidence": 0.91,
    }
    resp_create = client.post("/api/evidence", headers={"Authorization": f"Bearer {op_token}"}, json=create_payload)
    assert resp_create.status_code == 201
    assert resp_create.json()["verification_status"] == "UNVERIFIED"

    # 2. Investigator explicitly verifies evidence
    verify_payload = {
        "status": "VERIFIED",
        "notes": "Reviewed and confirmed person of interest face match in clip.",
    }
    resp_verify = client.post(
        "/api/evidence/EVD-TEST-VERIFY-01/verify",
        headers={"Authorization": f"Bearer {inv_token}"},
        json=verify_payload,
    )
    assert resp_verify.status_code == 200
    data = resp_verify.json()
    assert data["verification_status"] == "VERIFIED"

    # 3. Verify database audit record
    verif_record = db_session.query(EvidenceVerification).filter(
        EvidenceVerification.evidence_id == "EVD-TEST-VERIFY-01"
    ).first()
    assert verif_record is not None
    assert verif_record.status == "VERIFIED"
    assert verif_record.verified_by_user_id == "USR-INVESTIGATOR01"
    assert "face match" in verif_record.notes
    assert verif_record.provenance_snapshot_json["camera_id"] == "CAM-01"


def test_evidence_rejection_workflow(client: TestClient):
    inv_token = get_token(client, "investigator")
    op_token = get_token(client, "operator")

    t_start = datetime.now(timezone.utc) - timedelta(minutes=5)
    t_end = datetime.now(timezone.utc) - timedelta(minutes=4)
    create_payload = {
        "evidence_id": "EVD-TEST-REJECT-01",
        "camera_id": "CAM-01",
        "timestamp_start": t_start.isoformat(),
        "timestamp_end": t_end.isoformat(),
        "source_reference": "rtsp://feed/cam-01",
        "clip_reference": "storage/clip_reject.mp4",
        "confidence": 0.40,
    }
    client.post("/api/evidence", headers={"Authorization": f"Bearer {op_token}"}, json=create_payload)

    # Reject evidence
    reject_payload = {
        "status": "REJECTED",
        "notes": "False trigger caused by glare from headlights.",
    }
    resp = client.post(
        "/api/evidence/EVD-TEST-REJECT-01/verify",
        headers={"Authorization": f"Bearer {inv_token}"},
        json=reject_payload,
    )
    assert resp.status_code == 200
    assert resp.json()["verification_status"] == "REJECTED"


def test_evidence_insufficient_evidence_workflow(client: TestClient):
    inv_token = get_token(client, "investigator")
    op_token = get_token(client, "operator")

    t_start = datetime.now(timezone.utc) - timedelta(minutes=5)
    t_end = datetime.now(timezone.utc) - timedelta(minutes=4)
    create_payload = {
        "evidence_id": "EVD-TEST-INSUF-01",
        "camera_id": "CAM-01",
        "timestamp_start": t_start.isoformat(),
        "timestamp_end": t_end.isoformat(),
        "source_reference": "rtsp://feed/cam-01",
        "clip_reference": "storage/clip_insuf.mp4",
        "confidence": 0.55,
    }
    client.post("/api/evidence", headers={"Authorization": f"Bearer {op_token}"}, json=create_payload)

    # Mark INSUFFICIENT_EVIDENCE
    insuf_payload = {
        "status": "INSUFFICIENT_EVIDENCE",
        "notes": "Resolution too low to identify license plate or suspect attire.",
    }
    resp = client.post(
        "/api/evidence/EVD-TEST-INSUF-01/verify",
        headers={"Authorization": f"Bearer {inv_token}"},
        json=insuf_payload,
    )
    assert resp.status_code == 200
    assert resp.json()["verification_status"] == "INSUFFICIENT_EVIDENCE"


def test_evidence_invalid_verification_status_rejected(client: TestClient):
    inv_token = get_token(client, "investigator")
    payload = {"status": "INVALID_STATUS_CODE", "notes": "Some note"}
    resp = client.post(
        "/api/evidence/EVD-TEST-001/verify",
        headers={"Authorization": f"Bearer {inv_token}"},
        json=payload,
    )
    assert resp.status_code == 422


# ==========================================
# 4. Provenance Trail & Relational Integrity Tests
# ==========================================

def test_evidence_provenance_endpoint(client: TestClient):
    token = get_token(client, "viewer")
    op_token = get_token(client, "operator")

    t_start = datetime.now(timezone.utc) - timedelta(minutes=3)
    t_end = datetime.now(timezone.utc) - timedelta(minutes=2)
    payload = {
        "evidence_id": "EVD-TEST-PROV-01",
        "camera_id": "CAM-01",
        "timestamp_start": t_start.isoformat(),
        "timestamp_end": t_end.isoformat(),
        "source_reference": "rtsp://stream.secure/cam-01",
        "clip_reference": "storage/prov_clip.mp4",
        "confidence": 0.89,
        "source_type": "AI_VIDEO",
    }
    client.post("/api/evidence", headers={"Authorization": f"Bearer {op_token}"}, json=payload)

    resp = client.get("/api/evidence/EVD-TEST-PROV-01/provenance", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["evidence_id"] == "EVD-TEST-PROV-01"
    assert data["provenance"]["source_type"] == "AI_VIDEO"
    assert data["provenance"]["camera_id"] == "CAM-01"
    assert data["provenance"]["source_reference"] == "rtsp://stream.secure/cam-01"
    assert data["verification_status"] == "UNVERIFIED"


def test_evidence_event_and_camera_relationships(client: TestClient, db_session: Session):
    token = get_token(client, "operator")
    now = datetime.now(timezone.utc)

    # 1. Ingest event first
    evt_payload = {
        "event_id": "EVT-TEST-EVD-LINK-01",
        "camera_id": "CAM-01",
        "timestamp": now.isoformat(),
        "event_type": "PERSON_DETECTED",
        "confidence": 0.92,
        "source": "ai-video",
        "status": "NEW",
    }
    resp_evt = client.post("/api/events", headers={"Authorization": f"Bearer {token}"}, json=evt_payload)
    assert resp_evt.status_code == 200

    # 2. Ingest evidence referencing event
    t_start = now - timedelta(seconds=15)
    t_end = now + timedelta(seconds=15)
    evd_payload = {
        "evidence_id": "EVD-TEST-EVT-LINK-01",
        "camera_id": "CAM-01",
        "event_id": "EVT-TEST-EVD-LINK-01",
        "timestamp_start": t_start.isoformat(),
        "timestamp_end": t_end.isoformat(),
        "source_reference": "rtsp://cam-01/live",
        "clip_reference": "storage/events/clip_link.mp4",
        "confidence": 0.95,
    }
    resp_evd = client.post("/api/evidence", headers={"Authorization": f"Bearer {token}"}, json=evd_payload)
    assert resp_evd.status_code == 201

    # 3. Verify DB relational linking
    evd_db = db_session.query(EvidenceModel).filter(EvidenceModel.evidence_id == "EVD-TEST-EVT-LINK-01").first()
    assert evd_db is not None
    assert evd_db.event is not None
    assert evd_db.event.event_id == "EVT-TEST-EVD-LINK-01"
    assert evd_db.camera is not None
    assert evd_db.camera.camera_id == "CAM-01"

    # Verify Camera's relationship contains this evidence item
    cam_db = db_session.query(CameraModel).filter(CameraModel.camera_id == "CAM-01").first()
    cam_evd_ids = [e.evidence_id for e in cam_db.evidence_items]
    assert "EVD-TEST-EVT-LINK-01" in cam_evd_ids


# ==========================================
# 5. RBAC Authorization & Security Tests
# ==========================================

def test_evidence_rbac_unauthenticated_rejected(client: TestClient):
    resp = client.get("/api/evidence")
    assert resp.status_code == 401

    resp_post = client.post("/api/evidence", json={})
    assert resp_post.status_code == 401


def test_evidence_rbac_viewer_denied_creation_and_verification(client: TestClient):
    viewer_token = get_token(client, "viewer")
    t_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    t_end = datetime.now(timezone.utc) - timedelta(minutes=1)

    # 1. Viewer cannot create evidence
    create_payload = {
        "evidence_id": "EVD-TEST-VIEWER-NO",
        "camera_id": "CAM-01",
        "timestamp_start": t_start.isoformat(),
        "timestamp_end": t_end.isoformat(),
        "source_reference": "rtsp://cam-01",
        "clip_reference": "clip.mp4",
        "confidence": 0.8,
    }
    resp_create = client.post(
        "/api/evidence",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json=create_payload,
    )
    assert resp_create.status_code == 403
    assert "evidence.verify" in resp_create.json()["detail"]

    # 2. Viewer cannot verify evidence
    resp_verify = client.post(
        "/api/evidence/EVD-TEST-001/verify",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"status": "VERIFIED"},
    )
    assert resp_verify.status_code == 403
    assert "evidence.verify" in resp_verify.json()["detail"]

    # 3. Viewer CAN read evidence
    resp_read = client.get("/api/evidence", headers={"Authorization": f"Bearer {viewer_token}"})
    assert resp_read.status_code == 200
