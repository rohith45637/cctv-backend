from datetime import datetime, timezone
import pytest
from pydantic import ValidationError
from src.schemas import (
    Event,
    Evidence,
    Camera,
    Zone,
    SecurityPolicy,
    Threat,
    Incident,
    Investigation,
    SecurityMemory,
    RealtimeEvent,
    CopilotQueryRequest,
    CopilotQueryResponse,
    AuditLogResponse,
)


def test_common_event_schema_contract():
    now = datetime.now(timezone.utc)
    event_data = {
        "event_id": "EVT-TEST001",
        "camera_id": "CAM-01",
        "timestamp": now.isoformat(),
        "event_type": "INTRUSION",
        "entity_id": "ENT-PERSON01",
        "zone_id": "ZONE-01",
        "confidence": 0.95,
        "evidence_id": "EVD-CLIP001",
        "source": "ai-video",
        "status": "NEW",
        "schema_version": "1.0",
    }
    event = Event(**event_data)
    assert event.event_id == "EVT-TEST001"
    assert event.camera_id == "CAM-01"
    assert event.confidence == 0.95
    assert event.schema_version == "1.0"


def test_common_event_schema_validation_failures():
    now = datetime.now(timezone.utc)
    # Invalid confidence (> 1.0)
    with pytest.raises(ValidationError):
        Event(
            event_id="EVT-01",
            camera_id="CAM-01",
            timestamp=now,
            event_type="INTRUSION",
            confidence=1.5,
            source="ai-video",
            status="NEW",
        )

    # Invalid event_id format
    with pytest.raises(ValidationError):
        Event(
            event_id="INVALID-ID",
            camera_id="CAM-01",
            timestamp=now,
            event_type="INTRUSION",
            confidence=0.8,
            source="ai-video",
            status="NEW",
        )


def test_common_evidence_schema_contract():
    t_start = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 8, 12, 0, 30, tzinfo=timezone.utc)
    evidence_data = {
        "evidence_id": "EVD-CLIP001",
        "camera_id": "CAM-01",
        "event_id": "EVT-001",
        "timestamp_start": t_start.isoformat(),
        "timestamp_end": t_end.isoformat(),
        "source_reference": "rtsp://demo-mock/cameras/cam-01",
        "clip_reference": "storage/evidence/cam-01/clip.mp4",
        "confidence": 0.92,
        "verification_status": "VERIFIED",
        "schema_version": "1.0",
    }
    evidence = Evidence(**evidence_data)
    assert evidence.evidence_id == "EVD-CLIP001"
    assert evidence.camera_id == "CAM-01"
    assert evidence.schema_version == "1.0"


def test_common_evidence_schema_invalid_time_range():
    t_start = datetime(2026, 10, 8, 12, 1, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)  # end before start
    with pytest.raises(ValidationError, match="timestamp_end cannot precede timestamp_start"):
        Evidence(
            evidence_id="EVD-01",
            camera_id="CAM-01",
            timestamp_start=t_start,
            timestamp_end=t_end,
            source_reference="rtsp://stream",
            clip_reference="clip.mp4",
            confidence=0.8,
        )


def test_all_shared_schemas_have_version_1_0():
    cam = Camera(camera_id="CAM-01", name="Gate")
    zone = Zone(zone_id="ZONE-01", name="Perimeter")
    pol = SecurityPolicy(policy_id="POL-01", name="Intrusion", policy_type="INTRUSION")
    threat = Threat(threat_id="THR-01", title="Suspicious loitering")
    inc = Incident(incident_id="INC-01", title="Perimeter Breach")
    inv = Investigation(investigation_id="INV-01", incident_id="INC-01", title="Dossier")
    mem = SecurityMemory(memory_id="MEM-01", memory_type="KNOWN_PERSON")
    rt = RealtimeEvent(event_id="EVT-01", topic="security.events", event_type="DETECTED", payload={})
    c_req = CopilotQueryRequest(query="status check")
    c_resp = CopilotQueryResponse(query="status check", answer="all clear", confidence=1.0, status="CONFIRMED")
    audit_resp = AuditLogResponse(id=1, action="LOGIN", resource_type="auth", created_at=datetime.now(timezone.utc))

    assert cam.schema_version == "1.0"
    assert zone.schema_version == "1.0"
    assert pol.schema_version == "1.0"
    assert threat.schema_version == "1.0"
    assert inc.schema_version == "1.0"
    assert inv.schema_version == "1.0"
    assert mem.schema_version == "1.0"
    assert rt.schema_version == "1.0"
    assert c_req.schema_version == "1.0"
    assert c_resp.schema_version == "1.0"
    assert audit_resp.schema_version == "1.0"
