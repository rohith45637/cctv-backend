from datetime import datetime, timezone
import pytest
from sqlalchemy.orm import Session
from src.database.models import (
    Camera,
    Zone,
    ZoneCameraMapping,
    SecurityPolicy,
    Event,
    Evidence,
    User,
    Role,
    AuditLog,
    SystemSetting,
)


def test_core_tables_registered():
    from src.database.models import Base
    table_names = set(Base.metadata.tables.keys())
    expected = {
        "users",
        "roles",
        "permissions",
        "user_roles",
        "role_permissions",
        "cameras",
        "camera_status_history",
        "zones",
        "zone_camera_mapping",
        "security_policies",
        "events",
        "event_entities",
        "threats",
        "incidents",
        "investigations",
        "investigation_events",
        "evidence",
        "evidence_verifications",
        "security_memory",
        "audit_logs",
        "system_settings",
    }
    for t in expected:
        assert t in table_names, f"Table {t} missing from Base.metadata"


def test_seeded_demo_data(db_session: Session):
    cameras = db_session.query(Camera).all()
    assert len(cameras) >= 3
    cam_ids = [c.camera_id for c in cameras]
    assert "CAM-01" in cam_ids
    assert "CAM-02" in cam_ids
    assert "CAM-03" in cam_ids

    zones = db_session.query(Zone).all()
    assert len(zones) >= 3
    zone_ids = [z.zone_id for z in zones]
    assert "ZONE-01" in zone_ids
    assert "ZONE-02" in zone_ids
    assert "ZONE-03" in zone_ids

    # Check zone-camera mapping
    mapping = db_session.query(ZoneCameraMapping).filter(ZoneCameraMapping.zone_id == "ZONE-01").first()
    assert mapping is not None
    assert mapping.camera_id == "CAM-01"
    assert mapping.primary_camera is True


def test_event_and_evidence_relationship(db_session: Session):
    now = datetime.now(timezone.utc)
    # Create test event
    event = Event(
        event_id="EVT-UNIT-01",
        camera_id="CAM-01",
        zone_id="ZONE-01",
        timestamp=now,
        event_type="INTRUSION",
        confidence=0.88,
        source="ai-video",
        status="NEW",
    )
    db_session.add(event)
    db_session.commit()

    # Create associated evidence
    evidence = Evidence(
        evidence_id="EVD-UNIT-01",
        camera_id="CAM-01",
        event_id=event.event_id,
        timestamp_start=now,
        timestamp_end=now,
        source_reference="rtsp://demo/cam-01",
        clip_reference="clips/cam01-001.mp4",
        confidence=0.9,
        verification_status="UNVERIFIED",
    )
    db_session.add(evidence)
    db_session.commit()

    # Query back and verify ORM links
    fetched_event = db_session.query(Event).filter(Event.event_id == "EVT-UNIT-01").first()
    assert fetched_event is not None
    assert fetched_event.camera.name == "[DEMO] CAM-01 Main Gate"
    assert fetched_event.zone.name == "[DEMO] Perimeter - Main Gate"

    fetched_evidence = db_session.query(Evidence).filter(Evidence.evidence_id == "EVD-UNIT-01").first()
    assert fetched_evidence is not None
    assert fetched_evidence.camera_id == "CAM-01"
    assert fetched_evidence.event.event_type == "INTRUSION"
