from enum import Enum


class EventType(str, Enum):
    """
    Standard surveillance event types recognized by AI Video Intelligence
    and Backend Security Core. Extensible for custom analytics models.
    """
    PERSON_DETECTED = "PERSON_DETECTED"
    VEHICLE_DETECTED = "VEHICLE_DETECTED"
    OBJECT_DETECTED = "OBJECT_DETECTED"
    ZONE_ENTRY = "ZONE_ENTRY"
    ZONE_EXIT = "ZONE_EXIT"
    LINE_CROSSING = "LINE_CROSSING"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    CAMERA_STATUS_CHANGED = "CAMERA_STATUS_CHANGED"
    BLINDSPOT_DETECTED = "BLINDSPOT_DETECTED"
    EVIDENCE_AVAILABLE = "EVIDENCE_AVAILABLE"

    # Additional standard surveillance operational types
    INTRUSION = "INTRUSION"
    LOITERING = "LOITERING"
    TAILGATING = "TAILGATING"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"


class EventStatus(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    VERIFIED = "VERIFIED"
    DISMISSED = "DISMISSED"
    ESCALATED = "ESCALATED"
