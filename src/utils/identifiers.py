import re
import uuid
from typing import Literal

IDType = Literal[
    "camera_id",
    "zone_id",
    "event_id",
    "incident_id",
    "evidence_id",
    "investigation_id",
    "threat_id",
    "entity_id",
    "user_id",
    "memory_id",
]

PREFIX_MAP = {
    "camera_id": "CAM",
    "zone_id": "ZONE",
    "event_id": "EVT",
    "incident_id": "INC",
    "evidence_id": "EVD",
    "investigation_id": "INV",
    "threat_id": "THR",
    "entity_id": "ENT",
    "user_id": "USR",
    "memory_id": "MEM",
}


def generate_identifier(id_type: IDType, custom_suffix: str = None) -> str:
    """
    Centrally generate a stable, canonical shared identifier.
    Format: {PREFIX}-{HEX/CUSTOM}
    """
    if id_type not in PREFIX_MAP:
        raise ValueError(f"Unknown id_type: {id_type}. Must be one of {list(PREFIX_MAP.keys())}")

    prefix = PREFIX_MAP[id_type]
    if custom_suffix:
        # Sanitize custom suffix to alphanumeric and dashes
        clean_suffix = re.sub(r"[^A-Za-z0-9_-]", "", custom_suffix).upper()
        return f"{prefix}-{clean_suffix}"
    
    unique_suffix = uuid.uuid4().hex[:12].upper()
    return f"{prefix}-{unique_suffix}"


def validate_identifier(id_value: str, id_type: IDType) -> bool:
    """
    Validate that an identifier adheres to the canonical prefix and naming schema.
    """
    if not id_value or not isinstance(id_value, str):
        return False
    
    prefix = PREFIX_MAP.get(id_type)
    if not prefix:
        return False

    pattern = rf"^{prefix}-[A-Za-z0-9_-]{{2,64}}$"
    return bool(re.match(pattern, id_value.strip()))
