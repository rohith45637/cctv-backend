import pytest
from src.utils.identifiers import generate_identifier, validate_identifier, IDType, PREFIX_MAP


@pytest.mark.parametrize("id_type,expected_prefix", [
    ("camera_id", "CAM"),
    ("zone_id", "ZONE"),
    ("event_id", "EVT"),
    ("incident_id", "INC"),
    ("evidence_id", "EVD"),
    ("investigation_id", "INV"),
    ("threat_id", "THR"),
    ("entity_id", "ENT"),
    ("user_id", "USR"),
    ("memory_id", "MEM"),
])
def test_generate_and_validate_identifier(id_type: IDType, expected_prefix: str):
    # 1. Random generation
    generated_id = generate_identifier(id_type)
    assert generated_id.startswith(f"{expected_prefix}-")
    assert validate_identifier(generated_id, id_type) is True

    # 2. Custom suffix generation
    custom_id = generate_identifier(id_type, custom_suffix="TEST-01")
    assert custom_id == f"{expected_prefix}-TEST-01"
    assert validate_identifier(custom_id, id_type) is True


def test_invalid_identifiers():
    assert validate_identifier("INVALID_FORMAT", "camera_id") is False
    assert validate_identifier("CAM-", "camera_id") is False
    assert validate_identifier("ZONE-01", "camera_id") is False
    assert validate_identifier("", "event_id") is False
    assert validate_identifier(None, "user_id") is False


def test_unknown_id_type_raises():
    with pytest.raises(ValueError, match="Unknown id_type"):
        generate_identifier("invalid_type")  # type: ignore
