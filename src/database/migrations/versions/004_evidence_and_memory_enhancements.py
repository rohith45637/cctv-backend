"""Add evidence provenance and security memory context fields

Revision ID: 004_evidence_and_memory_enhancements
Revises: 003_threat_incident_enhancements
Create Date: 2026-10-08 17:10:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "004_evidence_and_memory_enhancements"
down_revision: Union[str, None] = "003_threat_incident_enhancements"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Update evidence table
    with op.batch_alter_table("evidence", schema=None) as batch_op:
        batch_op.add_column(sa.Column("source_type", sa.String(length=32), server_default="AI_VIDEO", nullable=False))
        batch_op.add_column(sa.Column("provenance_json", sa.JSON(), nullable=True))
        batch_op.create_index("ix_evidence_source_type", ["source_type"])

    # 2. Update evidence_verifications table
    with op.batch_alter_table("evidence_verifications", schema=None) as batch_op:
        batch_op.add_column(sa.Column("provenance_snapshot_json", sa.JSON(), nullable=True))

    # 3. Update security_memory table
    with op.batch_alter_table("security_memory", schema=None) as batch_op:
        batch_op.add_column(sa.Column("camera_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("zone_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("event_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("incident_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("content", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("source_reference", sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.create_index("ix_memory_camera_id", ["camera_id"])
        batch_op.create_index("ix_memory_zone_id", ["zone_id"])
        batch_op.create_index("ix_memory_event_id", ["event_id"])
        batch_op.create_index("ix_memory_incident_id", ["incident_id"])
        batch_op.create_index("ix_memory_expires_at", ["expires_at"])


def downgrade() -> None:
    with op.batch_alter_table("security_memory", schema=None) as batch_op:
        batch_op.drop_index("ix_memory_expires_at")
        batch_op.drop_index("ix_memory_incident_id")
        batch_op.drop_index("ix_memory_event_id")
        batch_op.drop_index("ix_memory_zone_id")
        batch_op.drop_index("ix_memory_camera_id")
        batch_op.drop_column("expires_at")
        batch_op.drop_column("source_reference")
        batch_op.drop_column("content")
        batch_op.drop_column("incident_id")
        batch_op.drop_column("event_id")
        batch_op.drop_column("zone_id")
        batch_op.drop_column("camera_id")

    with op.batch_alter_table("evidence_verifications", schema=None) as batch_op:
        batch_op.drop_column("provenance_snapshot_json")

    with op.batch_alter_table("evidence", schema=None) as batch_op:
        batch_op.drop_index("ix_evidence_source_type")
        batch_op.drop_column("provenance_json")
        batch_op.drop_column("source_type")
