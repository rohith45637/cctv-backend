"""Add threat and incident enhancements

Revision ID: 003_threat_incident_enhancements
Revises: 002_add_auth_enhancements
Create Date: 2026-10-08 16:55:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "003_threat_incident_enhancements"
down_revision: Union[str, None] = "002_add_auth_enhancements"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Update threats table
    with op.batch_alter_table("threats", schema=None) as batch_op:
        batch_op.add_column(sa.Column("severity", sa.String(length=32), server_default="MEDIUM", nullable=False))
        batch_op.add_column(sa.Column("risk_score", sa.Float(), server_default="0.0", nullable=False))
        batch_op.add_column(sa.Column("reason", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("incident_id", sa.String(length=64), nullable=True))
        batch_op.create_index("ix_threats_severity_status", ["severity", "status"])
        batch_op.create_index("ix_threats_incident_id", ["incident_id"])

    # 2. Update incidents table
    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.add_column(sa.Column("primary_camera_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("related_event_ids", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("related_threat_ids", sa.JSON(), nullable=True))
        batch_op.create_index("ix_incidents_primary_camera_id", ["primary_camera_id"])


def downgrade() -> None:
    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.drop_index("ix_incidents_primary_camera_id")
        batch_op.drop_column("related_threat_ids")
        batch_op.drop_column("related_event_ids")
        batch_op.drop_column("primary_camera_id")

    with op.batch_alter_table("threats", schema=None) as batch_op:
        batch_op.drop_index("ix_threats_incident_id")
        batch_op.drop_index("ix_threats_severity_status")
        batch_op.drop_column("incident_id")
        batch_op.drop_column("reason")
        batch_op.drop_column("risk_score")
        batch_op.drop_column("severity")
