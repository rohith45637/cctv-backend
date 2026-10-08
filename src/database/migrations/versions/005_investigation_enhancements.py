"""Add investigation lifecycle and multi-trigger relationship fields

Revision ID: 005_investigation_enhancements
Revises: 004_evidence_and_memory_enhancements
Create Date: 2026-10-08 17:35:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "005_investigation_enhancements"
down_revision: Union[str, None] = "004_evidence_and_memory_enhancements"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("investigations", schema=None) as batch_op:
        batch_op.add_column(sa.Column("description", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("priority", sa.String(length=32), server_default="MEDIUM", nullable=False))
        batch_op.add_column(sa.Column("trigger_event_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("trigger_threat_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("trigger_incident_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("assigned_user_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))

        batch_op.create_index("ix_investigations_priority", ["priority"])
        batch_op.create_index("ix_investigations_trigger_event_id", ["trigger_event_id"])
        batch_op.create_index("ix_investigations_trigger_threat_id", ["trigger_threat_id"])
        batch_op.create_index("ix_investigations_trigger_incident_id", ["trigger_incident_id"])
        batch_op.create_index("ix_investigations_assigned_user_id", ["assigned_user_id"])


def downgrade() -> None:
    with op.batch_alter_table("investigations", schema=None) as batch_op:
        batch_op.drop_index("ix_investigations_assigned_user_id")
        batch_op.drop_index("ix_investigations_trigger_incident_id")
        batch_op.drop_index("ix_investigations_trigger_threat_id")
        batch_op.drop_index("ix_investigations_trigger_event_id")
        batch_op.drop_index("ix_investigations_priority")

        batch_op.drop_column("completed_at")
        batch_op.drop_column("assigned_user_id")
        batch_op.drop_column("trigger_incident_id")
        batch_op.drop_column("trigger_threat_id")
        batch_op.drop_column("trigger_event_id")
        batch_op.drop_column("priority")
        batch_op.drop_column("description")
