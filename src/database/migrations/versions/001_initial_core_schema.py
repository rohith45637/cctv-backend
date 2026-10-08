"""Initial core security schema

Revision ID: 001_initial_core
Revises: 
Create Date: 2026-10-08 16:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "001_initial_core"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Users
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("username", sa.String(length=100), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=32), server_default="ACTIVE", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("is_demo", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_deleted", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
        sa.UniqueConstraint("user_id"),
        sa.UniqueConstraint("username"),
    )
    op.create_index("ix_users_user_id", "users", ["user_id"])
    op.create_index("ix_users_status", "users", ["status"])

    # 2. Roles
    op.create_table(
        "roles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=True),
        sa.Column("is_system_role", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    # 3. Permissions
    op.create_table(
        "permissions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("code", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code"),
    )

    # 4. User Roles
    op.create_table(
        "user_roles",
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("role_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "role_id"),
    )

    # 5. Role Permissions
    op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.Integer(), nullable=False),
        sa.Column("permission_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["permission_id"], ["permissions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("role_id", "permission_id"),
    )

    # 6. Cameras
    op.create_table(
        "cameras",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("camera_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("stream_url", sa.String(length=500), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("location_description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=32), server_default="ONLINE", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("is_demo", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("schema_version", sa.String(length=16), server_default="1.0", nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_deleted", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("camera_id"),
    )
    op.create_index("ix_cameras_camera_id", "cameras", ["camera_id"])
    op.create_index("ix_cameras_status_active", "cameras", ["status", "is_active"])

    # 7. Camera Status History
    op.create_table(
        "camera_status_history",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("camera_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=True),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["camera_id"], ["cameras.camera_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_camera_status_history_camera_id", "camera_status_history", ["camera_id"])

    # 8. Zones
    op.create_table(
        "zones",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("zone_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("risk_level", sa.String(length=32), server_default="MEDIUM", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("is_demo", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("schema_version", sa.String(length=16), server_default="1.0", nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_deleted", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("zone_id"),
    )
    op.create_index("ix_zones_zone_id", "zones", ["zone_id"])

    # 9. Zone Camera Mapping
    op.create_table(
        "zone_camera_mapping",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("zone_id", sa.String(length=64), nullable=False),
        sa.Column("camera_id", sa.String(length=64), nullable=False),
        sa.Column("primary_camera", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["camera_id"], ["cameras.camera_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["zone_id"], ["zones.zone_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("zone_id", "camera_id", name="uq_zone_camera"),
    )
    op.create_index("ix_zone_camera_composite", "zone_camera_mapping", ["zone_id", "camera_id"])

    # 10. Security Policies
    op.create_table(
        "security_policies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("policy_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("zone_id", sa.String(length=64), nullable=True),
        sa.Column("policy_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), server_default="MEDIUM", nullable=False),
        sa.Column("rules_json", sa.JSON(), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("is_demo", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("schema_version", sa.String(length=16), server_default="1.0", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_deleted", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["zone_id"], ["zones.zone_id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("policy_id"),
    )
    op.create_index("ix_security_policies_policy_id", "security_policies", ["policy_id"])

    # 11. Events
    op.create_table(
        "events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("camera_id", sa.String(length=64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("entity_id", sa.String(length=64), nullable=True),
        sa.Column("zone_id", sa.String(length=64), nullable=True),
        sa.Column("confidence", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("evidence_id", sa.String(length=64), nullable=True),
        sa.Column("source", sa.String(length=64), server_default="ai-video", nullable=False),
        sa.Column("status", sa.String(length=32), server_default="NEW", nullable=False),
        sa.Column("schema_version", sa.String(length=16), server_default="1.0", nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["camera_id"], ["cameras.camera_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["zone_id"], ["zones.zone_id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id"),
    )
    op.create_index("ix_events_event_id", "events", ["event_id"])
    op.create_index("ix_events_type_timestamp", "events", ["event_type", "timestamp"])
    op.create_index("ix_events_camera_timestamp", "events", ["camera_id", "timestamp"])

    # 12. Event Entities
    op.create_table(
        "event_entities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=64), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("bounding_box_json", sa.JSON(), nullable=True),
        sa.Column("confidence", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("tracking_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["event_id"], ["events.event_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_event_entities_event_id", "event_entities", ["event_id"])
    op.create_index("ix_event_entities_entity_id", "event_entities", ["entity_id"])

    # 13. Threats
    op.create_table(
        "threats",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("threat_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("threat_level", sa.String(length=32), server_default="MEDIUM", nullable=False),
        sa.Column("status", sa.String(length=32), server_default="DETECTED", nullable=False),
        sa.Column("camera_id", sa.String(length=64), nullable=True),
        sa.Column("zone_id", sa.String(length=64), nullable=True),
        sa.Column("event_id", sa.String(length=64), nullable=True),
        sa.Column("confidence", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("schema_version", sa.String(length=16), server_default="1.0", nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_deleted", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["camera_id"], ["cameras.camera_id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["event_id"], ["events.event_id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["zone_id"], ["zones.zone_id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("threat_id"),
    )
    op.create_index("ix_threats_threat_id", "threats", ["threat_id"])
    op.create_index("ix_threats_level_status", "threats", ["threat_level", "status"])

    # 14. Incidents
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=32), server_default="P2", nullable=False),
        sa.Column("status", sa.String(length=32), server_default="OPEN", nullable=False),
        sa.Column("lead_analyst_id", sa.String(length=64), nullable=True),
        sa.Column("zone_id", sa.String(length=64), nullable=True),
        sa.Column("threat_id", sa.String(length=64), nullable=True),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("schema_version", sa.String(length=16), server_default="1.0", nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_deleted", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["lead_analyst_id"], ["users.user_id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["threat_id"], ["threats.threat_id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["zone_id"], ["zones.zone_id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_id"),
    )
    op.create_index("ix_incidents_incident_id", "incidents", ["incident_id"])
    op.create_index("ix_incidents_severity_status", "incidents", ["severity", "status"])

    # 15. Investigations
    op.create_table(
        "investigations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("investigation_id", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="OPEN", nullable=False),
        sa.Column("findings", sa.Text(), nullable=True),
        sa.Column("investigator_id", sa.String(length=64), nullable=True),
        sa.Column("schema_version", sa.String(length=16), server_default="1.0", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("concluded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_deleted", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["investigator_id"], ["users.user_id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("investigation_id"),
    )
    op.create_index("ix_investigations_investigation_id", "investigations", ["investigation_id"])

    # 16. Investigation Events
    op.create_table(
        "investigation_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("investigation_id", sa.String(length=64), nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("added_by_user_id", sa.String(length=64), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["added_by_user_id"], ["users.user_id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["event_id"], ["events.event_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.investigation_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("investigation_id", "event_id", name="uq_investigation_event"),
    )

    # 17. Evidence
    op.create_table(
        "evidence",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.String(length=64), nullable=False),
        sa.Column("camera_id", sa.String(length=64), nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=True),
        sa.Column("timestamp_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("timestamp_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_reference", sa.String(length=500), nullable=False),
        sa.Column("clip_reference", sa.String(length=500), nullable=False),
        sa.Column("confidence", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("verification_status", sa.String(length=32), server_default="UNVERIFIED", nullable=False),
        sa.Column("schema_version", sa.String(length=16), server_default="1.0", nullable=False),
        sa.Column("storage_url", sa.String(length=500), nullable=True),
        sa.Column("hash_sha256", sa.String(length=64), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_deleted", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["camera_id"], ["cameras.camera_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["event_id"], ["events.event_id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("evidence_id"),
    )
    op.create_index("ix_evidence_evidence_id", "evidence", ["evidence_id"])
    op.create_index("ix_evidence_camera_time", "evidence", ["camera_id", "timestamp_start", "timestamp_end"])

    # 18. Evidence Verifications
    op.create_table(
        "evidence_verifications",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.String(length=64), nullable=False),
        sa.Column("verified_by_user_id", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.evidence_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["verified_by_user_id"], ["users.user_id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )

    # 19. Security Memory
    op.create_table(
        "security_memory",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("memory_id", sa.String(length=64), nullable=False),
        sa.Column("memory_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=64), nullable=True),
        sa.Column("identifier_value", sa.String(length=255), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("confidence", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("observations_count", sa.Integer(), server_default="1", nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schema_version", sa.String(length=16), server_default="1.0", nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_deleted", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("memory_id"),
    )
    op.create_index("ix_security_memory_memory_id", "security_memory", ["memory_id"])
    op.create_index("ix_memory_type_identifier", "security_memory", ["memory_type", "identifier_value"])

    # 20. Audit Logs
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=64), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("status", sa.String(length=32), server_default="SUCCESS", nullable=False),
        sa.Column("details_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_index("ix_audit_action_created", "audit_logs", ["action", "created_at"])

    # 21. System Settings
    op.create_table(
        "system_settings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(length=100), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=True),
        sa.Column("updated_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["updated_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key"),
    )


def downgrade() -> None:
    op.drop_table("system_settings")
    op.drop_table("audit_logs")
    op.drop_table("security_memory")
    op.drop_table("evidence_verifications")
    op.drop_table("evidence")
    op.drop_table("investigation_events")
    op.drop_table("investigations")
    op.drop_table("incidents")
    op.drop_table("threats")
    op.drop_table("event_entities")
    op.drop_table("events")
    op.drop_table("security_policies")
    op.drop_table("zone_camera_mapping")
    op.drop_table("zones")
    op.drop_table("camera_status_history")
    op.drop_table("cameras")
    op.drop_table("role_permissions")
    op.drop_table("user_roles")
    op.drop_table("permissions")
    op.drop_table("roles")
    op.drop_table("users")
