"""Add auth enhancements and refresh tokens

Revision ID: 002_add_auth_enhancements
Revises: 001_initial_core
Create Date: 2026-10-08 16:35:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "002_add_auth_enhancements"
down_revision: Union[str, None] = "001_initial_core"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add display_name column to users table if missing
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(sa.Column("display_name", sa.String(length=255), nullable=True))

    # 2. Create refresh_tokens table
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("token", sa.String(length=500), nullable=False),
        sa.Column("jti", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_revoked", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token"),
        sa.UniqueConstraint("jti"),
    )
    op.create_index("ix_refresh_tokens_id", "refresh_tokens", ["id"])
    op.create_index("ix_refresh_tokens_token", "refresh_tokens", ["token"])
    op.create_index("ix_refresh_tokens_jti", "refresh_tokens", ["jti"])
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
    op.create_index("ix_refresh_tokens_is_revoked", "refresh_tokens", ["is_revoked"])
    op.create_index("ix_refresh_tokens_user_revoked", "refresh_tokens", ["user_id", "is_revoked"])


def downgrade() -> None:
    op.drop_index("ix_refresh_tokens_user_revoked", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_is_revoked", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_user_id", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_jti", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_token", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_id", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")

    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_column("display_name")
