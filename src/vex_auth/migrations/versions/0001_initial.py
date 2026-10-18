"""Users, their Twitch tokens, sessions, one-time codes, sign-in states, watch progress and the audit log.

Revision ID: 0001
Revises:
Create Date: 2026-09-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("login", sa.Text, nullable=False),
        sa.Column("display_name", sa.Text, nullable=False),
        sa.Column("avatar", sa.Text),
        sa.Column("color", sa.Text),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
    )
    op.create_table(
        "twitch_tokens",
        sa.Column("user_id", sa.Text, sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("access_enc", sa.LargeBinary, nullable=False),
        sa.Column("refresh_enc", sa.LargeBinary),
        sa.Column("scopes", postgresql.ARRAY(sa.Text), nullable=False),
        sa.Column("updated_at", TS, nullable=False),
    )
    op.create_table(
        "sessions",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("token_hash", sa.LargeBinary, nullable=False, unique=True),
        sa.Column("user_id", sa.Text, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("csrf", sa.Text, nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("revoked_at", TS),
    )
    op.create_index("sessions_user_id", "sessions", ["user_id"])
    op.create_table(
        "codes",
        sa.Column("code_hash", sa.LargeBinary, primary_key=True),
        sa.Column("client_id", sa.Text, nullable=False),
        sa.Column("redirect_uri", sa.Text, nullable=False),
        sa.Column("session_id", sa.Text, sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.Text, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("used_at", TS),
    )
    op.create_index("codes_client_session", "codes", ["client_id", "session_id"])
    op.create_index("codes_client_user", "codes", ["client_id", "user_id"])
    op.create_table(
        "login_states",
        sa.Column("state_hash", sa.LargeBinary, primary_key=True),
        sa.Column("return_to", sa.Text),
        sa.Column("client_id", sa.Text),
        sa.Column("client_redirect_uri", sa.Text),
        sa.Column("client_state", sa.Text),
        sa.Column("scopes", postgresql.ARRAY(sa.Text), nullable=False),
        sa.Column("expires_at", TS, nullable=False),
    )
    op.create_table(
        "progress",
        sa.Column("user_id", sa.Text, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("vod_id", sa.Text, nullable=False),
        sa.Column("t", sa.Float, nullable=False),
        sa.Column("duration", sa.Float, nullable=False),
        sa.Column("updated_at", sa.BigInteger, nullable=False),
        sa.PrimaryKeyConstraint("user_id", "vod_id"),
    )
    op.create_table(
        "audit",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("at", TS, nullable=False),
        sa.Column("event", sa.Text, nullable=False),
        sa.Column("user_id", sa.Text),
        sa.Column("client_id", sa.Text),
        sa.Column("ip", sa.Text),
        sa.Column("detail", postgresql.JSONB),
    )
    op.create_index("audit_at", "audit", ["at"])


def downgrade() -> None:
    op.drop_table("audit")
    op.drop_table("progress")
    op.drop_table("login_states")
    op.drop_table("codes")
    op.drop_table("sessions")
    op.drop_table("twitch_tokens")
    op.drop_table("users")
