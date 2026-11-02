"""Record which backend was handed which session, so cleaning up old codes cannot forget it.

Backfills from the used codes still in the table; a sign-in whose code the cleanup already deleted is lost.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-02
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "session_clients",
        sa.Column("session_id", sa.Text, sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.Text, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("client_id", sa.Text, nullable=False),
        sa.PrimaryKeyConstraint("session_id", "client_id"),
    )
    op.create_index("session_clients_client_user", "session_clients", ["client_id", "user_id"])
    op.execute(
        "INSERT INTO session_clients (session_id, user_id, client_id) "
        "SELECT DISTINCT session_id, user_id, client_id FROM codes WHERE used_at IS NOT NULL"
    )


def downgrade() -> None:
    op.drop_index("session_clients_client_user", table_name="session_clients")
    op.drop_table("session_clients")
