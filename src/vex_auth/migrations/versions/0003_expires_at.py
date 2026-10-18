"""Index the expires_at columns the expired-row cleanup deletes by (sign-in states, one-time codes).

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-09
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("login_states_expires_at", "login_states", ["expires_at"])
    op.create_index("codes_expires_at", "codes", ["expires_at"])


def downgrade() -> None:
    op.drop_index("codes_expires_at", table_name="codes")
    op.drop_index("login_states_expires_at", table_name="login_states")
