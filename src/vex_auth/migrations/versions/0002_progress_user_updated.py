"""Index progress by (user_id, updated_at): listing a user's newest entries and trimming the oldest.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-09
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("progress_user_updated", "progress", ["user_id", "updated_at"])


def downgrade() -> None:
    op.drop_index("progress_user_updated", table_name="progress")
