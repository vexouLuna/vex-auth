"""Overlay files (sounds, images) a user uploads, and a public id per preset so an OBS source can read it.

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-17
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PUBLIC_ID_DEFAULT = "replace(gen_random_uuid()::text, '-', '')"


def upgrade() -> None:
    op.create_table(
        "files",
        sa.Column("id", sa.Text, primary_key=True),  # unguessable: the public link is the only key
        sa.Column("user_id", sa.Text, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("content_type", sa.Text, nullable=False),
        sa.Column("size_bytes", sa.Integer, nullable=False),
        sa.Column("data", sa.LargeBinary, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("files_user_id", "files", ["user_id"])
    # 122 random bits, drawn per row (the default is volatile, so existing rows each get their own). The service
    # sets its own value; the default also covers the previous release, which still serves while this migrates
    # and inserts presets without one.
    op.add_column(
        "presets",
        sa.Column("public_id", sa.Text, nullable=False, server_default=sa.text(PUBLIC_ID_DEFAULT)),
    )
    op.create_unique_constraint("presets_public_id", "presets", ["public_id"])


def downgrade() -> None:
    op.drop_constraint("presets_public_id", "presets")
    op.drop_column("presets", "public_id")
    op.drop_index("files_user_id", "files")
    op.drop_table("files")
