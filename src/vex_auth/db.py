"""The tables, and the migrations that make them.

The service only ever reads and writes these through SQLAlchemy Core. The schema itself is owned by the
Alembic revisions in `migrations/versions`, which run as their own step (`vex-auth db upgrade`)
before the service starts; the tables here must match what the revisions create.
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import (
    ARRAY,
    BigInteger,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    LargeBinary,
    MetaData,
    PrimaryKeyConstraint,
    Table,
    Text,
    create_engine,
)
from sqlalchemy.dialects.postgresql import JSONB

MIGRATIONS = Path(__file__).parent / "migrations"

metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("id", Text, primary_key=True),  # the Twitch user id
    Column("login", Text, nullable=False),
    Column("display_name", Text, nullable=False),
    Column("avatar", Text),
    Column("color", Text),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

twitch_tokens = Table(
    "twitch_tokens",
    metadata,
    Column("user_id", Text, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("access_enc", LargeBinary, nullable=False),
    Column("refresh_enc", LargeBinary),
    Column("scopes", ARRAY(Text), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

sessions = Table(
    "sessions",
    metadata,
    Column("id", Text, primary_key=True),  # the sid backends hold; never the cookie value
    Column("token_hash", LargeBinary, nullable=False, unique=True),
    Column("user_id", Text, ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("csrf", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("revoked_at", DateTime(timezone=True)),
    Index("sessions_user_id", "user_id"),
)

codes = Table(
    "codes",
    metadata,
    Column("code_hash", LargeBinary, primary_key=True),
    Column("client_id", Text, nullable=False),
    Column("redirect_uri", Text, nullable=False),
    Column("session_id", Text, ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False),
    Column("user_id", Text, ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("used_at", DateTime(timezone=True)),
    Index("codes_client_session", "client_id", "session_id"),
    Index("codes_client_user", "client_id", "user_id"),
    Index("codes_expires_at", "expires_at"),
)

login_states = Table(
    "login_states",
    metadata,
    Column("state_hash", LargeBinary, primary_key=True),
    Column("return_to", Text),  # a site URL, for a browser sign-in
    Column("client_id", Text),  # or the client whose /authorize started it
    Column("client_redirect_uri", Text),
    Column("client_state", Text),
    Column("scopes", ARRAY(Text), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Index("login_states_expires_at", "expires_at"),
)

progress = Table(
    "progress",
    metadata,
    Column("user_id", Text, ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("vod_id", Text, nullable=False),
    Column("t", Float, nullable=False),
    Column("duration", Float, nullable=False),
    Column("updated_at", BigInteger, nullable=False),  # epoch ms, as the browser saw it
    PrimaryKeyConstraint("user_id", "vod_id"),
    Index("progress_user_updated", "user_id", "updated_at"),
)

audit = Table(
    "audit",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("at", DateTime(timezone=True), nullable=False),
    Column("event", Text, nullable=False),
    Column("user_id", Text),
    Column("client_id", Text),
    Column("ip", Text),
    Column("detail", JSONB),
    Index("audit_at", "at"),
)


def alembic_config(url: str) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))  # ConfigParser interpolation
    return cfg


def upgrade(url: str, revision: str = "head") -> None:
    command.upgrade(alembic_config(url), revision)


def downgrade(url: str, revision: str) -> None:
    command.downgrade(alembic_config(url), revision)


def current(url: str) -> tuple[str | None, str | None]:
    """(the database's revision, the newest revision this code knows)."""
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            found = MigrationContext.configure(conn).get_current_revision()
    finally:
        engine.dispose()
    return found, ScriptDirectory.from_config(alembic_config(url)).get_current_head()
