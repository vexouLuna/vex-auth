"""Alembic environment. The URL comes from `db.alembic_config`, never from a file in the repo."""

from alembic import context
from sqlalchemy import create_engine

from vex_auth.db import metadata

url = context.config.get_main_option("sqlalchemy.url")
assert url, "run migrations through `vex-auth db`, which supplies the database URL"
engine = create_engine(url)
with engine.connect() as connection:
    context.configure(connection=connection, target_metadata=metadata)
    with context.begin_transaction():
        context.run_migrations()
engine.dispose()
