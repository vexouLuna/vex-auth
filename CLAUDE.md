@.conventions/CLAUDE.md

# vex-auth

The Twitch sign-in shared by every vexoul.net site, plus per-user data (watch progress). A FastAPI service
over Postgres, published as `ghcr.io/vexouluna/vex-auth`; production follows `:main`.

- It handles sessions and Twitch tokens. Never log or return a Twitch token, client secret or session
  token, and check every return URL, redirect URI and origin against the configuration.
- Migrations are their own step (`vex-auth db upgrade`), and `serve` refuses a database behind the
  code. A schema change is a new revision with a working downgrade; the tests run every revision down
  and up again. There is no alembic.ini: copy the newest file in `src/vex_auth/migrations/versions/`.
- Tests need Postgres at `TEST_DATABASE_URL` (see README "Developing"); they create and drop their own
  database.
- A release tag `vX.Y.Z` must equal `version` in pyproject.toml (`__version__` reads it from the installed
  package).
