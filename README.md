# vex-auth

One Twitch sign-in for every vexoul.net site. Sign in on any of them and the others know you too. It also
keeps the few things that belong to a person rather than a browser, starting with VOD watch progress.

It is a small FastAPI service over Postgres. The sites talk to it from the browser; the backends that
have their own admin (the bot's web admin, the VOD archive's admin) sign people in through it with a
one-time code, like any OAuth provider.

## How it works

- **The session** is an HttpOnly cookie on the service's own host (`__Host-` prefixed in production). The
  sites are on sibling hosts of the same site, so a credentialed `fetch` from them carries it, and CORS
  lets only the configured site origins read the answers.
- **Signing in** (`GET /login?return=<site URL>`) goes to Twitch with no extra scope, then back to the
  page. The return address must be on one of the configured sites.
- **Backends** redirect to `GET /authorize?client_id&redirect_uri&state[&scope]`. Already signed in with
  the scopes asked for, the browser comes straight back with a code; otherwise it goes through Twitch
  first. The backend trades the code (`POST /v1/token`, HTTP Basic with its id and secret) for the user
  and a session id, and checks the session is still alive with `GET /v1/sessions/{sid}`, which is how
  "sign out everywhere" reaches it. A client registered for `user:read:moderated_channels` can ask
  `GET /v1/users/{id}/moderated-channels`.
- **Codes without a redirect:** a site whose backend needs to know who is signed in, from a `fetch`
  with no page redirect, asks `POST /v1/codes {client_id}` (credentialed, with `X-Vex-CSRF`) and
  hands the code to its backend, which redeems it with `POST /v1/token` as usual. It is the same
  one-time code `/authorize` mints (same TTL, one use, bound to the client), and a redeemed one counts
  for `GET /v1/sessions/{sid}` the same way. Such a code carries the client's **first registered
  redirect URI**, so the backend sends that URI to `/v1/token`. It shares `/authorize`'s rate limit. If
  the client is registered for scopes the user's stored Twitch token lacks, the answer is 409
  `scope_missing`, and the browser has to go through `/authorize` once.
  Any script running on a configured site origin can mint a code for any registered client. That gives
  it nothing new: such a script can already call that site's backend same-origin with the user's
  cookies.
- **Twitch tokens** are stored encrypted (`AUTH_TOKEN_KEY`). A plain sign-in never replaces a stored
  token that carries more scopes.
- **Errors** come back to the site as `?auth_error=denied|expired|twitch`, and to a backend's redirect
  address as `?error=...&state=...`.

| Endpoint | For | What |
|---|---|---|
| `GET /v1/me` | sites | `{id, login, displayName, avatar, color, csrf, expiresAt}`, or 401 |
| `POST /v1/logout[?everywhere=1]` | sites | ends this session or all of the user's; needs `X-Vex-CSRF` |
| `POST /v1/codes` | sites | `{client_id}` → `{code}` for that backend; 401 `signed_out`, 403 `csrf`, 409 `scope_missing`, 400 `unknown_client`, 429 `rate_limited` |
| `GET /v1/progress[?limit=]` | sites | the user's progress, newest first |
| `GET/PUT/DELETE /v1/progress/{vodId}` | sites | one entry; `PUT {t, duration, updatedAt}`, newest wins |
| `POST /v1/progress/merge` | sites | `{items: [...]}`, newest wins per entry (a browser's local progress) |
| `GET /healthz` | ops | the process answers (liveness; the container's `HEALTHCHECK`), no dependency checks |
| `GET /readyz` | ops | the database answers too, else 503 naming it. Point uptime monitors here |

Writes need the `X-Vex-CSRF` header with the `csrf` from `/v1/me`.

## Running it

Copy `.env.example` to `.env` and `secrets.example/` to `secrets/`, and fill both in (a Twitch application
whose redirect URL is `<AUTH_PUBLIC_URL>/callback`). With compose, the secrets reach the containers as files
in `/run/secrets`; `secrets.example/README.md` lists them and the owner each needs. Without compose, set them
as variables in `.env` instead (`AUTH_TOKEN_KEY` and so on), or point `AUTH_SECRETS_DIR` at the directory:

```sh
uv sync --extra dev
uv run vex-auth db upgrade   # before every start: migrations are their own step
uv run vex-auth serve
```

`serve` refuses to start on a database behind the code. The container image (`ghcr.io/vexouluna/vex-auth`)
has the same entry point: run `db upgrade` as a one-shot before the service.

## Developing

Tests run against a real Postgres (`TEST_DATABASE_URL`, default `postgresql://postgres:postgres@127.0.0.1:55432/postgres`);
they create and drop their own database, and check that every migration downgrades.

```sh
docker run -d --name vex-auth-pg -e POSTGRES_PASSWORD=postgres -p 55432:5432 postgres:17-alpine
uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

A new migration: there is no alembic.ini (the URL comes from the environment), so copy the newest revision in
`src/vex_auth/migrations/versions/`, give it the next number, and write both `upgrade` and `downgrade`.

Branches follow [CONTRIBUTING.md](CONTRIBUTING.md): `main` is merge-only.
