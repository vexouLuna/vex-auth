"""The HTTP service.

Browsers (the sites, from their own origins, with credentials):
  GET  /login?return=<site URL>   → Twitch → /callback → back to the site, signed in
  GET  /v1/me                     the signed-in user and their CSRF token, or 401
  POST /v1/logout[?everywhere=1]  ends this session, or every session of the user
  POST /v1/codes {client_id}      a one-time code for that backend, without a redirect
  /v1/progress[/{vodId}]          watch progress (GET, PUT, DELETE; POST /v1/progress/merge imports many)

Backends (registered clients, HTTP Basic with their id and secret):
  GET  /authorize?client_id&redirect_uri&state[&scope]   a one-time code; straight back when already signed in
  POST /v1/token                        {code, redirect_uri} → {user, sid, expiresAt}
  GET  /v1/sessions/{sid}               is that session still alive (how sign out everywhere reaches them)
  GET  /v1/users/{id}/moderated-channels   for clients registered with that scope

The session is a host-only cookie on this service's own host. Sites are same-site with it, so their
credentialed fetches carry it; CORS lets only the configured site origins read the answers.
"""

import asyncio
import base64
import binascii
import hashlib
import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import structlog
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import Result, Row, and_, delete, exists, insert, literal_column, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from vex_auth import __version__
from vex_auth.config import EXTRA_SCOPES, Client, Settings, origin_of
from vex_auth.db import audit, codes, login_states, progress, sessions, twitch_tokens, users
from vex_auth.twitch import (
    AUTHORIZE_URL,
    Profile,
    Token,
    TokenRevoked,
    TwitchClient,
    TwitchError,
    TwitchHttp,
)

log = structlog.get_logger(__name__)

CSRF_HEADER = "X-Vex-CSRF"
READY_TIMEOUT_S = 5  # /readyz: a database slower than this counts as down
STATE_TTL = timedelta(minutes=10)
CODE_TTL = timedelta(seconds=60)
CLEANUP_INTERVAL = timedelta(minutes=10)  # expired states and codes go at most this often, per process
MODERATED_SCOPE = "user:read:moderated_channels"
PROGRESS_MAX = 5000  # per user; the oldest go first
MERGE_MAX = 500  # entries in one merge
VOD_ID_PATTERN = r"^[A-Za-z0-9_.:-]{1,100}$"


def _hash(value: str) -> bytes:
    return hashlib.sha256(value.encode()).digest()


def with_query(url: str, **params: str) -> str:
    """`url` with `params` added to its query (replacing any of the same name)."""
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in params]
    return urlunsplit(parts._replace(query=urlencode(query + list(params.items()))))


class Limiter:
    """At most `limit` hits per key in any `window` seconds. In memory: one instance serves the sites."""

    def __init__(self, limit: int, window: float, clock: Callable[[], float] = time.monotonic) -> None:
        self.limit, self.window, self.clock = limit, window, clock
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = self.clock()
        if len(self._hits) > 10_000:  # forget quiet keys before the map grows without bound
            self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < self.window}
        hits = [t for t in self._hits.get(key, ()) if now - t < self.window]
        allowed = len(hits) < self.limit
        if allowed:
            hits.append(now)
        self._hits[key] = hits
        return allowed


@dataclass(frozen=True, slots=True)
class Session:
    id: str
    user_id: str
    csrf: str
    expires_at: datetime


class ProgressIn(BaseModel):
    t: float = Field(ge=0, allow_inf_nan=False)
    duration: float = Field(ge=0, allow_inf_nan=False)
    updatedAt: int = Field(ge=0)  # noqa: N815 - the sites' field name


class ProgressItem(ProgressIn):
    vodId: str = Field(pattern=VOD_ID_PATTERN)  # noqa: N815


class ProgressMerge(BaseModel):
    items: list[ProgressItem] = Field(max_length=MERGE_MAX)


class CodeIn(BaseModel):
    client_id: str = Field(max_length=200)


class TokenIn(BaseModel):
    code: str = Field(max_length=200)
    redirect_uri: str = Field(max_length=2000)


def _error(status: int, error: str, **extra: Any) -> JSONResponse:
    return JSONResponse({"error": error, **extra}, status_code=status)


class Refused(Exception):
    """Raised by a guard or a body parser; answered as `_error(status, error)`."""

    def __init__(self, status: int, error: str) -> None:
        super().__init__(error)
        self.status, self.error = status, error


def json_body[M: BaseModel](model: type[M], status: int, error: str) -> Callable[[Request], Awaitable[M]]:
    """A dependency giving the request's body as `model`, or refusing it with `status` and `error`.

    Not a plain body parameter: FastAPI validates those only after every dependency has run, and a bad
    body is refused before the session guard looks at the request (so it never counts against a limit).
    An endpoint declares it before its guard."""

    async def parse(request: Request) -> M:
        try:
            return model.model_validate_json(await request.body())
        except ValidationError:
            raise Refused(status, error) from None

    return parse


progress_body = json_body(ProgressIn, 422, "invalid_progress")
merge_body = json_body(ProgressMerge, 422, "invalid_progress")
token_body = json_body(TokenIn, 400, "invalid_request")
code_body = json_body(CodeIn, 400, "invalid_request")


async def progress_item(vod_id: str, body: Annotated[ProgressIn, Depends(progress_body)]) -> ProgressItem:
    try:
        return ProgressItem(vodId=vod_id, **body.model_dump())
    except ValidationError:
        raise Refused(422, "invalid_progress") from None


async def progress_limit(request: Request) -> int:
    try:
        return min(max(int(request.query_params.get("limit", PROGRESS_MAX)), 1), PROGRESS_MAX)
    except ValueError:
        raise Refused(400, "invalid_limit") from None


def _user_json(row: Any) -> dict[str, Any]:
    return {
        "id": row.id,
        "login": row.login,
        "displayName": row.display_name,
        "avatar": row.avatar,
        "color": row.color,
    }


def _progress_json(row: Any) -> dict[str, Any]:
    m = row._mapping  # not row.t: Row has a .t of its own
    return {"vodId": m["vod_id"], "t": m["t"], "duration": m["duration"], "updatedAt": m["updated_at"]}


def create_app(
    settings: Settings,
    *,
    twitch: TwitchHttp | None = None,
    engine: AsyncEngine | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> FastAPI:
    key = settings.token_key.get_secret_value()
    if not key:
        raise ValueError("AUTH_TOKEN_KEY is required (a Fernet key: see .env.example)")
    fernet = Fernet(key.encode())
    clients = settings.client_map  # parse now: a bad registration fails at start, not at first sign-in
    owns_engine, owns_twitch = engine is None, twitch is None
    db = engine or create_async_engine(settings.sqlalchemy_url, pool_pre_ping=True)
    tw: TwitchHttp = twitch or TwitchClient(settings.twitch_client_id, settings.twitch_client_secret.get_secret_value())
    secure = settings.cookie_secure
    # __Host- makes the browser insist on Secure, path=/ and no Domain: the cookie can't leak to or be
    # planted from a sibling host. Plain http in development can't have it.
    session_cookie = "__Host-vxa_session" if secure else "vxa_session"
    state_cookie = "vxa_state"
    session_ttl = timedelta(days=settings.session_days)
    login_limit = Limiter(20, 60)
    backend_limit = Limiter(120, 60)
    write_limit = Limiter(240, 60)
    last_cleanup: datetime | None = None

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        if owns_twitch and isinstance(tw, TwitchClient):
            await tw.aclose()
        if owns_engine:
            await db.dispose()

    app = FastAPI(title="vex-auth", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)

    @app.exception_handler(Refused)
    async def refused(_: Request, exc: Refused) -> Response:
        return _error(exc.status, exc.error)

    @app.exception_handler(RequestValidationError)
    async def invalid(_: Request, exc: RequestValidationError) -> Response:
        return _error(422, "invalid_request")  # this service's error shape, not FastAPI's list of errors

    app.add_middleware(
        CORSMiddleware,
        allow_origins=sorted(settings.origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Content-Type", CSRF_HEADER],
        max_age=600,
    )

    # ── helpers ────────────────────────────────────────────────────────────────

    def ip_of(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    async def record(
        conn: AsyncConnection,
        event: str,
        request: Request,
        *,
        user_id: str | None = None,
        client_id: str | None = None,
        **detail: Any,
    ) -> None:
        await conn.execute(
            insert(audit).values(
                at=clock(),
                event=event,
                user_id=user_id,
                client_id=client_id,
                ip=ip_of(request),
                detail=detail or None,
            )
        )
        log.info(event, user=user_id, client=client_id, **detail)

    async def current_session(conn: AsyncConnection, request: Request) -> Session | None:
        token = request.cookies.get(session_cookie)
        if not token:
            return None
        row = (
            await conn.execute(
                select(sessions.c.id, sessions.c.user_id, sessions.c.csrf, sessions.c.expires_at).where(
                    sessions.c.token_hash == _hash(token),
                    sessions.c.revoked_at.is_(None),
                    sessions.c.expires_at > clock(),
                )
            )
        ).first()
        return Session(row.id, row.user_id, row.csrf, row.expires_at) if row else None

    async def live_session_user(conn: AsyncConnection, sid: str, now: datetime) -> Row[Any] | None:
        """The user of session `sid` with its expiry, unless it was revoked or has expired."""
        return (
            await conn.execute(
                select(users, sessions.c.expires_at)
                .join(sessions, sessions.c.user_id == users.c.id)
                .where(sessions.c.id == sid, sessions.c.revoked_at.is_(None), sessions.c.expires_at > now)
            )
        ).first()

    def authenticate_client(request: Request) -> Client | None:
        header = request.headers.get("authorization", "")
        scheme, _, value = header.partition(" ")
        if scheme.lower() != "basic":
            return None
        try:
            client_id, _, secret = base64.b64decode(value, validate=True).decode().partition(":")
        except (binascii.Error, UnicodeDecodeError):
            return None
        client = clients.get(client_id)
        if client is None or not secrets.compare_digest(secret.encode(), client.secret.encode()):
            return None
        return client

    async def has_signed_into(conn: AsyncConnection, client: Client, *, sid: str = "", user_id: str = "") -> bool:
        """Whether the client was ever handed this session or user: a backend only asks about its own."""
        where = codes.c.session_id == sid if sid else codes.c.user_id == user_id
        found = await conn.scalar(
            select(exists().where(and_(codes.c.client_id == client.id, codes.c.used_at.is_not(None), where)))
        )
        return bool(found)

    async def start_twitch(
        conn: AsyncConnection,
        scopes: set[str],
        *,
        return_to: str | None = None,
        client: Client | None = None,
        client_redirect_uri: str | None = None,
        client_state: str | None = None,
    ) -> Response:
        nonlocal last_cleanup
        now = clock()
        if last_cleanup is None or now - last_cleanup >= CLEANUP_INTERVAL:
            # Only tidiness: /callback and /v1/token check expires_at themselves.
            last_cleanup = now
            await conn.execute(delete(login_states).where(login_states.c.expires_at <= now))
            await conn.execute(delete(codes).where(codes.c.expires_at <= now - timedelta(days=1)))
        state = secrets.token_urlsafe(24)
        await conn.execute(
            insert(login_states).values(
                state_hash=_hash(state),
                return_to=return_to,
                client_id=client.id if client else None,
                client_redirect_uri=client_redirect_uri,
                client_state=client_state,
                scopes=sorted(scopes),
                expires_at=now + STATE_TTL,
            )
        )
        query = urlencode(
            {
                "client_id": settings.twitch_client_id,
                "redirect_uri": settings.callback_url,
                "response_type": "code",
                "scope": " ".join(sorted(scopes)),
                "state": state,
            }
        )
        resp = RedirectResponse(f"{AUTHORIZE_URL}?{query}", status_code=302)
        resp.set_cookie(
            state_cookie,
            state,
            max_age=int(STATE_TTL.total_seconds()),
            path="/callback",
            httponly=True,
            secure=secure,
            samesite="lax",
        )
        return resp

    async def issue_code(conn: AsyncConnection, client: Client, redirect_uri: str, sess: Session) -> str:
        code = secrets.token_urlsafe(32)
        await conn.execute(
            insert(codes).values(
                code_hash=_hash(code),
                client_id=client.id,
                redirect_uri=redirect_uri,
                session_id=sess.id,
                user_id=sess.user_id,
                expires_at=clock() + CODE_TTL,
            )
        )
        return code

    async def token_scopes(conn: AsyncConnection, user_id: str) -> set[str]:
        found = await conn.scalar(select(twitch_tokens.c.scopes).where(twitch_tokens.c.user_id == user_id))
        return set(found or ())

    async def store_user(conn: AsyncConnection, profile: Profile, token: Token) -> None:
        now = clock()
        values = {
            "login": profile.login,
            "display_name": profile.display_name,
            "avatar": profile.avatar,
            "color": profile.color,
            "updated_at": now,
        }
        await conn.execute(
            pg_insert(users)
            .values(id=profile.id, created_at=now, **values)
            .on_conflict_do_update(index_elements=[users.c.id], set_=values)
        )
        # A plain sign-in asks Twitch for no scope. Its token must not replace one that carries more, or
        # signing in on root would take away what the bot's admin needs.
        if not token.scopes >= await token_scopes(conn, profile.id):
            return
        stored = {
            "access_enc": fernet.encrypt(token.access.encode()),
            "refresh_enc": fernet.encrypt(token.refresh.encode()) if token.refresh else None,
            "scopes": sorted(token.scopes),
            "updated_at": now,
        }
        await conn.execute(
            pg_insert(twitch_tokens)
            .values(user_id=profile.id, **stored)
            .on_conflict_do_update(index_elements=[twitch_tokens.c.user_id], set_=stored)
        )

    async def new_session(conn: AsyncConnection, user_id: str) -> tuple[Session, str]:
        token = secrets.token_urlsafe(32)
        now = clock()
        sess = Session(secrets.token_urlsafe(18), user_id, secrets.token_urlsafe(24), now + session_ttl)
        await conn.execute(
            insert(sessions).values(
                id=sess.id,
                token_hash=_hash(token),
                user_id=user_id,
                csrf=sess.csrf,
                created_at=now,
                expires_at=sess.expires_at,
            )
        )
        return sess, token

    def set_session_cookie(resp: Response, token: str, expires_at: datetime) -> None:
        resp.set_cookie(
            session_cookie,
            token,
            max_age=max(0, int((expires_at - clock()).total_seconds())),
            path="/",
            httponly=True,
            secure=secure,
            samesite="lax",
        )

    # ── dependencies ───────────────────────────────────────────────────────────
    # A connection closes (its transaction commits, or rolls back on an exception) when the endpoint
    # returns, before the response goes out. Guards raise Refused, answered by its handler.

    async def reading() -> AsyncIterator[AsyncConnection]:
        async with db.connect() as conn:
            yield conn

    async def writing() -> AsyncIterator[AsyncConnection]:
        async with db.begin() as conn:
            yield conn

    ReadConn = Annotated[AsyncConnection, Depends(reading, scope="function")]  # noqa: N806
    WriteConn = Annotated[AsyncConnection, Depends(writing, scope="function")]  # noqa: N806

    def check_csrf(request: Request, sess: Session) -> None:
        sent = request.headers.get(CSRF_HEADER, "")
        if not secrets.compare_digest(sent, sess.csrf):
            raise Refused(403, "csrf")

    async def require_session(request: Request, conn: ReadConn) -> Session:
        """The session of a browser request that only reads."""
        sess = await current_session(conn, request)
        if sess is None:
            raise Refused(401, "signed_out")
        return sess

    async def require_write_session(request: Request, conn: WriteConn) -> Session:
        """The session of a state-changing browser request: signed in, with its CSRF token, within the limit."""
        sess = await current_session(conn, request)
        if sess is None:
            raise Refused(401, "signed_out")
        check_csrf(request, sess)
        if not write_limit.allow(sess.user_id):
            raise Refused(429, "rate_limited")
        return sess

    async def signing_out(request: Request, conn: WriteConn) -> Session | None:
        """The session a sign-out ends, CSRF-checked. None (signed out already) is fine; never limited."""
        sess = await current_session(conn, request)
        if sess is not None:
            check_csrf(request, sess)
        return sess

    async def require_client(request: Request) -> Client:
        """The backend making this request: within the limit, with good credentials."""
        if not backend_limit.allow(ip_of(request)):
            raise Refused(429, "rate_limited")
        client = authenticate_client(request)
        if client is None:
            raise Refused(401, "invalid_client")
        return client

    async def code_client(request: Request, body: Annotated[CodeIn, Depends(code_body)]) -> Client:
        """The registered client a browser asks a code for (POST /v1/codes), within /authorize's limit.
        Declared before the session guard, like /authorize checks the client before the session."""
        client = clients.get(body.client_id)
        if client is None:
            raise Refused(400, "unknown_client")
        if not login_limit.allow(ip_of(request)):
            raise Refused(429, "rate_limited")
        return client

    ReadSession = Annotated[Session, Depends(require_session)]  # noqa: N806
    WriteSession = Annotated[Session, Depends(require_write_session)]  # noqa: N806
    Backend = Annotated[Client, Depends(require_client)]  # noqa: N806

    # ── routes ─────────────────────────────────────────────────────────────────

    @app.get("/healthz")
    async def healthz() -> Response:
        """Liveness: the process answers. No dependency checks, so a database outage doesn't get the
        container restarted for nothing."""
        return JSONResponse({"ok": True, "version": __version__})

    @app.get("/readyz")
    async def readyz() -> Response:
        """Readiness: the database answers too, within READY_TIMEOUT_S, so a probe gets its 503 promptly."""
        try:
            async with asyncio.timeout(READY_TIMEOUT_S), db.connect() as conn:
                await conn.execute(text("select 1"))
        except Exception as exc:  # noqa: BLE001 - any failure means not healthy
            return _error(503, "database", detail=type(exc).__name__)
        return JSONResponse({"ok": True, "version": __version__})

    @app.get("/login")
    async def login(request: Request) -> Response:
        return_to = request.query_params.get("return", "")
        if len(return_to) > 2000 or origin_of(return_to) not in settings.origins:
            return PlainTextResponse("That return address is not one of the vexoul.net sites.", status_code=400)
        if not login_limit.allow(ip_of(request)):
            return PlainTextResponse("Too many sign-in attempts. Wait a minute.", status_code=429)
        async with db.begin() as conn:
            return await start_twitch(conn, set(), return_to=return_to)

    @app.get("/authorize")
    async def authorize(request: Request) -> Response:
        q = request.query_params
        client = clients.get(q.get("client_id", ""))
        redirect_uri = q.get("redirect_uri", "")
        if client is None or redirect_uri not in client.redirect_uris:
            return PlainTextResponse("Unknown client or redirect address.", status_code=400)
        state = q.get("state", "")
        if not state or len(state) > 500:
            return RedirectResponse(with_query(redirect_uri, error="invalid_request"), status_code=302)
        requested = set(q.get("scope", "").split())
        if not requested <= client.scopes:
            return RedirectResponse(with_query(redirect_uri, error="invalid_scope", state=state), status_code=302)
        if not login_limit.allow(ip_of(request)):
            return PlainTextResponse("Too many sign-in attempts. Wait a minute.", status_code=429)
        async with db.begin() as conn:
            sess = await current_session(conn, request)
            held = await token_scopes(conn, sess.user_id) if sess else set()
            if sess and requested <= held:
                # Signed in already, with every scope this client needs: straight back, no Twitch.
                code = await issue_code(conn, client, redirect_uri, sess)
                await record(conn, "code.issued", request, user_id=sess.user_id, client_id=client.id)
                return RedirectResponse(with_query(redirect_uri, code=code, state=state), status_code=302)
            return await start_twitch(
                conn,
                requested | held,
                client=client,
                client_redirect_uri=redirect_uri,
                client_state=state,
            )

    @app.get("/callback")
    async def callback(request: Request) -> Response:
        q = request.query_params
        state = q.get("state", "")
        async with db.begin() as conn:
            row = (
                await conn.execute(
                    delete(login_states).where(login_states.c.state_hash == _hash(state)).returning(login_states)
                )
            ).first()
        if row is None:
            return PlainTextResponse(
                "This sign-in has expired or was already used. Start again from the site.", status_code=400
            )
        client = clients.get(row.client_id) if row.client_id else None

        def fail(reason: str, message: str) -> Response:
            log.info("signin.failed", reason=reason, message=message, client=row.client_id)
            if client and row.client_redirect_uri in client.redirect_uris:
                url = with_query(row.client_redirect_uri, error=reason, state=row.client_state or "")
            else:
                url = with_query(row.return_to or "", auth_error=reason)
            resp = RedirectResponse(url, status_code=302)
            resp.delete_cookie(state_cookie, path="/callback")
            return resp

        if row.client_id and client is None:
            return PlainTextResponse("That client is no longer registered.", status_code=400)
        if row.expires_at <= clock():
            return fail("expired", "sign-in state expired")
        browser_state = request.cookies.get(state_cookie, "")
        if not browser_state or not secrets.compare_digest(browser_state, state):
            return fail("expired", "this sign-in was started in another browser")
        if error := q.get("error"):
            return fail("denied" if error == "access_denied" else "twitch", f"Twitch returned {error}")
        if not (code := q.get("code")):
            return fail("twitch", "no authorization code")
        try:
            token = await tw.exchange_code(code, settings.callback_url)
            profile = await tw.profile(token.access)
        except TwitchError as exc:
            return fail("twitch", str(exc))

        async with db.begin() as conn:
            await store_user(conn, profile, token)
            if old := await current_session(conn, request):  # this browser's previous sign-in ends here
                await conn.execute(update(sessions).where(sessions.c.id == old.id).values(revoked_at=clock()))
            sess, cookie = await new_session(conn, profile.id)
            await record(conn, "signin", request, user_id=profile.id, client_id=row.client_id, login=profile.login)
            if client and row.client_redirect_uri:
                code_out = await issue_code(conn, client, row.client_redirect_uri, sess)
                url = with_query(row.client_redirect_uri, code=code_out, state=row.client_state or "")
            else:
                url = row.return_to or "/"
        resp = RedirectResponse(url, status_code=302)
        resp.delete_cookie(state_cookie, path="/callback")
        set_session_cookie(resp, cookie, sess.expires_at)
        return resp

    @app.get("/v1/me")
    async def me(request: Request, conn: ReadConn) -> Response:
        # require_session's lookup and the user in one query
        token = request.cookies.get(session_cookie)
        row = (
            (
                await conn.execute(
                    select(users, sessions.c.csrf, sessions.c.expires_at)
                    .join(sessions, sessions.c.user_id == users.c.id)
                    .where(
                        sessions.c.token_hash == _hash(token),
                        sessions.c.revoked_at.is_(None),
                        sessions.c.expires_at > clock(),
                    )
                )
            ).first()
            if token
            else None
        )
        if row is None:
            raise Refused(401, "signed_out")
        return JSONResponse({**_user_json(row), "csrf": row.csrf, "expiresAt": row.expires_at.isoformat()})

    @app.post("/v1/logout")
    async def logout(
        request: Request, sess: Annotated[Session | None, Depends(signing_out)], conn: WriteConn
    ) -> Response:
        everywhere = request.query_params.get("everywhere") in ("1", "true")
        if sess is not None:
            where = sessions.c.user_id == sess.user_id if everywhere else sessions.c.id == sess.id
            await conn.execute(
                update(sessions).where(where, sessions.c.revoked_at.is_(None)).values(revoked_at=clock())
            )
            event = "signout.everywhere" if everywhere else "signout"
            await record(conn, event, request, user_id=sess.user_id)
        resp = Response(status_code=204)
        resp.delete_cookie(session_cookie, path="/", secure=secure, httponly=True, samesite="lax")
        return resp

    @app.post("/v1/codes")
    async def mint_code(
        request: Request,
        client: Annotated[Client, Depends(code_client)],
        sess: WriteSession,
        conn: WriteConn,
    ) -> Response:
        """/authorize without the redirect: the signed-in browser gets a code to hand to the client's backend.

        The code is the one /authorize mints, carrying the client's first registered redirect URI, which
        the backend sends to /v1/token. Any script on a site origin can mint one, but that gives it nothing
        it couldn't do already by calling that site's own backend same-origin."""
        if not client.scopes <= await token_scopes(conn, sess.user_id):
            return _error(409, "scope_missing")  # needs Twitch: the browser goes through /authorize
        code = await issue_code(conn, client, client.default_redirect_uri, sess)
        await record(conn, "code.issued", request, user_id=sess.user_id, client_id=client.id, via="fetch")
        return JSONResponse({"code": code})

    # ── progress ───────────────────────────────────────────────────────────────

    async def upsert_progress(conn: AsyncConnection, user_id: str, items: list[ProgressItem]) -> dict[str, Row[Any]]:
        """Saves `items` and gives the rows it wrote, by vod id. An entry missing from the answer was older
        than the one already saved, or was trimmed straight away."""
        if not items:
            return {}
        # Newest wins, per entry: an older write (another tab, a merge of stale local data) never undoes
        # a newer one.
        stmt = pg_insert(progress).values(
            [
                {
                    "user_id": user_id,
                    "vod_id": i.vodId,
                    "t": i.t,
                    "duration": i.duration,
                    "updated_at": i.updatedAt,
                }
                for i in items
            ]
        )
        result: Result[Any] = await conn.execute(
            stmt.on_conflict_do_update(
                index_elements=[progress.c.user_id, progress.c.vod_id],
                set_={
                    "t": stmt.excluded.t,
                    "duration": stmt.excluded.duration,
                    "updated_at": stmt.excluded.updated_at,
                },
                where=stmt.excluded.updated_at >= progress.c.updated_at,
            ).returning(*progress.c, literal_column("xmax = 0").label("inserted"))  # Postgres: 0 for a new row
        )
        written = {r.vod_id: r for r in result}
        if not any(r.inserted for r in written.values()):
            return written  # only updates: the user has no more entries than before, so nothing to trim
        keep = (
            select(progress.c.vod_id)
            .where(progress.c.user_id == user_id)
            .order_by(progress.c.updated_at.desc())
            .limit(PROGRESS_MAX)
        )
        trimmed = await conn.scalars(
            delete(progress)
            .where(progress.c.user_id == user_id, progress.c.vod_id.not_in(keep.scalar_subquery()))
            .returning(progress.c.vod_id)
        )
        for vod_id in trimmed:
            written.pop(vod_id, None)
        return written

    async def progress_list(conn: AsyncConnection, user_id: str, limit: int) -> list[dict[str, Any]]:
        rows = await conn.execute(
            select(progress).where(progress.c.user_id == user_id).order_by(progress.c.updated_at.desc()).limit(limit)
        )
        return [_progress_json(r) for r in rows]

    async def progress_row(conn: AsyncConnection, user_id: str, vod_id: str) -> Row[Any] | None:
        return (
            await conn.execute(select(progress).where(progress.c.user_id == user_id, progress.c.vod_id == vod_id))
        ).first()

    # A limit or a body is declared before the session, so it is checked first.

    @app.get("/v1/progress")
    async def progress_index(
        limit: Annotated[int, Depends(progress_limit)], sess: ReadSession, conn: ReadConn
    ) -> Response:
        return JSONResponse({"items": await progress_list(conn, sess.user_id, limit)})

    @app.get("/v1/progress/{vod_id}")
    async def progress_get(vod_id: str, sess: ReadSession, conn: ReadConn) -> Response:
        row = await progress_row(conn, sess.user_id, vod_id)
        return JSONResponse(_progress_json(row)) if row else _error(404, "not_found")

    @app.put("/v1/progress/{vod_id}")
    async def progress_put(
        item: Annotated[ProgressItem, Depends(progress_item)], sess: WriteSession, conn: WriteConn
    ) -> Response:
        written = await upsert_progress(conn, sess.user_id, [item])
        row = written.get(item.vodId) or await progress_row(conn, sess.user_id, item.vodId)  # stale or trimmed
        return JSONResponse(_progress_json(row)) if row else Response(status_code=204)

    @app.post("/v1/progress/merge")
    async def progress_merge(
        body: Annotated[ProgressMerge, Depends(merge_body)], sess: WriteSession, conn: WriteConn
    ) -> Response:
        """Many entries at once, newest winning each: a browser's local progress on its first sign-in."""
        await upsert_progress(conn, sess.user_id, body.items)
        return JSONResponse({"items": await progress_list(conn, sess.user_id, PROGRESS_MAX)})

    @app.delete("/v1/progress/{vod_id}")
    async def progress_delete(vod_id: str, sess: WriteSession, conn: WriteConn) -> Response:
        await conn.execute(delete(progress).where(progress.c.user_id == sess.user_id, progress.c.vod_id == vod_id))
        return Response(status_code=204)

    # ── backends ───────────────────────────────────────────────────────────────

    @app.post("/v1/token")
    async def token(request: Request, client: Backend, body: Annotated[TokenIn, Depends(token_body)]) -> Response:
        async with db.begin() as conn:
            now = clock()
            row = (
                await conn.execute(
                    update(codes)
                    .where(codes.c.code_hash == _hash(body.code), codes.c.used_at.is_(None))
                    .values(used_at=now)
                    .returning(codes)
                )
            ).first()
            if (
                row is None
                or row.client_id != client.id
                or row.redirect_uri != body.redirect_uri
                or row.expires_at <= now
            ):
                return _error(400, "invalid_grant")
            found = await live_session_user(conn, row.session_id, now)
            if found is None:
                return _error(400, "invalid_grant")
            await record(conn, "code.redeemed", request, user_id=row.user_id, client_id=client.id)
        return JSONResponse(
            {"user": _user_json(found), "sid": row.session_id, "expiresAt": found.expires_at.isoformat()}
        )

    @app.get("/v1/sessions/{sid}")
    async def session_status(sid: str, client: Backend) -> Response:
        async with db.connect() as conn:
            if not await has_signed_into(conn, client, sid=sid):
                return JSONResponse({"active": False}, status_code=404)
            found = await live_session_user(conn, sid, clock())
        if found is None:
            return JSONResponse({"active": False}, status_code=404)
        return JSONResponse({"active": True, "user": _user_json(found), "expiresAt": found.expires_at.isoformat()})

    @app.get("/v1/users/{user_id}/moderated-channels")
    async def moderated_channels(user_id: str, request: Request, client: Backend) -> Response:
        if MODERATED_SCOPE not in client.scopes:
            return _error(403, "scope_not_allowed")
        async with db.connect() as conn:
            if not await has_signed_into(conn, client, user_id=user_id):
                return _error(404, "unknown_user")
            row = (await conn.execute(select(twitch_tokens).where(twitch_tokens.c.user_id == user_id))).first()
        if row is None or MODERATED_SCOPE not in row.scopes:
            return _error(409, "scope_missing")
        try:
            access = fernet.decrypt(row.access_enc).decode()
            refresh = fernet.decrypt(row.refresh_enc).decode() if row.refresh_enc else None
        except InvalidToken:
            log.error("token.undecryptable", user=user_id)  # AUTH_TOKEN_KEY changed: sign in again
            return await forget_token(user_id, request, client)
        try:
            try:
                channels = await tw.moderated_channels(access, user_id)
            except TokenRevoked:
                if not refresh:
                    raise
                fresh = await tw.refresh(refresh)  # an expired access token, most likely
                async with db.begin() as conn:
                    await conn.execute(
                        update(twitch_tokens)
                        .where(twitch_tokens.c.user_id == user_id)
                        .values(
                            access_enc=fernet.encrypt(fresh.access.encode()),
                            refresh_enc=fernet.encrypt((fresh.refresh or refresh).encode()),
                            updated_at=clock(),
                        )
                    )
                channels = await tw.moderated_channels(fresh.access, user_id)
        except TokenRevoked:
            return await forget_token(user_id, request, client)
        except TwitchError as exc:
            log.warning("twitch.moderated_failed", user=user_id, error=str(exc))
            return _error(502, "twitch")
        return JSONResponse({"channels": channels})

    async def forget_token(user_id: str, request: Request, client: Client) -> Response:
        """Twitch took the grant back. Drop the token, so the next /authorize goes through Twitch again
        instead of handing out a code that can't answer anything."""
        async with db.begin() as conn:
            await conn.execute(delete(twitch_tokens).where(twitch_tokens.c.user_id == user_id))
            await record(conn, "token.revoked", request, user_id=user_id, client_id=client.id)
        return _error(410, "revoked")

    return app


__all__ = ["CSRF_HEADER", "EXTRA_SCOPES", "Limiter", "create_app", "with_query"]
