from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import psycopg
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from vex_auth.app import create_app
from vex_auth.config import Settings
from vex_auth.db import downgrade, metadata, upgrade
from vex_auth.twitch import Profile, Token, TokenRevoked, TwitchError

ADMIN = "postgresql://postgres:postgres@127.0.0.1:55432/postgres"
DB_NAME = "vex_auth_test"
SITE = "http://site.test"
BOT_REDIRECT = "http://bot.test/auth/admin/callback"
VODS_REDIRECT = "http://vods.test/admin/signin/callback"
CLIENTS = (
    '[{"id":"dtp","secret":"dtp-secret","redirect_uris":["' + BOT_REDIRECT + '"],'
    '"scopes":["user:read:moderated_channels"]},'
    '{"id":"vods-admin","secret":"vods-secret","redirect_uris":["' + VODS_REDIRECT + '"],"scopes":[]}]'
)


if sys.platform == "win32":

    def pytest_asyncio_loop_factories(config: pytest.Config, item: pytest.Item) -> dict[str, object]:
        # psycopg's async driver can't use Windows' proactor loop.
        return {"selector": asyncio.SelectorEventLoop}


@pytest.fixture(scope="session")
def db_url() -> Iterator[str]:
    admin = os.environ.get("TEST_DATABASE_URL", ADMIN)
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB_NAME} WITH (FORCE)")
        conn.execute(f"CREATE DATABASE {DB_NAME}")
    url = admin.rsplit("/", 1)[0].replace("postgresql://", "postgresql+psycopg://") + f"/{DB_NAME}"
    # Every revision must go both ways: up, all the way down, and up again.
    upgrade(url)
    downgrade(url, "base")
    upgrade(url)
    yield url
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB_NAME} WITH (FORCE)")


@pytest.fixture(scope="session")
async def engine(db_url: str) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(db_url)
    yield eng
    await eng.dispose()


@pytest.fixture
async def clean(engine: AsyncEngine) -> None:
    names = ", ".join(t.name for t in metadata.sorted_tables)
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))


@dataclass
class FakeTwitch:
    """Twitch as the service sees it. `authorize(profile, scopes)` stands in for the person approving."""

    codes: dict[str, tuple[Token, Profile]] = field(default_factory=dict)
    moderated: dict[str, list[str]] = field(default_factory=dict)
    valid: set[str] = field(default_factory=set)  # access tokens Twitch still accepts
    refreshable: dict[str, str] = field(default_factory=dict)  # refresh token -> the user id
    profiles: dict[str, Profile] = field(default_factory=dict)  # access token -> its user
    calls: list[str] = field(default_factory=list)
    n: int = 0

    def authorize(self, profile: Profile, scopes: set[str]) -> str:
        self.n += 1
        access, refresh = f"access-{self.n}", f"refresh-{self.n}"
        self.valid.add(access)
        self.refreshable[refresh] = profile.id
        code = f"twitch-code-{self.n}"
        self.codes[code] = (Token(access, refresh, frozenset(scopes)), profile)
        self.profiles[access] = profile
        return code

    async def exchange_code(self, code: str, redirect_uri: str) -> Token:
        self.calls.append("exchange")
        assert redirect_uri == "http://auth.test/callback"
        if code not in self.codes:
            raise TwitchError("bad code")
        return self.codes.pop(code)[0]

    async def refresh(self, refresh_token: str) -> Token:
        self.calls.append("refresh")
        if refresh_token not in self.refreshable:
            raise TokenRevoked("gone")
        self.n += 1
        access = f"access-{self.n}"
        self.valid.add(access)
        return Token(access, refresh_token, frozenset())

    async def profile(self, access_token: str) -> Profile:
        self.calls.append("profile")
        if access_token not in self.profiles:
            raise TokenRevoked("unknown token")
        return self.profiles[access_token]

    async def moderated_channels(self, access_token: str, user_id: str) -> list[str]:
        self.calls.append("moderated")
        if access_token not in self.valid:
            raise TokenRevoked("expired")
        return self.moderated.get(user_id, [])


ALICE = Profile("100", "alice", "Alice", "https://img.test/alice.png", "#FF0000")
BOB = Profile("200", "bob", "Bob", None, None)


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 9, 29, 12, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw: float) -> None:
        self.now += timedelta(**kw)


@dataclass
class Harness:
    http: httpx.AsyncClient
    twitch: FakeTwitch
    clock: Clock
    transport: httpx.AsyncBaseTransport
    others: list[httpx.AsyncClient] = field(default_factory=list)

    def another_browser(self) -> Harness:
        """The same service and Twitch, seen from a browser with no cookies."""
        http = httpx.AsyncClient(transport=self.transport, base_url="http://auth.test")
        self.others.append(http)
        return Harness(http, self.twitch, self.clock, self.transport, self.others)

    async def twitch_redirect(self, resp: httpx.Response) -> dict[str, str]:
        assert resp.status_code == 302, resp.text
        loc = urlsplit(resp.headers["location"])
        assert f"{loc.scheme}://{loc.netloc}{loc.path}" == "https://id.twitch.tv/oauth2/authorize"
        return {k: v[0] for k, v in parse_qs(loc.query, keep_blank_values=True).items()}

    async def approve(self, params: dict[str, str], profile: Profile) -> httpx.Response:
        """The person approves on Twitch, which sends the browser back to /callback."""
        code = self.twitch.authorize(profile, set(params["scope"].split()))
        return await self.http.get("/callback", params={"code": code, "state": params["state"]})

    async def sign_in(self, profile: Profile = ALICE, return_to: str = SITE + "/watch/1") -> httpx.Response:
        params = await self.twitch_redirect(await self.http.get("/login", params={"return": return_to}))
        return await self.approve(params, profile)

    async def me(self) -> httpx.Response:
        return await self.http.get("/v1/me", headers={"Origin": SITE})


def make_settings(**kw: Any) -> Settings:
    base: dict[str, Any] = {
        "public_url": "http://auth.test",
        "twitch_client_id": "twitch-app",
        "token_key": Fernet.generate_key().decode(),
        "site_origins": f"{SITE}, http://other-site.test",
        "clients": CLIENTS,
        "cookie_secure": False,
    }
    base.update(kw)
    return Settings(_env_file=None, **base)  # type: ignore[call-arg]


@pytest.fixture
async def h(engine: AsyncEngine, clean: None) -> AsyncIterator[Harness]:
    twitch, clock = FakeTwitch(), Clock()
    app = create_app(make_settings(), twitch=twitch, engine=engine, clock=clock)
    transport = httpx.ASGITransport(app=app, client=("198.51.100.7", 1234))
    async with httpx.AsyncClient(transport=transport, base_url="http://auth.test") as http:
        harness = Harness(http, twitch, clock, transport)
        yield harness
        for other in harness.others:
            await other.aclose()
