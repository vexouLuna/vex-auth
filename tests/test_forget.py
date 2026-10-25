from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlsplit

from cryptography.fernet import Fernet
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.conftest import ALICE, BOB, BOT_REDIRECT, SITE, Harness
from vex_auth.app import CSRF_HEADER
from vex_auth.db import audit, codes, progress, sessions, twitch_tokens, users

ENTRY = {"t": 1, "duration": 9, "updatedAt": 1}


async def headers(h: Harness) -> dict[str, str]:
    return {CSRF_HEADER: (await h.me()).json()["csrf"]}


async def forget(h: Harness, confirm: str = "alice", **kw: Any) -> int:
    resp = await h.http.request("DELETE", "/v1/me", json={"confirm": confirm}, **kw)
    return resp.status_code


async def count(engine: AsyncEngine, table: Any, user_id: str = ALICE.id) -> int:
    async with engine.connect() as conn:
        return int(await conn.scalar(select(func.count()).select_from(table).where(table.c.user_id == user_id)) or 0)


async def test_forget_deletes_the_user_and_everything_theirs(h: Harness, engine: AsyncEngine) -> None:
    await h.sign_in()
    hd = await headers(h)
    await h.http.put("/v1/progress/v1", headers=hd, json=ENTRY)
    other = h.another_browser()
    await other.sign_in()
    await other.sign_in(BOB)  # Bob's data stays
    await other.http.put("/v1/progress/v1", headers=await headers(other), json=ENTRY)

    assert await forget(h, "Alice", headers=hd) == 204
    assert h.twitch.revoked[-2:] == ["access-2", "refresh-2"]  # the token of Alice's newest sign-in
    assert (await h.me()).status_code == 401
    async with engine.connect() as conn:
        assert await conn.scalar(select(func.count()).select_from(users).where(users.c.id == ALICE.id)) == 0
    for table in (twitch_tokens, sessions, codes, progress):
        assert await count(engine, table) == 0, table.name
    assert await count(engine, progress, BOB.id) == 1
    assert (await other.me()).json()["login"] == "bob"


async def test_forget_anonymises_the_audit_log(h: Harness, engine: AsyncEngine) -> None:
    await h.sign_in()
    await h.sign_in()
    await h.another_browser().sign_in(BOB)
    assert await forget(h, headers=await headers(h)) == 204
    async with engine.connect() as conn:
        rows = (await conn.execute(select(audit).order_by(audit.c.id))).all()
    alice = [r for r in rows if r.user_id != BOB.id]
    assert [r.event for r in alice] == ["signin", "signin", "forgotten"]
    assert len({r.user_id for r in alice}) == 1  # one code links the actor's rows
    assert alice[0].user_id.startswith("anon-")
    assert all(r.ip is None for r in alice)
    assert all("login" not in (r.detail or {}) for r in alice)
    assert alice[-1].detail == {"revoke": "ok"}
    bob = [r for r in rows if r.user_id == BOB.id]
    assert bob[0].ip is not None and bob[0].detail["login"] == "bob"


async def test_forget_still_deletes_when_revoke_fails(h: Harness, engine: AsyncEngine) -> None:
    await h.sign_in()
    h.twitch.revoke_fails = True
    assert await forget(h, headers=await headers(h)) == 204
    assert await count(engine, twitch_tokens) == 0
    async with engine.connect() as conn:
        assert await conn.scalar(select(audit.c.detail).where(audit.c.event == "forgotten")) == {"revoke": "failed"}


async def test_forget_still_deletes_an_undecryptable_token(h: Harness, engine: AsyncEngine) -> None:
    await h.sign_in()
    async with engine.begin() as conn:
        await conn.execute(update(twitch_tokens).values(access_enc=Fernet(Fernet.generate_key()).encrypt(b"x")))
    assert await forget(h, headers=await headers(h)) == 204
    assert "revoke" not in h.twitch.calls
    assert await count(engine, sessions) == 0
    async with engine.connect() as conn:
        assert await conn.scalar(select(audit.c.detail).where(audit.c.event == "forgotten")) == {
            "revoke": "undecryptable"
        }


async def test_forget_needs_csrf_and_the_login(h: Harness, engine: AsyncEngine) -> None:
    assert await forget(h, headers={CSRF_HEADER: "x"}) == 401
    await h.sign_in()
    assert await forget(h) == 403
    hd = await headers(h)
    assert await forget(h, "bob", headers=hd) == 400
    assert (await h.http.request("DELETE", "/v1/me", headers=hd, content=b"{}")).status_code == 400
    assert h.twitch.revoked == []
    assert (await h.me()).status_code == 200


async def test_forget_ends_backend_sessions(h: Harness) -> None:
    await h.sign_in()
    scoped = {"client_id": "dtp", "redirect_uri": BOT_REDIRECT, "state": "s", "scope": "user:read:moderated_channels"}
    loc = await h.http.get("/authorize", params=scoped)
    params = await h.twitch_redirect(loc)  # dtp needs a scope: through Twitch
    resp = await h.approve(params, ALICE)
    code = parse_qs(urlsplit(resp.headers["location"]).query)["code"][0]
    basic = ("dtp", "dtp-secret")
    sid = (await h.http.post("/v1/token", auth=basic, json={"code": code, "redirect_uri": BOT_REDIRECT})).json()["sid"]
    assert (await h.http.get(f"/v1/sessions/{sid}", auth=basic)).status_code == 200
    assert await forget(h, headers=await headers(h)) == 204
    assert (await h.http.get(f"/v1/sessions/{sid}", auth=basic)).json() == {"active": False}


async def test_clear_progress(h: Harness, engine: AsyncEngine) -> None:
    await h.sign_in()
    hd = await headers(h)
    for vod in ("v1", "v2"):
        await h.http.put(f"/v1/progress/{vod}", headers=hd, json=ENTRY)
    assert (await h.http.delete("/v1/progress")).status_code == 403
    assert (await h.http.delete("/v1/progress", headers=hd)).status_code == 204
    assert (await h.http.get("/v1/progress")).json() == {"items": []}


async def test_me_has_member_since(h: Harness) -> None:
    await h.sign_in()
    assert (await h.me()).json()["createdAt"] == h.clock.now.isoformat()


async def test_reconnect_forces_twitch_with_the_held_scopes(h: Harness) -> None:
    await h.sign_in()
    plain = await h.twitch_redirect(await h.http.get("/login", params={"return": SITE}))
    assert "force_verify" not in plain and plain["scope"] == ""
    scoped = {"client_id": "dtp", "redirect_uri": BOT_REDIRECT, "state": "s", "scope": "user:read:moderated_channels"}
    loc = await h.http.get("/authorize", params=scoped)
    await h.approve(await h.twitch_redirect(loc), ALICE)  # now holds the moderated scope
    params = await h.twitch_redirect(await h.http.get("/login", params={"return": SITE, "force": "1"}))
    assert params["force_verify"] == "true"
    assert params["scope"] == "user:read:moderated_channels"
    h.twitch.revoked.clear()
    await h.approve(params, ALICE)
    assert (await h.me()).status_code == 200
    assert h.twitch.revoked == ["access-2", "refresh-2"]  # the replaced token, not the new one


async def test_a_replaced_token_is_revoked_and_a_kept_one_is_not(h: Harness) -> None:
    await h.sign_in()
    assert h.twitch.revoked == []  # nothing stored before
    scoped = {"client_id": "dtp", "redirect_uri": BOT_REDIRECT, "state": "s", "scope": "user:read:moderated_channels"}
    await h.approve(await h.twitch_redirect(await h.http.get("/authorize", params=scoped)), ALICE)
    assert h.twitch.revoked == ["access-1", "refresh-1"]  # more scopes: replaces the plain one
    await h.sign_in()  # a plain sign-in keeps the scoped token, so nothing is revoked
    assert h.twitch.revoked == ["access-1", "refresh-1"]


async def test_a_failed_revoke_of_a_replaced_token_never_blocks_sign_in(h: Harness) -> None:
    await h.sign_in()
    h.twitch.revoke_fails = True
    resp = await h.sign_in()
    assert resp.status_code == 302 and resp.headers["location"] == SITE + "/watch/1"
    assert (await h.me()).status_code == 200


async def test_a_site_may_forget_and_clear_across_origins(h: Harness) -> None:
    for path in ("/v1/me", "/v1/progress"):
        for origin, ok in ((SITE, True), ("http://evil.test", False)):
            preflight = await h.http.options(
                path,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "DELETE",
                    "Access-Control-Request-Headers": f"content-type,{CSRF_HEADER.lower()}",
                },
            )
            assert (preflight.status_code == 200) is ok, (path, origin)
            if ok:
                assert preflight.headers["access-control-allow-origin"] == SITE
                assert preflight.headers["access-control-allow-credentials"] == "true"
