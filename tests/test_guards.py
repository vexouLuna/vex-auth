"""The exact answers of every guarded route: status, headers and body, byte for byte.

These pin what the sites and backends see, including which refusal wins when a request is wrong in more
than one way (a bad body is refused before the session is looked at, so it never counts against the
write limit).
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any

import httpx
from sqlalchemy import event, insert
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.conftest import ALICE, Harness
from vex_auth.app import CSRF_HEADER, PROGRESS_MAX
from vex_auth.db import progress

ENTRY = {"t": 1, "duration": 9, "updatedAt": 1}
EXPIRES = "2026-10-29T12:00:00+00:00"  # the harness clock plus the default 30 days
BAD_BODIES: list[dict[str, Any]] = [
    {"content": b""},
    {"content": b"not json"},
    {"content": b"[]"},
    {"json": {"t": -1, "duration": 9, "updatedAt": 1}},
    {"json": {"t": 1, "updatedAt": 1}},
    {"json": {"t": "x"}},
    {"json": {"t": 1, "duration": 9, "updatedAt": -1}},
]
DELETE_COOKIE = 'vxa_session=""; HttpOnly; Max-Age=0; Path=/; SameSite=lax'


def js(obj: Any) -> bytes:
    """`obj` as JSONResponse renders it."""
    return json.dumps(obj, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()


def answer(resp: httpx.Response) -> tuple[int, list[tuple[str, str]], bytes]:
    """The response as compared here. A deleted cookie's `expires=` is the wall clock's, so it goes."""
    headers = [
        (k, re.sub(r"expires=[^;]*; ", "", v) if k == "set-cookie" else v) for k, v in resp.headers.multi_items()
    ]
    return resp.status_code, headers, resp.content


VARY = ("vary", "Origin")  # CORS adds it to every answer


def json_answer(status: int, body: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
    return status, [("content-length", str(len(body))), ("content-type", "application/json"), VARY], body


def error(status: int, code: str) -> tuple[int, list[tuple[str, str]], bytes]:
    return json_answer(status, js({"error": code}))


NO_CONTENT: tuple[int, list[tuple[str, str]], bytes] = (204, [VARY], b"")


def basic(client_id: str, secret: str) -> dict[str, str]:
    return {"Authorization": "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()}


async def signed_in(h: Harness) -> dict[str, str]:
    await h.sign_in()
    return {CSRF_HEADER: (await h.me()).json()["csrf"]}


# ── /v1/me ───────────────────────────────────────────────────────────────────


async def test_me(h: Harness) -> None:
    assert answer(await h.http.get("/v1/me")) == error(401, "signed_out")
    h.http.cookies.set("vxa_session", "made-up")
    assert answer(await h.http.get("/v1/me")) == error(401, "signed_out")
    h.http.cookies.clear()
    hd = await signed_in(h)
    body = {
        "id": "100",
        "login": "alice",
        "displayName": "Alice",
        "avatar": "https://img.test/alice.png",
        "color": "#FF0000",
        "csrf": hd[CSRF_HEADER],
        "expiresAt": EXPIRES,
    }
    assert answer(await h.http.get("/v1/me")) == json_answer(200, js(body))
    h.clock.advance(days=31)
    assert answer(await h.http.get("/v1/me")) == error(401, "signed_out")


async def test_me_is_one_query(h: Harness, engine: AsyncEngine) -> None:
    await signed_in(h)
    statements: list[str] = []

    def record(*args: Any) -> None:
        statements.append(args[2])

    event.listen(engine.sync_engine, "before_cursor_execute", record)
    try:
        assert (await h.http.get("/v1/me")).status_code == 200
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", record)
    assert len(statements) == 1


# ── /v1/logout ───────────────────────────────────────────────────────────────


def logged_out(resp: httpx.Response) -> None:
    assert answer(resp) == (204, [("set-cookie", DELETE_COOKIE), VARY], b"")


async def test_logout(h: Harness) -> None:
    logged_out(await h.http.post("/v1/logout"))
    logged_out(await h.http.post("/v1/logout", headers={CSRF_HEADER: "anything"}))
    hd = await signed_in(h)
    assert answer(await h.http.post("/v1/logout")) == error(403, "csrf")
    assert answer(await h.http.post("/v1/logout", headers={CSRF_HEADER: "wrong"})) == error(403, "csrf")
    assert answer(await h.http.post("/v1/logout?everywhere=1", headers={CSRF_HEADER: ""})) == error(403, "csrf")
    assert (await h.me()).status_code == 200  # none of those signed out
    logged_out(await h.http.post("/v1/logout", headers=hd))
    assert (await h.me()).status_code == 401
    hd = await signed_in(h)
    logged_out(await h.http.post("/v1/logout?everywhere=true", headers=hd))
    assert (await h.me()).status_code == 401


async def test_logout_keeps_the_cookie_of_a_dead_session_out(h: Harness) -> None:
    hd = await signed_in(h)
    cookie = h.http.cookies["vxa_session"]
    logged_out(await h.http.post("/v1/logout", headers=hd))
    h.http.cookies.set("vxa_session", cookie)
    logged_out(await h.http.post("/v1/logout", headers=hd))  # revoked: as if signed out


# ── reading progress ─────────────────────────────────────────────────────────


async def test_progress_index(h: Harness) -> None:
    assert answer(await h.http.get("/v1/progress")) == error(401, "signed_out")
    assert answer(await h.http.get("/v1/progress?limit=x")) == error(400, "invalid_limit")  # before the session
    hd = await signed_in(h)
    assert answer(await h.http.get("/v1/progress")) == json_answer(200, b'{"items":[]}')
    for bad in ("x", "", "1.5", "1e3"):
        assert answer(await h.http.get("/v1/progress", params={"limit": bad})) == error(400, "invalid_limit")
    await h.http.put("/v1/progress/v1", headers=hd, json={"t": 1.5, "duration": 9, "updatedAt": 10})
    await h.http.put("/v1/progress/v2", headers=hd, json={"t": 2, "duration": 9.25, "updatedAt": 20})
    v1 = {"vodId": "v1", "t": 1.5, "duration": 9.0, "updatedAt": 10}
    v2 = {"vodId": "v2", "t": 2.0, "duration": 9.25, "updatedAt": 20}
    assert answer(await h.http.get("/v1/progress")) == json_answer(200, js({"items": [v2, v1]}))
    for limit in ("1", "0", "-5", " 1 "):
        assert answer(await h.http.get("/v1/progress", params={"limit": limit})) == json_answer(
            200, js({"items": [v2]})
        )
    assert answer(await h.http.get("/v1/progress?limit=99999")) == json_answer(200, js({"items": [v2, v1]}))
    assert answer(await h.http.get("/v1/progress?limit=x&limit=1")) == json_answer(200, js({"items": [v2]}))


async def test_progress_get(h: Harness) -> None:
    assert answer(await h.http.get("/v1/progress/v1")) == error(401, "signed_out")
    hd = await signed_in(h)
    assert answer(await h.http.get("/v1/progress/v1")) == error(404, "not_found")
    assert answer(await h.http.get("/v1/progress/bad%20id")) == error(404, "not_found")
    await h.http.put("/v1/progress/v1", headers=hd, json=ENTRY)
    assert answer(await h.http.get("/v1/progress/v1")) == json_answer(
        200, b'{"vodId":"v1","t":1.0,"duration":9.0,"updatedAt":1}'
    )


# ── writing progress ─────────────────────────────────────────────────────────


async def test_progress_put(h: Harness) -> None:
    assert answer(await h.http.put("/v1/progress/v1", json=ENTRY)) == error(401, "signed_out")
    for bad in BAD_BODIES:  # the body is checked first, signed in or not
        assert answer(await h.http.put("/v1/progress/v1", **bad)) == error(422, "invalid_progress")
    assert answer(await h.http.put("/v1/progress/bad%20id", json=ENTRY)) == error(422, "invalid_progress")
    hd = await signed_in(h)
    assert answer(await h.http.put("/v1/progress/v1", json=ENTRY)) == error(403, "csrf")
    assert answer(await h.http.put("/v1/progress/v1", headers={CSRF_HEADER: "x"}, json=ENTRY)) == error(403, "csrf")
    for bad in BAD_BODIES:
        assert answer(await h.http.put("/v1/progress/v1", headers=hd, **bad)) == error(422, "invalid_progress")
        assert answer(await h.http.put("/v1/progress/v1", **bad)) == error(422, "invalid_progress")
    too_long = "v" * 101
    assert answer(await h.http.put(f"/v1/progress/{too_long}", headers=hd, json=ENTRY)) == error(
        422, "invalid_progress"
    )
    put = await h.http.put(
        "/v1/progress/a.b:c-d_e", headers=hd, json={"t": 3, "duration": 4.5, "updatedAt": 100, "extra": 1}
    )
    assert answer(put) == json_answer(200, b'{"vodId":"a.b:c-d_e","t":3.0,"duration":4.5,"updatedAt":100}')
    stale = await h.http.put("/v1/progress/a.b:c-d_e", headers=hd, json={"t": 1, "duration": 1, "updatedAt": 99})
    assert answer(stale) == json_answer(200, b'{"vodId":"a.b:c-d_e","t":3.0,"duration":4.5,"updatedAt":100}')
    same = await h.http.put("/v1/progress/a.b:c-d_e", headers=hd, json={"t": 7, "duration": 8, "updatedAt": 100})
    assert answer(same) == json_answer(200, b'{"vodId":"a.b:c-d_e","t":7.0,"duration":8.0,"updatedAt":100}')


async def test_progress_put_of_an_entry_trimmed_at_once(h: Harness, engine: AsyncEngine) -> None:
    hd = await signed_in(h)
    rows = [
        {"user_id": ALICE.id, "vod_id": f"v{i}", "t": 0, "duration": 1, "updated_at": 1000 + i}
        for i in range(PROGRESS_MAX)
    ]
    async with engine.begin() as conn:
        await conn.execute(insert(progress), rows)
    # Older than every one of the user's PROGRESS_MAX entries: saved, then trimmed straight away.
    assert answer(await h.http.put("/v1/progress/old", headers=hd, json=ENTRY)) == NO_CONTENT
    assert answer(await h.http.get("/v1/progress/old")) == error(404, "not_found")
    new = await h.http.put("/v1/progress/new", headers=hd, json={"t": 1, "duration": 9, "updatedAt": 9000})
    assert answer(new) == json_answer(200, b'{"vodId":"new","t":1.0,"duration":9.0,"updatedAt":9000}')
    assert answer(await h.http.get("/v1/progress/v0")) == error(404, "not_found")  # the oldest went
    assert len((await h.http.get("/v1/progress")).json()["items"]) == PROGRESS_MAX


async def test_progress_merge(h: Harness) -> None:
    assert answer(await h.http.post("/v1/progress/merge", json={"items": []})) == error(401, "signed_out")
    bad_merges: list[dict[str, Any]] = [
        {"content": b""},
        {"json": {}},
        {"json": {"items": [ENTRY]}},
        {"json": {"items": [{"vodId": "bad id", **ENTRY}]}},
        {"json": {"items": [{"vodId": f"v{i}", **ENTRY} for i in range(501)]}},
    ]
    for bad in bad_merges:
        assert answer(await h.http.post("/v1/progress/merge", **bad)) == error(422, "invalid_progress")
    hd = await signed_in(h)
    assert answer(await h.http.post("/v1/progress/merge", json={"items": []})) == error(403, "csrf")
    for bad in bad_merges:
        assert answer(await h.http.post("/v1/progress/merge", headers=hd, **bad)) == error(422, "invalid_progress")
    assert answer(await h.http.post("/v1/progress/merge", headers=hd, json={"items": []})) == json_answer(
        200, b'{"items":[]}'
    )
    await h.http.put("/v1/progress/v1", headers=hd, json={"t": 5, "duration": 9, "updatedAt": 50})
    items = [
        {"vodId": "v1", "t": 1, "duration": 9, "updatedAt": 10},
        {"vodId": "v2", "t": 2, "duration": 9, "updatedAt": 60},
    ]
    merged = await h.http.post("/v1/progress/merge", headers=hd, json={"items": items})
    expected = {
        "items": [
            {"vodId": "v2", "t": 2.0, "duration": 9.0, "updatedAt": 60},
            {"vodId": "v1", "t": 5.0, "duration": 9.0, "updatedAt": 50},
        ]
    }
    assert answer(merged) == json_answer(200, js(expected))


async def test_progress_delete(h: Harness) -> None:
    assert answer(await h.http.delete("/v1/progress/v1")) == error(401, "signed_out")
    hd = await signed_in(h)
    assert answer(await h.http.delete("/v1/progress/v1")) == error(403, "csrf")
    assert answer(await h.http.delete("/v1/progress/v1", headers={CSRF_HEADER: "x"})) == error(403, "csrf")
    assert answer(await h.http.delete("/v1/progress/v1", headers=hd)) == NO_CONTENT  # nothing there: fine
    await h.http.put("/v1/progress/v1", headers=hd, json=ENTRY)
    assert answer(await h.http.delete("/v1/progress/v1", headers=hd)) == NO_CONTENT
    assert answer(await h.http.get("/v1/progress/v1")) == error(404, "not_found")


async def test_writes_are_rate_limited_per_user(h: Harness) -> None:
    hd = await signed_in(h)
    for _ in range(240):
        assert (await h.http.delete("/v1/progress/v1", headers=hd)).status_code == 204
    limited = error(429, "rate_limited")
    assert answer(await h.http.delete("/v1/progress/v1", headers=hd)) == limited
    assert answer(await h.http.put("/v1/progress/v1", headers=hd, json=ENTRY)) == limited
    assert answer(await h.http.post("/v1/progress/merge", headers=hd, json={"items": []})) == limited
    # The checks before it still answer first, and reading is not limited.
    assert answer(await h.http.put("/v1/progress/v1", headers=hd, json={})) == error(422, "invalid_progress")
    assert answer(await h.http.delete("/v1/progress/v1")) == error(403, "csrf")
    assert (await h.http.get("/v1/progress")).status_code == 200
    logged_out(await h.http.post("/v1/logout", headers=hd))  # nor is signing out
    assert answer(await h.http.delete("/v1/progress/v1", headers=hd)) == error(401, "signed_out")


# ── backends ─────────────────────────────────────────────────────────────────


async def test_token_refusals(h: Harness) -> None:
    vods = basic("vods-admin", "vods-secret")
    good = {"code": "nope", "redirect_uri": "http://vods.test/admin/signin/callback"}
    bad_bodies: list[dict[str, Any]] = [
        {"content": b""},
        {"content": b"{"},
        {"json": {"code": "x"}},
        {"json": {"code": "x" * 201, "redirect_uri": "y"}},
        {"json": {"code": 1, "redirect_uri": "y"}},
    ]
    assert answer(await h.http.post("/v1/token", json=good)) == error(401, "invalid_client")
    for bad in bad_bodies:  # the client is checked before the body
        assert answer(await h.http.post("/v1/token", **bad)) == error(401, "invalid_client")
        assert answer(await h.http.post("/v1/token", headers=vods, **bad)) == error(400, "invalid_request")
    for header in ("Basic !!!", "Bearer x", basic("vods-admin", "wrong")["Authorization"], ""):
        resp = await h.http.post("/v1/token", headers={"Authorization": header}, json=good)
        assert answer(resp) == error(401, "invalid_client")
    assert answer(await h.http.post("/v1/token", headers=vods, json=good)) == error(400, "invalid_grant")


async def test_backend_routes_are_rate_limited_per_address(h: Harness) -> None:
    for _ in range(120 - 3):
        await h.http.get("/v1/sessions/x")
    assert answer(await h.http.get("/v1/sessions/x")) == error(401, "invalid_client")
    assert answer(await h.http.get("/v1/users/1/moderated-channels")) == error(401, "invalid_client")
    assert answer(await h.http.post("/v1/token", json={})) == error(401, "invalid_client")
    vods = basic("vods-admin", "vods-secret")
    limited = error(429, "rate_limited")
    assert answer(await h.http.get("/v1/sessions/x", headers=vods)) == limited
    assert answer(await h.http.get("/v1/users/1/moderated-channels", headers=vods)) == limited
    assert answer(await h.http.post("/v1/token", headers=vods, content=b"")) == limited


async def test_backend_reads(h: Harness) -> None:
    vods, dtp = basic("vods-admin", "vods-secret"), basic("dtp", "dtp-secret")
    assert answer(await h.http.get("/v1/sessions/x", headers=vods)) == json_answer(404, b'{"active":false}')
    assert answer(await h.http.get("/v1/users/1/moderated-channels", headers=vods)) == error(403, "scope_not_allowed")
    assert answer(await h.http.get("/v1/users/1/moderated-channels", headers=dtp)) == error(404, "unknown_user")
