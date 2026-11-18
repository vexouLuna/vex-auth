"""/v2/presets: named sets of settings a user saves per kind."""

from __future__ import annotations

import os
import re
from typing import Any

import httpx
import psycopg
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.conftest import ADMIN, ALICE, BOB, SITE, Harness
from vex_auth.app import CSRF_HEADER_V2, PRESET_VALUE_MAX, PRESETS_MAX
from vex_auth.db import presets, upgrade

NOW = "2026-09-29T12:00:00Z"  # the harness's clock


async def csrf(h: Harness) -> dict[str, str]:
    return {CSRF_HEADER_V2: (await h.http.get("/v2/me", headers={"Origin": SITE})).json()["csrf"]}


def invalid(resp: httpx.Response) -> list[Any]:
    """The `loc` of the first error of a 422 `invalid`."""
    assert (resp.status_code, resp.json()["code"]) == (422, "invalid"), resp.text
    assert resp.headers["content-type"] == "application/problem+json"
    loc: list[Any] = resp.json()["errors"][0]["loc"]
    return loc


async def count(engine: AsyncEngine, user_id: str) -> int:
    async with engine.connect() as conn:
        query = select(func.count()).select_from(presets).where(presets.c.user_id == user_id)
        return int(await conn.scalar(query) or 0)


async def test_round_trip_replace_delete(h: Harness) -> None:
    await h.sign_in()
    hd = await csrf(h)
    assert (await h.http.get("/v2/presets/obs.chat")).json() == {"items": [], "next_cursor": None}
    value = {"font": "Inter", "size": 24, "nested": {"shadow": True, "tags": ["a", "ü"]}}
    put = await h.http.put("/v2/presets/obs.chat/Stream", headers=hd, json={"value": value})
    pid = put.json()["public_id"]
    assert (put.status_code, put.json()) == (
        200,
        {"name": "Stream", "value": value, "updated_at": NOW, "public_id": pid},
    )
    await h.http.put("/v2/presets/obs.chat/%20Big%20text%20", headers=hd, json={"value": {}})  # name is stripped
    await h.http.put("/v2/presets/obs.alerts/Stream", headers=hd, json={"value": {"other": "kind"}})

    h.clock.advance(hours=1)
    replaced = await h.http.put("/v2/presets/obs.chat/Stream", headers=hd, json={"value": {"size": 30}})
    assert replaced.json() == {
        "name": "Stream",
        "value": {"size": 30},
        "updated_at": "2026-09-29T13:00:00Z",
        "public_id": pid,  # a replace keeps the public id, so an OBS link keeps working
    }
    items = (await h.http.get("/v2/presets/obs.chat")).json()["items"]
    big = {"name": "Big text", "value": {}, "updated_at": NOW, "public_id": items[0]["public_id"]}
    assert items[0]["public_id"] != pid
    assert (await h.http.get("/v2/presets/obs.chat")).json() == {
        "items": [big, replaced.json()],  # sorted by name
        "next_cursor": None,
    }

    assert (await h.http.delete("/v2/presets/obs.chat/Stream", headers=hd)).status_code == 204
    assert (await h.http.delete("/v2/presets/obs.chat/Stream", headers=hd)).status_code == 204  # already gone
    assert [i["name"] for i in (await h.http.get("/v2/presets/obs.chat")).json()["items"]] == ["Big text"]
    assert len((await h.http.get("/v2/presets/obs.alerts")).json()["items"]) == 1  # the other kind is untouched


async def test_presets_belong_to_one_user(h: Harness) -> None:
    await h.sign_in()
    await h.http.put("/v2/presets/obs.chat/Mine", headers=await csrf(h), json={"value": {"who": "alice"}})
    bob = h.another_browser()
    await bob.sign_in(BOB)
    hd = await csrf(bob)
    assert (await bob.http.get("/v2/presets/obs.chat")).json()["items"] == []
    await bob.http.put("/v2/presets/obs.chat/Mine", headers=hd, json={"value": {"who": "bob"}})
    assert (await bob.http.delete("/v2/presets/obs.chat/Mine", headers=hd)).status_code == 204
    assert (await h.http.get("/v2/presets/obs.chat")).json()["items"][0]["value"] == {"who": "alice"}


async def test_signed_out_and_csrf(h: Harness) -> None:
    body: dict[str, Any] = {"value": {}}
    for resp in (
        await h.http.get("/v2/presets/obs.chat"),
        await h.http.put("/v2/presets/obs.chat/a", json=body),
        await h.http.delete("/v2/presets/obs.chat/a"),
    ):
        assert (resp.status_code, resp.json()["code"]) == (401, "signed_out")
    await h.sign_in()
    for resp in (
        await h.http.put("/v2/presets/obs.chat/a", json=body),
        await h.http.put("/v2/presets/obs.chat/a", headers={CSRF_HEADER_V2: "x"}, json=body),
        await h.http.delete("/v2/presets/obs.chat/a"),
    ):
        assert (resp.status_code, resp.json()["code"]) == (403, "csrf")
    assert (await h.http.get("/v2/presets/obs.chat")).json()["items"] == []


async def test_kind_and_name_limits(h: Harness) -> None:
    await h.sign_in()
    hd = await csrf(h)
    body: dict[str, Any] = {"value": {}}
    for kind in ("Obs", "a%20b", "k" * 65):
        assert invalid(await h.http.get(f"/v2/presets/{kind}")) == ["path", "kind"]
        assert invalid(await h.http.put(f"/v2/presets/{kind}/a", headers=hd, json=body)) == ["path", "kind"]
        assert invalid(await h.http.delete(f"/v2/presets/{kind}/a", headers=hd)) == ["path", "kind"]
    assert (await h.http.put(f"/v2/presets/{'k' * 64}/{'n' * 64}", headers=hd, json=body)).status_code == 200
    for name in ("%20%20", "n" * 65, "a%00b"):
        assert invalid(await h.http.put(f"/v2/presets/obs.chat/{name}", headers=hd, json=body)) == ["path", "name"]
        assert invalid(await h.http.delete(f"/v2/presets/obs.chat/{name}", headers=hd)) == ["path", "name"]


async def test_value_limits(h: Harness) -> None:
    await h.sign_in()
    hd = {**await csrf(h), "Content-Type": "application/json"}

    async def put(content: str) -> httpx.Response:
        return await h.http.put("/v2/presets/obs.chat/a", headers=hd, content=content.encode())

    for not_an_object in ("[1]", '"text"', "null", "3"):
        assert invalid(await put(f'{{"value": {not_an_object}}}')) == ["body", "value"]
    assert invalid(await put("{}")) == ["body", "value"]  # missing
    assert invalid(await put('{"value": {}, "extra": 1}')) == ["body", "extra"]
    assert invalid(await put('{"value": {"a": "\\u0000"}}')) == ["body", "value"]  # jsonb cannot hold it
    assert (await put('{"value": {"a": "\\\\u0000"}}')).status_code == 200  # a backslash and "u0000" can be

    fits = "x" * (PRESET_VALUE_MAX - len('{"a":""}'))  # measured compact, whatever the request's spacing
    assert (await put(f'{{"value":   {{"a" :  "{fits}"}}}}')).status_code == 200
    assert invalid(await put(f'{{"value":{{"a":"{fits}x"}}}}')) == ["body", "value"]
    assert invalid(await put(f'{{"value":{{"a":"{fits[:-1]}é"}}}}')) == ["body", "value"]  # bytes, not characters
    assert (await h.http.get("/v2/presets/obs.chat")).json()["items"][0]["value"] == {"a": fits}


async def test_at_most_fifty_per_kind(h: Harness, engine: AsyncEngine) -> None:
    await h.sign_in()
    hd = await csrf(h)
    rows = [
        {
            "user_id": ALICE.id,
            "kind": "obs.chat",
            "name": f"p{i:02}",
            "value": {},
            "updated_at": h.clock(),
            "public_id": f"public-id-{i:06}",
        }
        for i in range(PRESETS_MAX)
    ]
    async with engine.begin() as conn:
        await conn.execute(presets.insert(), rows)
    over = await h.http.put("/v2/presets/obs.chat/one-more", headers=hd, json={"value": {}})
    assert invalid(over) == ["path", "name"]
    replaced = await h.http.put("/v2/presets/obs.chat/p00", headers=hd, json={"value": {"new": 1}})  # at the cap
    assert (replaced.status_code, replaced.json()["value"]) == (200, {"new": 1})
    assert (await h.http.put("/v2/presets/obs.alerts/a", headers=hd, json={"value": {}})).status_code == 200
    assert (await h.http.delete("/v2/presets/obs.chat/p01", headers=hd)).status_code == 204
    assert (await h.http.put("/v2/presets/obs.chat/one-more", headers=hd, json={"value": {}})).status_code == 200
    assert len((await h.http.get("/v2/presets/obs.chat")).json()["items"]) == PRESETS_MAX


async def test_forget_me_removes_presets(h: Harness, engine: AsyncEngine) -> None:
    await h.sign_in()
    hd = await csrf(h)
    await h.http.put("/v2/presets/obs.chat/a", headers=hd, json={"value": {}})
    bob = h.another_browser()
    await bob.sign_in(BOB)
    await bob.http.put("/v2/presets/obs.chat/a", headers=await csrf(bob), json={"value": {}})
    assert (await count(engine, ALICE.id), await count(engine, BOB.id)) == (1, 1)
    forgot = await h.http.request("DELETE", "/v2/me", headers=hd, json={"confirm": "alice"})
    assert forgot.status_code == 204
    assert (await count(engine, ALICE.id), await count(engine, BOB.id)) == (0, 1)


async def test_insert_without_public_id_gets_one(h: Harness, engine: AsyncEngine) -> None:
    """The previous release inserts presets without a public_id while a deploy migrates: the default fills it."""
    await h.sign_in()
    row = {"user_id": ALICE.id, "kind": "obs.chat", "value": {}, "updated_at": h.clock()}
    async with engine.begin() as conn:
        await conn.execute(presets.insert(), [{**row, "name": "a"}, {**row, "name": "b"}])
        ids = (await conn.execute(select(presets.c.public_id).order_by(presets.c.name))).scalars().all()
    assert len(set(ids)) == 2
    assert all(re.fullmatch(r"[0-9a-f]{32}", i) for i in ids)
    got = await h.another_browser().http.get(f"/v2/public/presets/{ids[0]}")
    assert (got.status_code, got.json()["kind"]) == (200, "obs.chat")


async def test_public_read_by_id(h: Harness) -> None:
    await h.sign_in()
    hd = await csrf(h)
    put = await h.http.put("/v2/presets/obs.wheel/Main", headers=hd, json={"value": {"options": ["a", "b"]}})
    pid = put.json()["public_id"]
    anyone = h.another_browser()  # an OBS source: no cookie
    got = await anyone.http.get(f"/v2/public/presets/{pid}")
    assert (got.status_code, got.json()) == (
        200,
        {"kind": "obs.wheel", "value": {"options": ["a", "b"]}, "updated_at": NOW},
    )
    assert got.headers["cache-control"] == "no-cache"
    await h.http.put("/v2/presets/obs.wheel/Main", headers=hd, json={"value": {"options": ["c"]}})
    assert (await anyone.http.get(f"/v2/public/presets/{pid}")).json()["value"] == {"options": ["c"]}

    missing = await anyone.http.get("/v2/public/presets/" + "x" * 22)
    assert (missing.status_code, missing.json()["code"]) == (404, "not_found")
    assert invalid(await anyone.http.get("/v2/public/presets/short")) == ["path", "public_id"]
    await h.http.delete("/v2/presets/obs.wheel/Main", headers=hd)
    assert (await anyone.http.get(f"/v2/public/presets/{pid}")).status_code == 404


async def test_public_reads_are_rate_limited(h: Harness) -> None:
    anyone = h.another_browser()
    codes = [(await anyone.http.get("/v2/public/presets/" + "x" * 22)).status_code for _ in range(301)]
    assert codes[:300] == [404] * 300
    assert codes[300] == 429


def test_upgrade_gives_existing_presets_their_own_public_id() -> None:
    """Revision 0006 on a database that already holds presets: each gets a different id."""
    admin = os.environ.get("TEST_DATABASE_URL", ADMIN)
    name = "vex_auth_test_0006"
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        conn.execute(f"CREATE DATABASE {name}")
    url = admin.rsplit("/", 1)[0] + f"/{name}"
    try:
        upgrade(url.replace("postgresql://", "postgresql+psycopg://"), "0005")
        with psycopg.connect(url) as conn:
            conn.execute("INSERT INTO users VALUES ('1', 'a', 'A', NULL, NULL, now(), now())")
            conn.execute("INSERT INTO presets VALUES ('1', 'k', 'a', '{}', now()), ('1', 'k', 'b', '{}', now())")
        upgrade(url.replace("postgresql://", "postgresql+psycopg://"))
        with psycopg.connect(url) as conn:
            ids = [r[0] for r in conn.execute("SELECT public_id FROM presets")]
        assert len(set(ids)) == 2
        assert all(re.fullmatch(r"[0-9a-f]{32}", i) for i in ids)
    finally:
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
