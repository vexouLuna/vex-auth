"""/v2/presets: named sets of settings a user saves per kind."""

from __future__ import annotations

from typing import Any

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.conftest import ALICE, BOB, SITE, Harness
from vex_auth.app import CSRF_HEADER_V2, PRESET_VALUE_MAX, PRESETS_MAX
from vex_auth.db import presets

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
    assert (put.status_code, put.json()) == (200, {"name": "Stream", "value": value, "updated_at": NOW})
    await h.http.put("/v2/presets/obs.chat/%20Big%20text%20", headers=hd, json={"value": {}})  # name is stripped
    await h.http.put("/v2/presets/obs.alerts/Stream", headers=hd, json={"value": {"other": "kind"}})

    h.clock.advance(hours=1)
    replaced = await h.http.put("/v2/presets/obs.chat/Stream", headers=hd, json={"value": {"size": 30}})
    assert replaced.json() == {"name": "Stream", "value": {"size": 30}, "updated_at": "2026-09-29T13:00:00Z"}
    assert (await h.http.get("/v2/presets/obs.chat")).json() == {
        "items": [{"name": "Big text", "value": {}, "updated_at": NOW}, replaced.json()],  # sorted by name
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
        {"user_id": ALICE.id, "kind": "obs.chat", "name": f"p{i:02}", "value": {}, "updated_at": h.clock()}
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
