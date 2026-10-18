from __future__ import annotations

from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.conftest import ALICE, BOB, Harness
from vex_auth.app import CSRF_HEADER, PROGRESS_MAX
from vex_auth.db import progress

ENTRY = {"t": 1, "duration": 9, "updatedAt": 1}


async def headers(h: Harness) -> dict[str, str]:
    return {CSRF_HEADER: (await h.me()).json()["csrf"]}


async def test_put_get_list_delete(h: Harness) -> None:
    await h.sign_in()
    hd = await headers(h)
    resp = await h.http.put("/v1/progress/v1", headers=hd, json={"t": 120.5, "duration": 3600, "updatedAt": 1000})
    assert resp.json() == {"vodId": "v1", "t": 120.5, "duration": 3600, "updatedAt": 1000}
    await h.http.put("/v1/progress/v2", headers=hd, json={"t": 5, "duration": 60, "updatedAt": 2000})
    assert (await h.http.get("/v1/progress/v1")).json()["t"] == 120.5
    items = (await h.http.get("/v1/progress")).json()["items"]
    assert [i["vodId"] for i in items] == ["v2", "v1"]  # newest first
    assert [i["vodId"] for i in (await h.http.get("/v1/progress?limit=1")).json()["items"]] == ["v2"]
    assert (await h.http.delete("/v1/progress/v1", headers=hd)).status_code == 204
    assert (await h.http.get("/v1/progress/v1")).status_code == 404


async def test_newest_wins(h: Harness) -> None:
    await h.sign_in()
    hd = await headers(h)
    await h.http.put("/v1/progress/v1", headers=hd, json={"t": 500, "duration": 900, "updatedAt": 2000})
    stale = await h.http.put("/v1/progress/v1", headers=hd, json={"t": 10, "duration": 900, "updatedAt": 1000})
    assert stale.json()["t"] == 500


async def test_merge_imports_local_progress(h: Harness) -> None:
    await h.sign_in()
    hd = await headers(h)
    await h.http.put("/v1/progress/v1", headers=hd, json={"t": 500, "duration": 900, "updatedAt": 2000})
    items = [
        {"vodId": "v1", "t": 1, "duration": 900, "updatedAt": 1000},  # older than the account's: loses
        {"vodId": "v2", "t": 2, "duration": 900, "updatedAt": 3000},
    ]
    resp = await h.http.post("/v1/progress/merge", headers=hd, json={"items": items})
    got = {i["vodId"]: i["t"] for i in resp.json()["items"]}
    assert got == {"v1": 500, "v2": 2}


async def test_progress_is_per_user(h: Harness) -> None:
    await h.sign_in()
    await h.http.put("/v1/progress/v1", headers=await headers(h), json=ENTRY)
    await h.sign_in(BOB)
    assert (await h.http.get("/v1/progress")).json() == {"items": []}
    assert (await h.http.get("/v1/progress/v1")).status_code == 404


async def test_writes_need_a_session_and_csrf(h: Harness) -> None:
    assert (await h.http.put("/v1/progress/v1", json=ENTRY)).status_code == 401
    assert (await h.http.get("/v1/progress")).status_code == 401
    await h.sign_in()
    assert (await h.http.put("/v1/progress/v1", json=ENTRY)).status_code == 403
    assert (await h.http.delete("/v1/progress/v1", headers={CSRF_HEADER: "wrong"})).status_code == 403
    assert (await h.http.post("/v1/progress/merge", json={"items": []})).status_code == 403


async def test_the_old_csrf_header_is_refused(h: Harness) -> None:
    # X-Vexoulz-CSRF, the name before the vexouLuna rename, counts as no header.
    await h.sign_in()
    token = (await h.me()).json()["csrf"]
    assert (await h.http.put("/v1/progress/v1", headers={"X-Vexoulz-CSRF": token}, json=ENTRY)).status_code == 403


async def test_bad_progress_is_refused(h: Harness) -> None:
    await h.sign_in()
    hd = await headers(h)
    for bad in ({"t": -1, "duration": 9, "updatedAt": 1}, {"t": 1, "updatedAt": 1}, {"t": "x"}):
        assert (await h.http.put("/v1/progress/v1", headers=hd, json=bad)).status_code == 422
    assert (await h.http.put("/v1/progress/bad%20id", headers=hd, json=ENTRY)).status_code == 422
    too_many = [{"vodId": f"v{i}", **ENTRY} for i in range(501)]
    assert (await h.http.post("/v1/progress/merge", headers=hd, json={"items": too_many})).status_code == 422


async def test_only_a_new_entry_trims(h: Harness, engine: AsyncEngine) -> None:
    await h.sign_in()
    hd = await headers(h)
    # One over the cap, put there behind the service's back, shows when it trims.
    rows = [
        {"user_id": ALICE.id, "vod_id": f"v{i}", "t": 0, "duration": 1, "updated_at": 1000 + i}
        for i in range(PROGRESS_MAX + 1)
    ]
    async with engine.begin() as conn:
        await conn.execute(insert(progress), rows)

    async def count() -> int:
        async with engine.connect() as conn:
            return int(await conn.scalar(select(func.count()).select_from(progress)) or 0)

    await h.http.put("/v1/progress/v5", headers=hd, json={"t": 1, "duration": 1, "updatedAt": 9000})  # an update
    await h.http.put("/v1/progress/v6", headers=hd, json={"t": 1, "duration": 1, "updatedAt": 1})  # a stale one
    await h.http.post("/v1/progress/merge", headers=hd, json={"items": [{"vodId": "v7", **ENTRY, "updatedAt": 9001}]})
    assert await count() == PROGRESS_MAX + 1
    await h.http.put("/v1/progress/new", headers=hd, json={"t": 1, "duration": 1, "updatedAt": 9002})  # an insert
    assert await count() == PROGRESS_MAX
    assert (await h.http.get("/v1/progress/v0")).status_code == 404  # the oldest went
    assert (await h.http.get("/v1/progress/v1")).status_code == 404
    assert (await h.http.get("/v1/progress/new")).status_code == 200
