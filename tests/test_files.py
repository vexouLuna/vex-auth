"""/v2/files and /v2/public/files: overlay sounds and images, uploaded signed in and read by id."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.conftest import ALICE, BOB, SITE, Harness
from tests.test_presets import csrf, invalid
from vex_auth.app import FILE_MAX, FILES_MAX, FILES_TOTAL_MAX, sniff
from vex_auth.db import files

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
MP3 = b"ID3\x04\x00\x00" + b"\x00" * 32
NOW = "2026-09-29T12:00:00Z"


@pytest.mark.parametrize(
    ("data", "kind"),
    [
        (PNG, "image/png"),
        (b"\xff\xd8\xff\xe0" + b"\x00" * 8, "image/jpeg"),
        (b"GIF89a" + b"\x00" * 8, "image/gif"),
        (b"RIFF\x00\x00\x00\x00WEBPVP8 ", "image/webp"),
        (b"RIFF\x00\x00\x00\x00WAVEfmt ", "audio/wav"),
        (b"OggS\x00\x02", "audio/ogg"),
        (b"fLaC\x00\x00", "audio/flac"),
        (MP3, "audio/mpeg"),
        (b"\xff\xfb\x90\x00", "audio/mpeg"),  # a bare MPEG-1 layer III frame
        (b"\x00\x00\x00\x20ftypM4A \x00\x00", "audio/mp4"),
        (b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', None),
        (b"<!doctype html><script>alert(1)</script>", None),
        (b"\x00\x00\x00\x20ftypisom", None),  # an MP4 video
        (b"\xff\xe0", None),  # a frame sync with no layer
        (b"", None),
    ],
)
def test_sniff(data: bytes, kind: str | None) -> None:
    assert sniff(data) == kind


async def test_upload_list_read_delete(h: Harness) -> None:
    await h.sign_in()
    hd = await csrf(h)
    up = await h.http.post(
        "/v2/files", params={"name": " spin.mp3\n"}, headers={**hd, "Content-Type": "text/html"}, content=MP3
    )
    assert up.status_code == 201, up.text
    fid = up.json()["id"]
    item = {"id": fid, "name": "spin.mp3", "content_type": "audio/mpeg", "size_bytes": len(MP3), "created_at": NOW}
    assert up.json() == item  # the type comes from the bytes, not the header
    listed = (await h.http.get("/v2/files")).json()
    assert listed == {"items": [item], "next_cursor": None, "used_bytes": len(MP3), "max_bytes": FILES_TOTAL_MAX}

    anyone = h.another_browser()
    got = await anyone.http.get(f"/v2/public/files/{fid}")
    assert (got.status_code, got.content) == (200, MP3)
    assert got.headers["content-type"] == "audio/mpeg"
    assert got.headers["x-content-type-options"] == "nosniff"
    assert got.headers["content-disposition"] == "inline"
    assert got.headers["content-security-policy"] == "default-src 'none'; sandbox"
    assert got.headers["cross-origin-resource-policy"] == "cross-origin"

    assert (await h.http.delete(f"/v2/files/{fid}", headers=hd)).status_code == 204
    gone = await anyone.http.get(f"/v2/public/files/{fid}")
    assert (gone.status_code, gone.json()["code"]) == (404, "not_found")
    assert (await h.http.get("/v2/files")).json()["items"] == []


async def test_refuses_other_kinds_and_empty(h: Harness) -> None:
    await h.sign_in()
    hd = await csrf(h)
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"/>'
    assert invalid(await h.http.post("/v2/files", headers={**hd, "Content-Type": "image/svg+xml"}, content=svg)) == [
        "body"
    ]
    assert invalid(await h.http.post("/v2/files", headers=hd, content=b"")) == ["body"]
    assert (await h.http.get("/v2/files")).json()["items"] == []


async def test_size_caps(h: Harness, engine: AsyncEngine) -> None:
    await h.sign_in()
    hd = await csrf(h)
    big = await h.http.post("/v2/files", headers=hd, content=PNG + b"\x00" * (FILE_MAX - len(PNG) + 1))
    assert (big.status_code, big.json()["code"]) == (413, "too_large")
    assert (
        await h.http.post("/v2/files", headers=hd, content=PNG + b"\x00" * (FILE_MAX - len(PNG)))
    ).status_code == 201

    # The per-user total: fill it up to just under, straight in the table.
    async with engine.begin() as conn:
        await conn.execute(
            files.insert().values(
                id="f" * 22,
                user_id=ALICE.id,
                name="filler",
                content_type="image/png",
                size_bytes=FILES_TOTAL_MAX - FILE_MAX - 10,
                data=b"",
                created_at=h.clock(),
            )
        )
    over = await h.http.post("/v2/files", headers=hd, content=PNG)  # 40 bytes > the 10 left
    assert invalid(over) == ["body"]
    assert over.json()["errors"][0]["type"] == "too_big"


async def test_count_cap(h: Harness, engine: AsyncEngine) -> None:
    await h.sign_in()
    hd = await csrf(h)
    rows = [
        {
            "id": f"file-id-{i:08}",
            "user_id": ALICE.id,
            "name": "x",
            "content_type": "image/png",
            "size_bytes": 1,
            "data": b"x",
            "created_at": h.clock(),
        }
        for i in range(FILES_MAX)
    ]
    async with engine.begin() as conn:
        await conn.execute(files.insert(), rows)
    over = await h.http.post("/v2/files", headers=hd, content=PNG)
    assert over.json()["errors"][0]["type"] == "too_many"


async def test_files_belong_to_one_user(h: Harness) -> None:
    await h.sign_in()
    fid = (await h.http.post("/v2/files", headers=await csrf(h), content=PNG)).json()["id"]
    bob = h.another_browser()
    await bob.sign_in(BOB)
    assert (await bob.http.get("/v2/files")).json()["items"] == []  # never another user's list
    assert (await bob.http.delete(f"/v2/files/{fid}", headers=await csrf(bob))).status_code == 204
    assert [i["id"] for i in (await h.http.get("/v2/files")).json()["items"]] == [fid]


async def test_signed_out_and_csrf(h: Harness) -> None:
    for resp in (
        await h.http.get("/v2/files"),
        await h.http.post("/v2/files", content=PNG),
        await h.http.delete("/v2/files/x"),
    ):
        assert (resp.status_code, resp.json()["code"]) == (401, "signed_out")
    await h.sign_in()
    for resp in (
        await h.http.post("/v2/files", content=PNG),
        await h.http.delete("/v2/files/x", headers={"Origin": SITE}),
    ):
        assert (resp.status_code, resp.json()["code"]) == (403, "csrf")


async def test_upload_rate_limit(h: Harness) -> None:
    await h.sign_in()
    hd = await csrf(h)
    codes = [(await h.http.post("/v2/files", headers=hd, content=PNG)).status_code for _ in range(31)]
    assert codes == [201] * 30 + [429]


async def test_forget_me_removes_files(h: Harness, engine: AsyncEngine) -> None:
    await h.sign_in()
    hd = await csrf(h)
    await h.http.post("/v2/files", headers=hd, content=PNG)
    forgot = await h.http.request("DELETE", "/v2/me", headers=hd, json={"confirm": "alice"})
    assert forgot.status_code == 204
    async with engine.connect() as conn:
        assert await conn.scalar(select(func.count()).select_from(files)) == 0
