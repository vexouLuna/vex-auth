"""/v2: the same routes as /v1 in the wire conventions (.conventions/API.md)."""

from __future__ import annotations

from tests.conftest import SITE, Harness
from vex_auth.app import CSRF_HEADER, CSRF_HEADER_V2

PROBLEM = "application/problem+json"


async def csrf(h: Harness) -> dict[str, str]:
    return {CSRF_HEADER_V2: (await h.http.get("/v2/me", headers={"Origin": SITE})).json()["csrf"]}


async def test_errors_are_problem_details(h: Harness) -> None:
    resp = await h.http.get("/v2/me", headers={"X-Request-ID": "req-1"})
    assert resp.status_code == 401
    assert resp.headers["content-type"] == PROBLEM
    assert resp.headers["x-request-id"] == "req-1"
    assert resp.json() == {
        "type": "about:blank",
        "title": "Unauthorized",
        "status": 401,
        "code": "signed_out",
        "request_id": "req-1",
    }
    assert (await h.http.get("/v1/me")).json() == {"error": "signed_out"}  # /v1 keeps its shape
    unknown = await h.http.get("/v2/nothing", headers={"X-Request-ID": "bad id!"})
    assert unknown.json()["code"] == "not_found"
    assert unknown.json()["request_id"] == unknown.headers["x-request-id"] != "bad id!"


async def test_writes_need_x_csrf_token(h: Harness) -> None:
    await h.sign_in()
    token = (await csrf(h))[CSRF_HEADER_V2]
    entry = {"position_seconds": 1, "duration_seconds": 9, "updated_at": "2026-10-29T12:00:00Z"}
    old_header = await h.http.put("/v2/progress/v1", headers={CSRF_HEADER: token}, json=entry)
    assert (old_header.status_code, old_header.json()["code"]) == (403, "csrf")
    ok = await h.http.put("/v2/progress/v1", headers={CSRF_HEADER_V2: token}, json=entry)
    assert ok.status_code == 200


async def test_invalid_body_lists_its_errors(h: Harness) -> None:
    await h.sign_in()
    body = {"position_seconds": -1, "duration_seconds": 9, "updated_at": "2026-10-29T12:00:00Z", "t": 1}
    resp = await h.http.put("/v2/progress/v1", headers=await csrf(h), json=body)
    assert resp.status_code == 422
    problem = resp.json()
    assert problem["code"] == "invalid"
    assert {(tuple(e["loc"]), e["type"]) for e in problem["errors"]} == {
        (("body", "position_seconds"), "greater_than_equal"),
        (("body", "t"), "extra_forbidden"),
    }
    naive = {**body, "position_seconds": 1, "updated_at": "2026-10-29T12:00:00"}
    del naive["t"]
    resp = await h.http.put("/v2/progress/v1", headers=await csrf(h), json=naive)
    assert resp.json()["errors"][0]["loc"] == ["body", "updated_at"]  # a timestamp needs its zone


async def test_me_is_snake_case_utc(h: Harness) -> None:
    await h.sign_in()
    me = (await h.http.get("/v2/me")).json()
    assert {"display_name", "created_at", "expires_at", "csrf"} <= me.keys()
    assert me["created_at"] == "2026-09-29T12:00:00Z"


async def test_progress_pages_by_cursor(h: Harness) -> None:
    await h.sign_in()
    hd = await csrf(h)
    for i, at in enumerate(["2026-10-29T12:00:00Z", "2026-10-29T13:00:00.250Z", "2026-10-29T13:00:00.250Z"]):
        body = {"position_seconds": i, "duration_seconds": 60, "updated_at": at}
        resp = await h.http.put(f"/v2/progress/v{i}", headers=hd, json=body)
    assert resp.json() == {
        "vod_id": "v2",
        "position_seconds": 2,
        "duration_seconds": 60,
        "updated_at": "2026-10-29T13:00:00.250Z",
    }
    first = (await h.http.get("/v2/progress?limit=2")).json()
    assert [i["vod_id"] for i in first["items"]] == ["v1", "v2"]  # newest first, then by id
    rest = (await h.http.get("/v2/progress", params={"limit": 2, "cursor": first["next_cursor"]})).json()
    assert rest == {"items": [{**rest["items"][0], "vod_id": "v0"}], "next_cursor": None}
    # /v1 sees the same entries, in its own shape
    assert (await h.http.get("/v1/progress/v1")).json()["updatedAt"] == 1793278800250

    bad = await h.http.get("/v2/progress?cursor=nope")
    assert (bad.status_code, bad.json()["code"]) == (400, "bad_cursor")
    over = await h.http.get("/v2/progress?limit=501")
    assert (over.status_code, over.json()["errors"][0]["loc"]) == (422, ["query", "limit"])

    merged = await h.http.post(
        "/v2/progress/merge",
        headers=hd,
        json={
            "items": [
                {"vod_id": "v0", "position_seconds": 9, "duration_seconds": 60, "updated_at": "2027-01-01T00:00:00Z"}
            ]
        },
    )
    assert merged.status_code == 204
    assert (await h.http.get("/v2/progress/v0")).json()["position_seconds"] == 9
    missing = await h.http.get("/v2/progress/none")
    assert (missing.status_code, missing.json()["code"]) == (404, "not_found")
