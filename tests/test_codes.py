"""POST /v1/codes: a one-time code for a backend, minted by a credentialed fetch instead of a redirect."""

from __future__ import annotations

from typing import Any

from tests.conftest import ALICE, BOT_REDIRECT, SITE, VODS_REDIRECT, Harness, make_settings
from tests.test_guards import answer, error
from tests.test_signin import DTP, MODERATED, VODS, authorize, query
from vex_auth.app import CSRF_HEADER


async def signed_in(h: Harness) -> dict[str, str]:
    await h.sign_in()
    return {"Origin": SITE, CSRF_HEADER: str((await h.me()).json()["csrf"])}


async def mint(h: Harness, headers: dict[str, str], client_id: str = "vods-admin") -> str:
    resp = await h.http.post("/v1/codes", headers=headers, json={"client_id": client_id})
    assert resp.status_code == 200, resp.text
    assert set(resp.json()) == {"code"}
    return str(resp.json()["code"])


async def test_a_fetched_code_signs_the_backend_in_and_keeps_answering(h: Harness) -> None:
    hd = await signed_in(h)
    calls = len(h.twitch.calls)
    code = await mint(h, hd)
    assert len(h.twitch.calls) == calls  # no Twitch, no redirect
    resp = await h.http.post("/v1/token", headers=VODS, json={"code": code, "redirect_uri": VODS_REDIRECT})
    assert resp.status_code == 200
    body = resp.json()
    assert body["user"]["login"] == "alice"
    sid = body["sid"]
    # The redemption is recorded like /authorize's: the backend may now ask about this session.
    status = await h.http.get(f"/v1/sessions/{sid}", headers=VODS)
    assert status.status_code == 200 and status.json()["active"] is True
    assert status.json()["user"]["id"] == ALICE.id
    assert (await h.http.get(f"/v1/sessions/{sid}", headers=DTP)).status_code == 404  # still its own only
    # And sign out reaches it, as it reaches any backend.
    await h.http.post("/v1/logout", headers=hd)
    assert (await h.http.get(f"/v1/sessions/{sid}", headers=VODS)).json() == {"active": False}


async def test_the_code_carries_the_first_registered_redirect_uri(h: Harness) -> None:
    second = "http://vods.test/other/callback"
    clients = (
        '[{"id":"vods-admin","secret":"vods-secret","redirect_uris":["'
        + VODS_REDIRECT
        + '","'
        + second
        + '"],"scopes":[]}]'
    )
    assert make_settings(clients=clients).client_map["vods-admin"].default_redirect_uri == VODS_REDIRECT
    hd = await signed_in(h)
    code = await mint(h, hd)
    resp = await h.http.post("/v1/token", headers=VODS, json={"code": code, "redirect_uri": second})
    assert resp.json() == {"error": "invalid_grant"}  # a code matches one redirect_uri only, and is spent
    code = await mint(h, hd)
    assert (
        await h.http.post("/v1/token", headers=VODS, json={"code": code, "redirect_uri": VODS_REDIRECT})
    ).status_code == 200


async def test_signed_out_is_401(h: Harness) -> None:
    resp = await h.http.post("/v1/codes", headers={"Origin": SITE}, json={"client_id": "vods-admin"})
    assert answer(resp)[0::2] == error(401, "signed_out")[0::2]
    h.http.cookies.set("vxa_session", "made-up")
    resp = await h.http.post("/v1/codes", headers={"Origin": SITE, CSRF_HEADER: "x"}, json={"client_id": "vods-admin"})
    assert answer(resp)[0::2] == error(401, "signed_out")[0::2]
    h.http.cookies.clear()
    hd = await signed_in(h)
    h.clock.advance(days=31)
    resp = await h.http.post("/v1/codes", headers=hd, json={"client_id": "vods-admin"})
    assert answer(resp)[0::2] == error(401, "signed_out")[0::2]


async def test_csrf_is_required(h: Harness) -> None:
    hd = await signed_in(h)
    for headers in ({"Origin": SITE}, {"Origin": SITE, CSRF_HEADER: "wrong"}):
        resp = await h.http.post("/v1/codes", headers=headers, json={"client_id": "vods-admin"})
        assert answer(resp)[0::2] == error(403, "csrf")[0::2]
    await mint(h, hd)


async def test_a_missing_scope_is_409(h: Harness) -> None:
    hd = await signed_in(h)  # a plain sign-in: no moderated scope held
    resp = await h.http.post("/v1/codes", headers=hd, json={"client_id": "dtp"})
    assert answer(resp)[0::2] == error(409, "scope_missing")[0::2]
    # Through /authorize once, and the scope is held: fetch works from then on.
    params = await h.twitch_redirect(await authorize(h, "dtp", BOT_REDIRECT, MODERATED))
    query(await h.approve(params, ALICE))
    hd[CSRF_HEADER] = str((await h.me()).json()["csrf"])  # that sign-in started a new session
    code = await mint(h, hd, "dtp")
    resp = await h.http.post("/v1/token", headers=DTP, json={"code": code, "redirect_uri": BOT_REDIRECT})
    assert resp.status_code == 200


async def test_an_unknown_client_or_a_bad_body_is_400(h: Harness) -> None:
    hd = await signed_in(h)
    resp = await h.http.post("/v1/codes", headers=hd, json={"client_id": "nope"})
    assert answer(resp)[0::2] == error(400, "unknown_client")[0::2]
    bodies: list[dict[str, Any]] = [{"json": {}}, {"json": {"client_id": 5}}, {"content": b"not json"}]
    for bad in bodies:
        resp = await h.http.post("/v1/codes", headers=hd, **bad)
        assert answer(resp)[0::2] == error(400, "invalid_request")[0::2]
    # The client is checked before the session, as /authorize does.
    resp = await h.another_browser().http.post("/v1/codes", json={"client_id": "nope"})
    assert resp.json() == {"error": "unknown_client"}


async def test_only_the_sites_may_read_it(h: Harness) -> None:
    hd = await signed_in(h)
    preflight = await h.http.options(
        "/v1/codes",
        headers={
            "Origin": "https://evil.test",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": f"content-type,{CSRF_HEADER.lower()}",
        },
    )
    assert preflight.status_code == 400
    assert "access-control-allow-origin" not in preflight.headers
    resp = await h.http.post("/v1/codes", headers={**hd, "Origin": "https://evil.test"}, json={"client_id": "x"})
    assert "access-control-allow-origin" not in resp.headers

    preflight = await h.http.options(
        "/v1/codes",
        headers={
            "Origin": SITE,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": f"content-type,{CSRF_HEADER.lower()}",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == SITE
    assert preflight.headers["access-control-allow-credentials"] == "true"
    resp = await h.http.post("/v1/codes", headers=hd, json={"client_id": "vods-admin"})
    assert resp.headers["access-control-allow-origin"] == SITE


async def test_a_code_works_once(h: Harness) -> None:
    hd = await signed_in(h)
    body = {"code": await mint(h, hd), "redirect_uri": VODS_REDIRECT}
    assert (await h.http.post("/v1/token", headers=VODS, json=body)).status_code == 200
    assert (await h.http.post("/v1/token", headers=VODS, json=body)).json() == {"error": "invalid_grant"}


async def test_a_code_is_for_its_own_client(h: Harness) -> None:
    hd = await signed_in(h)
    body = {"code": await mint(h, hd), "redirect_uri": VODS_REDIRECT}
    assert (await h.http.post("/v1/token", headers=DTP, json=body)).json() == {"error": "invalid_grant"}


async def test_codes_expire(h: Harness) -> None:
    hd = await signed_in(h)
    body = {"code": await mint(h, hd), "redirect_uri": VODS_REDIRECT}
    h.clock.advance(seconds=61)
    assert (await h.http.post("/v1/token", headers=VODS, json=body)).json() == {"error": "invalid_grant"}


async def test_minting_shares_the_authorize_limit(h: Harness) -> None:
    hd = await signed_in(h)  # its /login was one hit
    for _ in range(19):
        await mint(h, hd)
    resp = await h.http.post("/v1/codes", headers=hd, json={"client_id": "vods-admin"})
    assert answer(resp)[0::2] == error(429, "rate_limited")[0::2]
    resp = await authorize(h, "vods-admin", VODS_REDIRECT)
    assert resp.status_code == 429  # one limit for both ways of getting a code


async def test_preflight_refuses_the_old_csrf_header(h: Harness) -> None:
    preflight = await h.http.options(
        "/v1/codes",
        headers={
            "Origin": SITE,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-vexoulz-csrf",
        },
    )
    assert preflight.status_code == 400
