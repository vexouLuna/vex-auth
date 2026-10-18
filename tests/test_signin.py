from __future__ import annotations

import base64
from urllib.parse import parse_qs, urlsplit

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from tests.conftest import ALICE, BOB, BOT_REDIRECT, SITE, VODS_REDIRECT, Clock, FakeTwitch, Harness, make_settings
from vex_auth.app import CSRF_HEADER, Limiter, create_app, with_query
from vex_auth.db import login_states

MODERATED = "user:read:moderated_channels"


def basic(client_id: str, secret: str) -> dict[str, str]:
    return {"Authorization": "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()}


DTP = basic("dtp", "dtp-secret")
VODS = basic("vods-admin", "vods-secret")


def query(resp: httpx.Response) -> dict[str, str]:
    assert resp.status_code == 302, resp.text
    return {k: v[0] for k, v in parse_qs(urlsplit(resp.headers["location"]).query).items()}


async def authorize(h: Harness, client: str, redirect: str, scope: str = "", state: str = "st-1") -> httpx.Response:
    params = {"client_id": client, "redirect_uri": redirect, "state": state, "scope": scope}
    return await h.http.get("/authorize", params=params)


async def code_for(h: Harness, client: str, redirect: str) -> dict[str, str]:
    q = query(await authorize(h, client, redirect))
    return {"code": q["code"], "redirect_uri": redirect}


async def csrf(h: Harness) -> str:
    return str((await h.me()).json()["csrf"])


# ── browser sign-in ──────────────────────────────────────────────────────────


async def test_sign_in_returns_to_the_page_and_me_knows_the_user(h: Harness) -> None:
    params = await h.twitch_redirect(await h.http.get("/login", params={"return": SITE + "/watch/1?t=5"}))
    assert params["scope"] == ""  # a plain sign-in asks Twitch for nothing extra
    assert params["redirect_uri"] == "http://auth.test/callback"
    resp = await h.approve(params, ALICE)
    assert resp.status_code == 302
    assert resp.headers["location"] == SITE + "/watch/1?t=5"
    me = await h.me()
    assert me.status_code == 200
    body = me.json()
    assert {k: body[k] for k in ("id", "login", "displayName", "avatar", "color")} == {
        "id": "100",
        "login": "alice",
        "displayName": "Alice",
        "avatar": "https://img.test/alice.png",
        "color": "#FF0000",
    }
    assert body["csrf"]
    assert me.headers["access-control-allow-origin"] == SITE
    assert me.headers["access-control-allow-credentials"] == "true"


async def test_me_is_not_readable_from_other_origins(h: Harness) -> None:
    await h.sign_in()
    resp = await h.http.get("/v1/me", headers={"Origin": "https://evil.test"})
    assert "access-control-allow-origin" not in resp.headers
    pre = await h.http.options(
        "/v1/me", headers={"Origin": "https://evil.test", "Access-Control-Request-Method": "GET"}
    )
    assert "access-control-allow-origin" not in pre.headers


async def test_signed_out_me_is_401(h: Harness) -> None:
    assert (await h.me()).status_code == 401


async def test_login_only_returns_to_the_sites(h: Harness) -> None:
    for bad in ("https://evil.test/", "/relative", "javascript:alert(1)", "http://site.test.evil.test/", ""):
        assert (await h.http.get("/login", params={"return": bad})).status_code == 400, bad
    assert (await h.http.get("/login", params={"return": "http://other-site.test/"})).status_code == 302


async def test_denied_on_twitch_goes_back_with_the_reason(h: Harness) -> None:
    params = await h.twitch_redirect(await h.http.get("/login", params={"return": SITE + "/x"}))
    resp = await h.http.get("/callback", params={"error": "access_denied", "state": params["state"]})
    assert resp.headers["location"] == SITE + "/x?auth_error=denied"
    assert (await h.me()).status_code == 401


async def test_a_callback_from_another_browser_is_refused(h: Harness) -> None:
    params = await h.twitch_redirect(await h.http.get("/login", params={"return": SITE + "/x"}))
    resp = await h.another_browser().approve(params, ALICE)  # without the state cookie
    assert resp.headers["location"] == SITE + "/x?auth_error=expired"
    assert "exchange" not in h.twitch.calls


async def test_a_state_works_once_and_expires(h: Harness) -> None:
    params = await h.twitch_redirect(await h.http.get("/login", params={"return": SITE + "/x"}))
    assert (await h.approve(params, ALICE)).status_code == 302
    assert (await h.approve(params, ALICE)).status_code == 400  # used

    params = await h.twitch_redirect(await h.http.get("/login", params={"return": SITE + "/x"}))
    h.clock.advance(minutes=11)
    assert (await h.approve(params, ALICE)).headers["location"] == SITE + "/x?auth_error=expired"


async def test_expired_states_are_cleaned_up_at_most_every_interval(h: Harness, engine: AsyncEngine) -> None:
    async def states() -> int:
        async with engine.connect() as conn:
            return int(await conn.scalar(select(func.count()).select_from(login_states)) or 0)

    await h.http.get("/login", params={"return": SITE})  # cleans up (nothing yet), then stores its state
    h.clock.advance(minutes=9)
    await h.http.get("/login", params={"return": SITE})
    h.clock.advance(minutes=2)  # the first state has expired, but the last cleanup was 11 minutes ago...
    assert await states() == 2
    await h.http.get("/login", params={"return": SITE})  # ...so this one cleans up
    assert await states() == 2  # the first went, this one came
    h.clock.advance(minutes=9)  # the second has expired too, within the interval: it stays
    await h.http.get("/login", params={"return": SITE})
    assert await states() == 3


async def test_sessions_expire(h: Harness) -> None:
    await h.sign_in()
    h.clock.advance(days=31)
    assert (await h.me()).status_code == 401


async def test_signing_in_again_ends_the_previous_session(h: Harness) -> None:
    await h.sign_in()
    sid = (await h.http.post("/v1/token", headers=VODS, json=await code_for(h, "vods-admin", VODS_REDIRECT))).json()[
        "sid"
    ]
    await h.sign_in(BOB)
    assert (await h.me()).json()["login"] == "bob"
    assert (await h.http.get(f"/v1/sessions/{sid}", headers=VODS)).status_code == 404


# ── sign out ─────────────────────────────────────────────────────────────────


async def test_sign_out_needs_the_csrf_token(h: Harness) -> None:
    await h.sign_in()
    assert (await h.http.post("/v1/logout")).status_code == 403
    assert (await h.me()).status_code == 200
    assert (await h.http.post("/v1/logout", headers={CSRF_HEADER: await csrf(h)})).status_code == 204
    assert (await h.me()).status_code == 401


async def test_sign_out_everywhere_reaches_other_browsers_and_the_backends(h: Harness) -> None:
    await h.sign_in()
    sid = (await h.http.post("/v1/token", headers=VODS, json=await code_for(h, "vods-admin", VODS_REDIRECT))).json()[
        "sid"
    ]
    phone = h.another_browser()
    await phone.sign_in()
    assert (await h.http.get(f"/v1/sessions/{sid}", headers=VODS)).json()["active"] is True

    resp = await phone.http.post("/v1/logout?everywhere=1", headers={CSRF_HEADER: await csrf(phone)})
    assert resp.status_code == 204
    resp = await h.http.get(f"/v1/sessions/{sid}", headers=VODS)
    assert resp.status_code == 404 and resp.json() == {"active": False}
    assert (await h.me()).status_code == 401
    assert (await phone.me()).status_code == 401


async def test_plain_sign_out_leaves_other_browsers(h: Harness) -> None:
    await h.sign_in()
    phone = h.another_browser()
    await phone.sign_in()
    await phone.http.post("/v1/logout", headers={CSRF_HEADER: await csrf(phone)})
    assert (await h.me()).status_code == 200


# ── backends ─────────────────────────────────────────────────────────────────


async def test_a_signed_in_user_gets_a_code_without_twitch(h: Harness) -> None:
    await h.sign_in()
    calls = len(h.twitch.calls)
    q = query(await authorize(h, "vods-admin", VODS_REDIRECT, state="abc"))
    assert q["state"] == "abc" and q["code"]
    assert len(h.twitch.calls) == calls
    resp = await h.http.post("/v1/token", headers=VODS, json={"code": q["code"], "redirect_uri": VODS_REDIRECT})
    assert resp.status_code == 200
    body = resp.json()
    assert body["user"]["login"] == "alice" and body["sid"] and body["expiresAt"]


async def test_a_client_asking_for_more_goes_through_twitch_once(h: Harness) -> None:
    await h.sign_in()
    params = await h.twitch_redirect(await authorize(h, "dtp", BOT_REDIRECT, MODERATED))
    assert params["scope"] == MODERATED
    q = query(await h.approve(params, ALICE))
    assert q["state"] == "st-1"
    resp = await h.http.post("/v1/token", headers=DTP, json={"code": q["code"], "redirect_uri": BOT_REDIRECT})
    assert resp.json()["user"]["id"] == "100"
    # From now on the scope is held: straight back with a code, even after a plain sign-in elsewhere.
    await h.sign_in()
    assert "code" in query(await authorize(h, "dtp", BOT_REDIRECT, MODERATED))


async def test_signed_out_authorize_signs_in_and_returns_to_the_client(h: Harness) -> None:
    params = await h.twitch_redirect(await authorize(h, "vods-admin", VODS_REDIRECT, state="s9"))
    resp = await h.approve(params, BOB)
    assert resp.headers["location"].startswith(VODS_REDIRECT + "?")
    assert query(resp)["state"] == "s9"
    assert (await h.me()).json()["login"] == "bob"  # and the sites know too


async def test_denied_goes_back_to_the_client_with_its_state(h: Harness) -> None:
    params = await h.twitch_redirect(await authorize(h, "dtp", BOT_REDIRECT, state="s1"))
    resp = await h.http.get("/callback", params={"error": "access_denied", "state": params["state"]})
    assert query(resp) == {"error": "denied", "state": "s1"}


async def test_authorize_checks_the_client(h: Harness) -> None:
    assert (await authorize(h, "nope", BOT_REDIRECT)).status_code == 400
    assert (await authorize(h, "dtp", "https://evil.test/cb")).status_code == 400
    assert (await authorize(h, "dtp", VODS_REDIRECT)).status_code == 400  # another client's address
    q = query(await authorize(h, "vods-admin", VODS_REDIRECT, MODERATED))
    assert q == {"error": "invalid_scope", "state": "st-1"}


async def test_a_code_works_once_for_its_own_client_only(h: Harness) -> None:
    await h.sign_in()
    body = await code_for(h, "vods-admin", VODS_REDIRECT)
    assert (await h.http.post("/v1/token", headers=DTP, json=body)).json() == {"error": "invalid_grant"}
    # A failed redemption still spends the code: it was presented, and must not be tried again.
    assert (await h.http.post("/v1/token", headers=VODS, json=body)).status_code == 400

    body = await code_for(h, "vods-admin", VODS_REDIRECT)
    assert (await h.http.post("/v1/token", headers=VODS, json=body)).status_code == 200
    assert (await h.http.post("/v1/token", headers=VODS, json=body)).status_code == 400


async def test_codes_expire(h: Harness) -> None:
    await h.sign_in()
    body = await code_for(h, "vods-admin", VODS_REDIRECT)
    h.clock.advance(seconds=61)
    assert (await h.http.post("/v1/token", headers=VODS, json=body)).status_code == 400


async def test_backends_must_authenticate(h: Harness) -> None:
    await h.sign_in()
    body = await code_for(h, "vods-admin", VODS_REDIRECT)
    assert (await h.http.post("/v1/token", json=body)).status_code == 401
    assert (await h.http.post("/v1/token", headers=basic("vods-admin", "wrong"), json=body)).status_code == 401
    assert (await h.http.get("/v1/sessions/x", headers=basic("dtp", "nope"))).status_code == 401


async def test_a_backend_only_sees_its_own_sessions(h: Harness) -> None:
    await h.sign_in()
    body = await code_for(h, "vods-admin", VODS_REDIRECT)
    sid = (await h.http.post("/v1/token", headers=VODS, json=body)).json()["sid"]
    assert (await h.http.get(f"/v1/sessions/{sid}", headers=VODS)).status_code == 200
    assert (await h.http.get(f"/v1/sessions/{sid}", headers=DTP)).status_code == 404


async def dtp_sign_in(h: Harness) -> str:
    params = await h.twitch_redirect(await authorize(h, "dtp", BOT_REDIRECT, MODERATED))
    q = query(await h.approve(params, ALICE))
    resp = await h.http.post("/v1/token", headers=DTP, json={"code": q["code"], "redirect_uri": BOT_REDIRECT})
    return str(resp.json()["user"]["id"])


async def test_moderated_channels(h: Harness) -> None:
    uid = await dtp_sign_in(h)
    h.twitch.moderated[uid] = ["1", "2"]
    resp = await h.http.get(f"/v1/users/{uid}/moderated-channels", headers=DTP)
    assert resp.json() == {"channels": ["1", "2"]}
    # vods-admin isn't registered for the scope, and nobody asks about users who never signed in to them.
    assert (await h.http.get(f"/v1/users/{uid}/moderated-channels", headers=VODS)).status_code == 403
    assert (await h.http.get("/v1/users/999/moderated-channels", headers=DTP)).status_code == 404


async def test_moderated_channels_refreshes_an_expired_token(h: Harness) -> None:
    uid = await dtp_sign_in(h)
    h.twitch.valid.clear()  # the access token expired
    resp = await h.http.get(f"/v1/users/{uid}/moderated-channels", headers=DTP)
    assert resp.status_code == 200 and "refresh" in h.twitch.calls
    h.twitch.calls.clear()
    assert (await h.http.get(f"/v1/users/{uid}/moderated-channels", headers=DTP)).status_code == 200
    assert "refresh" not in h.twitch.calls  # the refreshed token was kept


async def test_a_revoked_grant_is_forgotten_and_asked_for_again(h: Harness) -> None:
    uid = await dtp_sign_in(h)
    h.twitch.valid.clear()
    h.twitch.refreshable.clear()  # they disconnected the app on Twitch
    resp = await h.http.get(f"/v1/users/{uid}/moderated-channels", headers=DTP)
    assert resp.status_code == 410 and resp.json() == {"error": "revoked"}
    # The next sign-in to the bot goes through Twitch again rather than handing out a useless code.
    await h.twitch_redirect(await authorize(h, "dtp", BOT_REDIRECT, MODERATED))


async def test_a_plain_sign_in_keeps_the_scoped_token(h: Harness) -> None:
    uid = await dtp_sign_in(h)
    await h.sign_in()  # identity only: must not replace the token that can list moderated channels
    h.twitch.moderated[uid] = ["7"]
    assert (await h.http.get(f"/v1/users/{uid}/moderated-channels", headers=DTP)).json() == {"channels": ["7"]}


# ── small pieces ─────────────────────────────────────────────────────────────


def test_with_query() -> None:
    assert with_query("http://a.test/p?x=1&error=old", error="new") == "http://a.test/p?x=1&error=new"
    assert with_query("http://a.test/p", code="c", state="a b") == "http://a.test/p?code=c&state=a+b"


def test_limiter() -> None:
    now = [0.0]
    lim = Limiter(2, 60, clock=lambda: now[0])
    assert lim.allow("a") and lim.allow("a") and not lim.allow("a")
    assert lim.allow("b")
    now[0] = 61
    assert lim.allow("a")


async def test_healthz_and_readyz(h: Harness) -> None:
    for path in ("/healthz", "/readyz"):
        resp = await h.http.get(path)
        assert resp.status_code == 200 and resp.json()["ok"] is True and resp.json()["version"]


async def test_readyz_is_503_without_the_database() -> None:
    """/healthz still answers: liveness doesn't look at the database."""
    engine = create_async_engine("postgresql+psycopg://nobody:nothing@127.0.0.1:1/auth")
    app = create_app(make_settings(), twitch=FakeTwitch(), engine=engine, clock=Clock())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://auth.test") as http:
        assert (await http.get("/healthz")).status_code == 200
        resp = await http.get("/readyz")
    await engine.dispose()
    assert resp.status_code == 503
    assert "database" in resp.text
