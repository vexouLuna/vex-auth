"""The few Twitch calls the service makes, behind a protocol so tests can stand in for Twitch."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import httpx

AUTHORIZE_URL = "https://id.twitch.tv/oauth2/authorize"
TOKEN_URL = "https://id.twitch.tv/oauth2/token"
VALIDATE_URL = "https://id.twitch.tv/oauth2/validate"
HELIX = "https://api.twitch.tv/helix"


class TwitchError(Exception):
    """Twitch failed or refused a call."""


class TokenRevoked(TwitchError):
    """Twitch no longer accepts the user's grant: they disconnected the app, or the refresh token is gone."""


@dataclass(frozen=True, slots=True)
class Token:
    access: str
    refresh: str | None
    scopes: frozenset[str]


@dataclass(frozen=True, slots=True)
class Profile:
    id: str
    login: str
    display_name: str
    avatar: str | None
    color: str | None


class TwitchHttp(Protocol):
    async def exchange_code(self, code: str, redirect_uri: str) -> Token: ...

    async def refresh(self, refresh_token: str) -> Token:
        """Raises TokenRevoked when Twitch refuses the refresh token."""
        ...

    async def profile(self, access_token: str) -> Profile:
        """The token's user: who they are, their avatar and chat colour. Raises TokenRevoked on a 401."""
        ...

    async def moderated_channels(self, access_token: str, user_id: str) -> list[str]:
        """Broadcaster ids of every channel the user moderates. Raises TokenRevoked on a 401."""
        ...


class TwitchClient:
    def __init__(self, client_id: str, client_secret: str, timeout: float = 10.0) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.http = httpx.AsyncClient(timeout=timeout)

    async def aclose(self) -> None:
        await self.http.aclose()

    async def _token(self, data: dict[str, str]) -> Token:
        data = {"client_id": self.client_id, "client_secret": self.client_secret, **data}
        try:
            resp = await self.http.post(TOKEN_URL, data=data)
        except httpx.HTTPError as exc:
            raise TwitchError(f"token request failed: {exc}") from exc
        if data["grant_type"] == "refresh_token" and resp.status_code in (400, 401):
            raise TokenRevoked(f"Twitch refused the refresh token ({resp.status_code})")
        if resp.status_code != 200:
            raise TwitchError(f"token request failed ({resp.status_code})")
        body: dict[str, Any] = resp.json()
        return Token(body["access_token"], body.get("refresh_token"), frozenset(body.get("scope") or ()))

    async def exchange_code(self, code: str, redirect_uri: str) -> Token:
        return await self._token({"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri})

    async def refresh(self, refresh_token: str) -> Token:
        return await self._token({"grant_type": "refresh_token", "refresh_token": refresh_token})

    async def _helix(self, access_token: str, path: str, params: dict[str, str]) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {access_token}", "Client-Id": self.client_id}
        try:
            resp = await self.http.get(f"{HELIX}{path}", headers=headers, params=params)
        except httpx.HTTPError as exc:
            raise TwitchError(f"{path} failed: {exc}") from exc
        if resp.status_code == 401:
            raise TokenRevoked("Twitch refused the user's token")
        if resp.status_code != 200:
            raise TwitchError(f"{path} failed ({resp.status_code})")
        body: dict[str, Any] = resp.json()
        return body

    async def profile(self, access_token: str) -> Profile:
        rows = (await self._helix(access_token, "/users", {})).get("data") or []
        if not rows:
            raise TwitchError("/users returned no user for the token")
        user = rows[0]
        colors = (await self._helix(access_token, "/chat/color", {"user_id": user["id"]})).get("data") or []
        return Profile(
            id=user["id"],
            login=user["login"],
            display_name=user.get("display_name") or user["login"],
            avatar=user.get("profile_image_url") or None,
            color=(colors[0].get("color") or None) if colors else None,
        )

    async def moderated_channels(self, access_token: str, user_id: str) -> list[str]:
        found: list[str] = []
        cursor: str | None = None
        while True:
            params = {"user_id": user_id, "first": "100", **({"after": cursor} if cursor else {})}
            body = await self._helix(access_token, "/moderation/channels", params)
            found += [row["broadcaster_id"] for row in body.get("data", [])]
            cursor = (body.get("pagination") or {}).get("cursor")
            if not cursor:
                return found
