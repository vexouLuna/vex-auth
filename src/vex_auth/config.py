"""Settings, from the environment (`AUTH_*`) or from secrets files.

`.env.example` lists the settings and `secrets.example/` the secrets, with placeholder values. A secret is a
file named like its variable, lowercased (`auth_token_key`), in `/run/secrets` (where compose mounts them) or
`AUTH_SECRETS_DIR`. A variable set in the environment wins over the file.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

# Scopes a client may ask Twitch for on top of plain identity. Anything else is refused: the service
# holds these tokens, so it only ever asks for what one of its answers needs.
EXTRA_SCOPES = frozenset({"user:read:moderated_channels"})


@dataclass(frozen=True, slots=True)
class Client:
    """A backend that signs people in through this service (the bot's web admin, the archive admin)."""

    id: str
    secret: str
    redirect_uris: frozenset[str]
    scopes: frozenset[str]
    # The first registered redirect URI. A code minted by `POST /v1/codes` carries it, since no redirect
    # names one, and the backend sends it to `/v1/token` like any other.
    default_redirect_uri: str


def origin_of(url: str) -> str | None:
    """`scheme://host[:port]` of an absolute http(s) URL, lowercased; None for anything else."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"{parts.scheme}://{host}" + (f":{port}" if port else "")


SECRETS_DIR = Path(os.environ.get("AUTH_SECRETS_DIR", "/run/secrets"))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AUTH_",
        env_file=".env",
        extra="ignore",
        secrets_dir=SECRETS_DIR if SECRETS_DIR.is_dir() else None,
    )

    database_url: str = "postgresql://postgres:dev@127.0.0.1:55434/vex_auth"
    # Where this service is reached from browsers. Twitch sends people back to `<public_url>/callback`,
    # which must be registered on the Twitch application exactly.
    public_url: str = "http://localhost:8090"
    twitch_client_id: str = ""
    twitch_client_secret: SecretStr = SecretStr("")
    # Fernet key (32 url-safe base64 bytes) encrypting the stored Twitch tokens. Required.
    token_key: SecretStr = SecretStr("")
    # Comma-separated origins of the sites: the only pages that may read /v1/* with the session cookie,
    # and the only places /login sends people back to.
    site_origins: str = "http://localhost:5173"
    # The backends, as a JSON list of {id, secret, redirect_uris, scopes}. Either inline or in a file
    # (a mounted secret); the file wins when both are set.
    clients: SecretStr = SecretStr("[]")
    clients_file: Path | None = None
    session_days: int = 30
    # Off only for local development over plain http.
    cookie_secure: bool = True
    host: str = "0.0.0.0"
    port: int = 8090
    # Reverse proxies whose X-Forwarded-For/-Proto are believed (uvicorn's forwarded_allow_ips).
    forwarded_allow_ips: str = "127.0.0.1"

    @cached_property
    def origins(self) -> frozenset[str]:
        found = {origin_of(o.strip()) for o in self.site_origins.split(",") if o.strip()}
        return frozenset(o for o in found if o)

    @cached_property
    def client_map(self) -> dict[str, Client]:
        raw = self.clients_file.read_text(encoding="utf-8") if self.clients_file else self.clients.get_secret_value()
        out: dict[str, Client] = {}
        for entry in json.loads(raw or "[]"):
            scopes = frozenset(entry.get("scopes") or ())
            if not scopes <= EXTRA_SCOPES:
                raise ValueError(f"client {entry.get('id')!r} asks for scopes this service never grants")
            uris = entry.get("redirect_uris")
            if not entry.get("id") or not entry.get("secret") or not isinstance(uris, list) or not uris:
                raise ValueError("every client needs an id, a secret and a list of at least one redirect_uri")
            out[entry["id"]] = Client(
                id=entry["id"],
                secret=entry["secret"],
                redirect_uris=frozenset(uris),
                scopes=scopes,
                default_redirect_uri=uris[0],
            )
        return out

    @property
    def callback_url(self) -> str:
        return self.public_url.rstrip("/") + "/callback"

    @property
    def sqlalchemy_url(self) -> str:
        """The URL with the psycopg driver named, whatever form it was given in."""
        url = self.database_url
        for prefix in ("postgresql+psycopg://", "postgresql://", "postgres://"):
            if url.startswith(prefix):
                return "postgresql+psycopg://" + url[len(prefix) :]
        return url
