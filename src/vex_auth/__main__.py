"""`vex-auth serve` runs the service; `vex-auth db upgrade|downgrade|current` migrates its database.

Migrations are their own step, run before `serve` (the container's compose file runs `db upgrade` as a
one-shot the service waits for). `serve` never changes the schema; it refuses to start on a database
that is behind the code.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import uvicorn

from vex_auth.config import Settings
from vex_auth.db import current, downgrade, upgrade


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vex-auth")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="run the HTTP service")
    db = sub.add_parser("db", help="database migrations")
    db_sub = db.add_subparsers(dest="action", required=True)
    up = db_sub.add_parser("upgrade", help="migrate to a revision (default: the newest)")
    up.add_argument("revision", nargs="?", default="head")
    down = db_sub.add_parser("downgrade", help="migrate back to a revision (`base` removes everything)")
    down.add_argument("revision")
    db_sub.add_parser("current", help="the database's revision and the newest one")
    args = parser.parse_args(argv)

    settings = Settings()
    url = settings.sqlalchemy_url
    if args.command == "db":
        if args.action == "upgrade":
            upgrade(url, args.revision)
        elif args.action == "downgrade":
            downgrade(url, args.revision)
        else:
            found, head = current(url)
            print(f"database: {found or 'empty'}, newest: {head}")
            return 0 if found == head else 1
        return 0

    found, head = current(url)
    if found != head:
        print(f"database is at {found or 'nothing'}, the code needs {head}: run `vex-auth db upgrade`")
        return 1
    from vex_auth.app import create_app

    config = uvicorn.Config(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        proxy_headers=True,
        forwarded_allow_ips=settings.forwarded_allow_ips,
        access_log=False,
    )
    server = uvicorn.Server(config)
    # psycopg's async driver can't run on Windows' default proactor loop; elsewhere this is the default.
    loop_factory = asyncio.SelectorEventLoop if sys.platform == "win32" else None
    asyncio.run(server.serve(), loop_factory=loop_factory)
    return 0


if __name__ == "__main__":
    sys.exit(main())
