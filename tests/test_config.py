from __future__ import annotations

from pathlib import Path

import pytest

from vex_auth.config import Settings


def test_secrets_come_from_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUTH_TOKEN_KEY", raising=False)
    monkeypatch.delenv("AUTH_DATABASE_URL", raising=False)
    (tmp_path / "auth_token_key").write_text("key-from-file\n", encoding="utf-8")
    (tmp_path / "auth_database_url").write_text("postgresql://u:p@db:5432/x\n", encoding="utf-8")
    settings = Settings(_env_file=None, _secrets_dir=tmp_path)  # type: ignore[call-arg]
    assert settings.token_key.get_secret_value() == "key-from-file"
    assert settings.database_url == "postgresql://u:p@db:5432/x"


def test_environment_wins_over_a_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "auth_token_key").write_text("key-from-file", encoding="utf-8")
    monkeypatch.setenv("AUTH_TOKEN_KEY", "key-from-env")
    settings = Settings(_env_file=None, _secrets_dir=tmp_path)  # type: ignore[call-arg]
    assert settings.token_key.get_secret_value() == "key-from-env"
