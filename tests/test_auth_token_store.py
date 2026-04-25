"""Tests for local auth token storage."""

import os

from app.auth.config import AuthConfig
from app.auth.models import AuthSession, UserIdentity
from app.auth.token_store import TokenStore


def test_token_store_saves_and_loads_with_file_fallback(tmp_path, monkeypatch) -> None:
    """The file fallback should persist auth state with restrictive permissions."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr("app.auth.token_store.keyring", None)

    config = AuthConfig()
    store = TokenStore(config)
    session = AuthSession(
        access_token="secret-token",
        token_type="Bearer",
        expires_at="2026-04-24T12:00:00Z",
        api_base_url=config.api_base_url,
        user=UserIdentity(
            id=7,
            email="alice@example.com",
            first_name="Alice",
            last_name="Lee",
            provider="google",
            role_name="Admin",
            role_slug="admin",
        ),
    )

    store.save(session)
    loaded = store.load()

    assert loaded is not None
    assert loaded.access_token == "secret-token"
    assert loaded.user.email == "alice@example.com"
    assert oct(os.stat(store.storage_path).st_mode & 0o777) == "0o600"


def test_token_store_clear_removes_file_state(tmp_path, monkeypatch) -> None:
    """Clearing auth state should remove the fallback file."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr("app.auth.token_store.keyring", None)

    config = AuthConfig()
    store = TokenStore(config)
    session = AuthSession(
        access_token="secret-token",
        token_type="Bearer",
        api_base_url=config.api_base_url,
        user=UserIdentity(id=1, email="alice@example.com"),
    )

    store.save(session)
    assert store.storage_path.exists() is True

    store.clear()

    assert store.storage_path.exists() is False
