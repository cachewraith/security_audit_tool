"""Tests for Laravel-backed auth service behavior."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.auth.config import AuthConfig
from app.auth.exceptions import ApiError
from app.auth.models import AuthSession, DeviceLoginSession, UserIdentity
from app.auth.service import AuthService


@dataclass
class DummyStore:
    """Simple in-memory token store for service tests."""

    session: AuthSession | None = None
    cleared: bool = False

    def load(self) -> AuthSession | None:
        return self.session

    def save(self, session: AuthSession) -> None:
        self.session = session

    def clear(self) -> None:
        self.cleared = True
        self.session = None


class SequenceClient:
    """API client test double with queued exchange responses."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def post(self, path: str, *, json=None, bearer_token=None):
        self.requests.append((path, json, bearer_token))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def get(self, path: str, *, bearer_token=None):
        self.requests.append((path, None, bearer_token))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def test_poll_for_token_retries_pending_then_saves_session(monkeypatch) -> None:
    """Pending responses should poll again and eventually persist the session."""
    store = DummyStore()
    client = SequenceClient(
        [
            ApiError("Login not completed in browser yet.", error_code="authorization_pending"),
            {
                "success": True,
                "data": {
                    "access_token": "token-123",
                    "token_type": "Bearer",
                    "expires_at": "2026-04-24T12:00:00Z",
                    "user": {
                        "id": 5,
                        "email": "alice@example.com",
                        "first_name": "Alice",
                        "provider": "google",
                        "role": {"name": "User", "slug": "user"},
                    },
                },
            },
        ]
    )
    service = AuthService(client, store, AuthConfig())
    session = DeviceLoginSession(
        device_code="device-123",
        user_code="ABCD-EFGH",
        verification_uri="https://portal.example.test/verify",
        verification_uri_complete="https://portal.example.test/verify?c=device-123",
        interval=2,
        expires_in=60,
    )
    updates = []

    monkeypatch.setattr("app.auth.service.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("app.auth.service.time.monotonic", lambda: 0.0)

    result = service.poll_for_token(session, on_update=updates.append)

    assert result.access_token == "token-123"
    assert store.session is not None
    assert store.session.user.email == "alice@example.com"
    assert [update.state for update in updates] == ["pending"]


def test_poll_for_token_slow_down_increases_interval(monkeypatch) -> None:
    """`slow_down` should back off before retrying."""
    store = DummyStore()
    client = SequenceClient(
        [
            ApiError("Slow down.", error_code="slow_down"),
            {
                "success": True,
                "data": {
                    "access_token": "token-123",
                    "user": {"id": 5, "email": "alice@example.com"},
                },
            },
        ]
    )
    service = AuthService(client, store, AuthConfig())
    session = DeviceLoginSession(
        device_code="device-123",
        user_code="ABCD-EFGH",
        verification_uri="https://portal.example.test/verify",
        verification_uri_complete="https://portal.example.test/verify?c=device-123",
        interval=2,
        expires_in=60,
    )
    sleeps = []
    updates = []

    monkeypatch.setattr("app.auth.service.time.sleep", lambda seconds: sleeps.append(seconds))
    monkeypatch.setattr("app.auth.service.time.monotonic", lambda: 0.0)

    service.poll_for_token(session, on_update=updates.append)

    assert sleeps == [4]
    assert [update.wait_seconds for update in updates] == [4]


def test_poll_for_token_maps_terminal_error(monkeypatch) -> None:
    """Terminal exchange failures should become user-facing CLI messages."""
    store = DummyStore()
    client = SequenceClient(
        [ApiError("Bad device code.", error_code="invalid_device_code")]
    )
    service = AuthService(client, store, AuthConfig())
    session = DeviceLoginSession(
        device_code="device-123",
        user_code="ABCD-EFGH",
        verification_uri="https://portal.example.test/verify",
        verification_uri_complete="https://portal.example.test/verify?c=device-123",
        interval=2,
        expires_in=60,
    )

    monkeypatch.setattr("app.auth.service.time.monotonic", lambda: 0.0)

    with pytest.raises(ApiError, match="Start a new login attempt"):
        service.poll_for_token(session)


def test_whoami_clears_invalid_saved_session() -> None:
    """401 responses should clear stale local auth state."""
    store = DummyStore(
        session=AuthSession(
            access_token="secret-token",
            token_type="Bearer",
            user=UserIdentity(id=1, email="alice@example.com"),
            api_base_url="https://portal-api.hushstackcambodia.site",
        )
    )
    client = SequenceClient(
        [ApiError("Unauthenticated.", status_code=401)]
    )
    service = AuthService(client, store, AuthConfig())

    with pytest.raises(ApiError, match="Run `security-audit login` again"):
        service.whoami()

    assert store.cleared is True
