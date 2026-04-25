"""Tests for auth gating in the main entrypoint."""

import pytest

from app.auth import AuthCommandResult
from app.auth.exceptions import AuthError
from app.main import main


def test_main_requires_login_before_launching_tui(monkeypatch) -> None:
    """No-arg tool launch should fail cleanly when no login is present."""
    monkeypatch.setattr("app.main.maybe_handle_auth_command", lambda _args: None)
    monkeypatch.setattr(
        "app.main.require_authenticated_session",
        lambda _config: (_ for _ in ()).throw(AuthError("Login required. Run `security-audit login` first.")),
    )

    assert main([]) == 1


def test_main_continues_into_tui_after_successful_login(monkeypatch) -> None:
    """`login` should enter the tool immediately after auth succeeds."""
    monkeypatch.setattr(
        "app.main.maybe_handle_auth_command",
        lambda _args: AuthCommandResult(exit_code=0, launch_tool=True),
    )
    monkeypatch.setattr("app.main.require_authenticated_session", lambda _config: None)

    launched = {}

    class FakeTUI:
        def run(self):
            launched["ran"] = True
            return None

    monkeypatch.setattr("app.main.TUI", FakeTUI)

    assert main(["login"]) == 0
    assert launched["ran"] is True
