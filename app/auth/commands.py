"""Command handlers for Laravel-backed CLI auth."""

from __future__ import annotations

import argparse
import traceback
from dataclasses import dataclass
from typing import Callable

from rich.console import Console
from rich.status import Status

from .api_client import ApiClient
from .browser import open_browser
from .config import AuthConfig
from .exceptions import ApiError, AuthError, NetworkError, StorageError
from .renderers import (
    render_browser_fallback,
    render_login_intro,
    render_login_success,
    render_logout_success,
    render_user_summary,
)
from .service import AuthService, LoginPollUpdate
from .token_store import TokenStore


@dataclass(frozen=True)
class AuthCommandResult:
    """Result of handling an auth command."""

    exit_code: int
    launch_tool: bool = False


def maybe_handle_auth_command(args: list[str]) -> AuthCommandResult | None:
    """Handle standalone auth commands while preserving the existing scan CLI."""
    if not args:
        return None

    command_prefix = "security-audit"
    normalized = list(args)
    if normalized[0] == "auth":
        command_prefix = "security-audit auth"
        normalized = normalized[1:]

    if not normalized or normalized[0] not in {"login", "whoami", "logout"}:
        return None
    command = normalized[0]

    parser = argparse.ArgumentParser(
        prog=f"{command_prefix} {command}",
        description="Laravel-backed authentication for the Security Audit Tool",
    )
    parser.add_argument("--debug", action="store_true", help="Show debug diagnostics without printing secrets")
    parsed = parser.parse_args(normalized[1:])

    console = Console()
    config = AuthConfig()

    with ApiClient(config, debug=parsed.debug) as client:
        service = AuthService(client, TokenStore(config), config)
        try:
            if command == "login":
                return _run_login(service, console)
            if command == "whoami":
                return _run_whoami(service, console)
            return _run_logout(service, console)
        except KeyboardInterrupt:
            console.print("\n[yellow]Authentication cancelled.[/]")
            return AuthCommandResult(exit_code=130)
        except (AuthError, ApiError, NetworkError, StorageError) as exc:
            console.print(f"[red]{exc}[/]")
            if parsed.debug:
                traceback.print_exc()
            return AuthCommandResult(exit_code=1)
        except Exception as exc:  # pragma: no cover - defensive fallback
            console.print("[red]Unexpected authentication failure.[/]")
            if parsed.debug:
                traceback.print_exc()
            else:
                console.print(f"[dim]{type(exc).__name__}: {exc}[/]")
            return AuthCommandResult(exit_code=1)


def _run_login(service: AuthService, console: Console) -> AuthCommandResult:
    login_session = service.start_login()
    render_login_intro(console, login_session)

    browser_opened = open_browser(login_session.verification_uri_complete)
    if browser_opened:
        console.print("[green]Browser opened. Complete login there, then return here.[/]")
    else:
        render_browser_fallback(console, login_session)

    last_message = "Waiting for approval in your browser..."

    def handle_update(update: LoginPollUpdate) -> None:
        nonlocal last_message
        last_message = update.message

    with console.status("[cyan]Waiting for browser approval...[/]", spinner="dots") as status:
        session = service.poll_for_token(login_session, on_update=handle_update_and_refresh(status, handle_update))

    if last_message and "authorization_pending" not in last_message:
        console.print(f"[dim]{last_message}[/]")
    render_login_success(console, session)
    console.print("[green]Opening the tool...[/]")
    return AuthCommandResult(exit_code=0, launch_tool=True)


def handle_update_and_refresh(
    status: Status,
    callback: Callable[[LoginPollUpdate], None],
) -> Callable[[LoginPollUpdate], None]:
    """Return a poll callback that also updates the Rich status line."""

    def _handle(update: LoginPollUpdate) -> None:
        callback(update)
        if update.state == "slow_down":
            status.update(f"[yellow]{update.message} Retrying in {update.wait_seconds}s...[/]")
        else:
            status.update("[cyan]Waiting for browser approval...[/]")

    return _handle


def _run_whoami(service: AuthService, console: Console) -> AuthCommandResult:
    session = service.whoami()
    render_user_summary(console, session.user, title="[bold cyan]Current User[/]")
    if session.expires_at:
        console.print(f"[dim]Token expires at {session.expires_at}[/]")
    return AuthCommandResult(exit_code=0)


def _run_logout(service: AuthService, console: Console) -> AuthCommandResult:
    message = service.logout()
    render_logout_success(console, message)
    return AuthCommandResult(exit_code=0)
