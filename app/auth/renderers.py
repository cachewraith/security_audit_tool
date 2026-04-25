"""Rich renderers for auth commands."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import AuthSession, DeviceLoginSession, UserIdentity


APP_TITLE = "Hushstack CLI Login"


def render_login_intro(console: Console, session: DeviceLoginSession) -> None:
    """Render the initial login instructions."""
    code = Text(session.user_code, style="bold black on bright_white")
    body = Table.grid(padding=(0, 1))
    body.add_column(style="bold cyan", width=16)
    body.add_column(style="white", ratio=1)
    body.add_row("What happens", "Open the browser, sign in through the Laravel portal, then return here.")
    body.add_row("User code", code)
    body.add_row("Verification URL", session.verification_uri)
    body.add_row("Expires in", f"{session.expires_in} seconds")

    console.print(
        Panel(
            body,
            title=f"[bold cyan]{APP_TITLE}[/]",
            border_style="cyan",
            padding=(1, 2),
        )
    )


def render_browser_fallback(console: Console, session: DeviceLoginSession) -> None:
    """Render a browser fallback when automatic open fails."""
    console.print(
        Panel(
            f"[bold]Open this URL manually:[/]\n{session.verification_uri_complete}\n\n"
            f"[bold]User code:[/] {session.user_code}",
            title="[bold yellow]Browser Not Opened[/]",
            border_style="yellow",
        )
    )


def render_user_summary(console: Console, user: UserIdentity, *, title: str) -> None:
    """Render a compact user card."""
    table = Table.grid(padding=(0, 1))
    table.add_column(style="bold cyan", width=14)
    table.add_column(style="white", ratio=1)
    table.add_row("Name", user.full_name)
    table.add_row("Email", user.email)
    if user.username:
        table.add_row("Username", user.username)
    if user.provider:
        table.add_row("Provider", user.provider)
    if user.role_name:
        table.add_row("Role", user.role_name)

    console.print(Panel(table, title=title, border_style="green"))


def render_login_success(console: Console, session: AuthSession) -> None:
    """Render the login success state."""
    render_user_summary(console, session.user, title="[bold green]Logged In[/]")
    if session.expires_at:
        console.print(f"[dim]Token expires at {session.expires_at}[/]")


def render_logout_success(console: Console, message: str) -> None:
    """Render logout confirmation."""
    console.print(Panel(message, title="[bold green]Logged Out[/]", border_style="green"))
