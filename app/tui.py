"""Modern terminal workspace UI for the security audit tool."""

from __future__ import annotations

import logging
import re
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version as get_package_version
from pathlib import Path
from typing import Any, Optional

from prompt_toolkit import prompt as pt_prompt
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.key_binding import KeyBindings
from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.prompt import Confirm
from rich.table import Table
from rich.text import Text

from .config import Config
from .core.check_runner import select_checks
from .core.scan_modes import (
    CHECK_SETTING_BY_ID,
    SCAN_MODE_DEFINITIONS,
    apply_scan_mode,
    enable_checks,
    get_scan_mode_definition,
)
from .models import ScanMode, Scope
from .report.terminal_reporter import TerminalReporter
from .scope import ScopeManager
from .utils import validate_host, validate_path, validate_url


THEME = {
    "bg": "on #0b1220",
    "primary": "#7dd3fc",
    "secondary": "#38bdf8",
    "accent": "#34d399",
    "warning": "#fbbf24",
    "error": "#f87171",
    "text": "#e2e8f0",
    "muted": "#94a3b8",
    "border": "#1e293b",
    "active": "#22c55e",
    "complete": "#38bdf8",
    "pending": "#475569",
}

FLOW_STEPS = (
    "Mode",
    "Target",
    "Custom Checks",
    "Reports",
    "Authorization",
)

CUSTOM_CHECK_OPTIONS = (
    ("tls", "TLS review", "TLS settings, certificates, and transport posture"),
    ("website_risk", "Website risk", "Headers, cookies, forms, CORS, and banner exposure"),
    ("performance", "Performance", "Latency and response-time checks"),
    ("load_test", "Load test", "Bounded load testing for resilience mode"),
    ("vulnerability", "Vulnerability", "Explicit active application probes"),
    ("secrets", "Secrets", "Pattern-based secret discovery in files"),
    ("dependencies", "Dependencies", "Dependency hygiene and risky packages"),
    ("webapp_config", "Web config", "App and server configuration review"),
    ("containers", "Containers", "Docker and container configuration review"),
    ("permissions", "Permissions", "Filesystem ownership and permission issues"),
    ("services", "Services", "Local service exposure review"),
    ("firewall", "Firewall", "Firewall posture inspection"),
    ("hardening", "Hardening", "Local hardening baseline checks"),
)


@dataclass
class ScanProgressState:
    """Mutable state for the live scan workspace."""

    mode_label: str = "Security Audit"
    total_checks: int = 0
    completed_checks: int = 0
    current_check_name: str = "Preparing workspace"
    current_message: str = "Building scan plan"
    findings_count: int = 0
    errors_count: int = 0
    started_at: float = field(default_factory=time.perf_counter)
    scope_lines: list[str] = field(default_factory=list)
    check_names: list[str] = field(default_factory=list)
    recent_events: list[str] = field(default_factory=list)
    failed: bool = False
    finished: bool = False

    def push_event(self, message: str) -> None:
        """Add a recent event while keeping the list compact."""
        self.recent_events = [message, *self.recent_events[:5]]

    @property
    def elapsed_seconds(self) -> float:
        """Return the current elapsed time."""
        return time.perf_counter() - self.started_at


class NavigateBack(Exception):
    """Raised when the user requests to go back to the previous step."""


class TUI:
    """Terminal workspace UI for interactive scans."""

    RICH_TAG_RE = re.compile(r"\[/?[^\]]+\]")
    SPINNER_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")

    def __init__(self):
        self.console = Console()
        self.reporter = TerminalReporter(use_colors=sys.stdout.isatty())
        self.config = Config()
        self.theme = THEME

    def _package_version(self) -> str:
        """Return the installed package version or a fallback."""
        try:
            return get_package_version("cache-wraith-audit-tool")
        except PackageNotFoundError:
            return "1.0.6"

    def _plain_prompt_message(self, message: str) -> str:
        """Remove Rich tags for prompt_toolkit prompts."""
        return self.RICH_TAG_RE.sub("", message).strip()

    def _current_mode_label(self, mode: ScanMode | None) -> str:
        """Return the user-facing label for a mode."""
        if mode is None:
            return "Not selected"
        return get_scan_mode_definition(mode).label

    def _scope_lines(self, scope: Scope | None) -> list[str]:
        """Summarize a scope into short lines for side panels."""
        if scope is None:
            return ["No target selected yet"]

        lines: list[str] = []

        if scope.allowed_urls:
            lines.extend(f"URL  {url}" for url in scope.allowed_urls[:3])
            if len(scope.allowed_urls) > 3:
                lines.append(f"+ {len(scope.allowed_urls) - 3} more URLs")

        if scope.allowed_hosts:
            lines.extend(f"Host {host}" for host in scope.allowed_hosts[:3])
            if len(scope.allowed_hosts) > 3:
                lines.append(f"+ {len(scope.allowed_hosts) - 3} more hosts")

        if scope.project_paths:
            lines.extend(f"Path {path}" for path in scope.project_paths[:2])
            if len(scope.project_paths) > 2:
                lines.append(f"+ {len(scope.project_paths) - 2} more paths")

        if scope.local_endpoint:
            lines.append("Local endpoint enabled")

        if scope.container_ids:
            lines.append(f"Containers {len(scope.container_ids)} selected")

        if scope.container_images:
            lines.append(f"Images {len(scope.container_images)} selected")

        return lines or ["No target selected yet"]

    def _enabled_check_ids(self) -> list[str]:
        """Return enabled checks for the current config."""
        enabled: list[str] = []
        for check_id, setting_name in CHECK_SETTING_BY_ID.items():
            if bool(getattr(self.config.check, setting_name)):
                enabled.append(check_id)
        return enabled

    def _build_flow_panel(self, current_step: int) -> Panel:
        """Render the left-side step navigator."""
        rows = Table.grid(expand=True)
        rows.add_column(width=5)
        rows.add_column(ratio=1)

        for index, label in enumerate(FLOW_STEPS):
            if index < current_step:
                marker = "[bold #38bdf8]●[/]"
                title = f"[bold {self.theme['text']}]{label}[/]"
                note = f"[{self.theme['muted']}]Done[/]"
            elif index == current_step:
                marker = "[bold #22c55e]◉[/]"
                title = f"[bold {self.theme['accent']}]{label}[/]"
                note = f"[{self.theme['muted']}]Active[/]"
            else:
                marker = f"[{self.theme['pending']}]○[/]"
                title = f"[{self.theme['muted']}]{label}[/]"
                note = f"[{self.theme['pending']}]Waiting[/]"
            rows.add_row(marker, f"{title}\n{note}")

        return Panel(
            rows,
            title=f"[bold {self.theme['secondary']}]Flow[/]",
            border_style=self.theme["border"],
            box=box.ROUNDED,
            padding=(1, 1),
        )

    def _build_context_panel(
        self,
        mode: ScanMode | None,
        scope: Scope | None,
        target_family: str,
    ) -> Panel:
        """Render the current workspace context panel."""
        content = Table.grid(padding=(0, 1))
        content.add_column(style=f"bold {self.theme['muted']}", width=10)
        content.add_column(style=self.theme["text"], ratio=1)
        content.add_row("Mode", self._current_mode_label(mode))
        content.add_row("Target", target_family or "Not selected")

        enabled_checks = self._enabled_check_ids()
        checks_value = ", ".join(enabled_checks[:5]) if enabled_checks else "Auto after selection"
        if len(enabled_checks) > 5:
            checks_value += f" +{len(enabled_checks) - 5}"
        content.add_row("Checks", checks_value)

        scope_lines = self._scope_lines(scope)
        scope_text = "\n".join(scope_lines[:4])
        content.add_row("Scope", scope_text)

        return Panel(
            content,
            title=f"[bold {self.theme['secondary']}]Context[/]",
            border_style=self.theme["border"],
            box=box.ROUNDED,
            padding=(1, 1),
        )

    def _render_shell(
        self,
        title: str,
        body: Any,
        current_step: int,
        subtitle: str = "",
        mode: ScanMode | None = None,
        scope: Scope | None = None,
        target_family: str = "",
    ) -> Layout:
        """Render the shared shell layout used by the wizard."""
        width = self.console.size.width
        sidebar_width = max(28, min(36, width // 3))

        header_grid = Table.grid(expand=True)
        header_grid.add_column(ratio=1)
        header_grid.add_column(justify="right", width=16)
        header_grid.add_row(
            Text("CACHE WRAITH", style=f"bold {self.theme['primary']}"),
            Text(f"v{self._package_version()}", style=self.theme["muted"]),
        )
        header_grid.add_row(
            Text("Security audit workspace", style=f"bold {self.theme['text']}"),
            Text("AUTHORIZED USE ONLY", style=f"bold {self.theme['warning']}"),
        )

        header_panel = Panel(
            Group(
                header_grid,
                Text(subtitle or "Set up the scan, then launch it from the workspace.", style=self.theme["muted"]),
            ),
            border_style=self.theme["border"],
            box=box.SQUARE,
            padding=(0, 1),
        )

        footer_panel = Panel(
            Align.center(
                Text(
                    "Enter confirm   Ctrl+Left go back   Ctrl+C exit",
                    style=self.theme["muted"],
                )
            ),
            border_style=self.theme["border"],
            box=box.SQUARE,
            padding=(0, 1),
        )

        main_panel = Panel(
            body,
            title=f"[bold {self.theme['secondary']}]{title}[/]",
            border_style=self.theme["border"],
            box=box.ROUNDED,
            padding=(1, 2),
        )

        sidebar = Group(
            self._build_flow_panel(current_step),
            self._build_context_panel(mode, scope, target_family),
        )

        layout = Layout(name="root")
        layout.split_column(
            Layout(header_panel, name="header", size=5),
            Layout(name="content", ratio=1),
            Layout(footer_panel, name="footer", size=3),
        )
        layout["content"].split_row(
            Layout(Panel(sidebar, border_style=self.theme["border"], box=box.SQUARE), name="sidebar", size=sidebar_width),
            Layout(main_panel, name="main", ratio=1),
        )
        return layout

    def _show_screen(
        self,
        title: str,
        body: Any,
        current_step: int,
        subtitle: str = "",
        mode: ScanMode | None = None,
        scope: Scope | None = None,
        target_family: str = "",
    ) -> None:
        """Clear the console and render a shell screen."""
        self.console.clear()
        self.console.print(
            self._render_shell(
                title=title,
                body=body,
                current_step=current_step,
                subtitle=subtitle,
                mode=mode,
                scope=scope,
                target_family=target_family,
            )
        )

    def _handle_interrupt(self, message: str = "Operation cancelled by user.") -> None:
        """Render a cancellation message."""
        self.console.print(f"\n[{self.theme['warning']}]{message}[/]")

    def _create_prompt_bindings(self) -> KeyBindings:
        """Create prompt-toolkit key bindings for navigation."""
        bindings = KeyBindings()

        @bindings.add("c-left")
        def _(event) -> None:
            event.app.exit(exception=NavigateBack())

        return bindings

    def _prompt_ask(
        self,
        message: str,
        choices: Optional[list[str]] = None,
        default: Optional[str] = None,
    ) -> str:
        """Prompt for text input with Ctrl+C handling."""
        try:
            while True:
                prompt_text = (
                    f"\n\033[96m▶\033[0m {self._plain_prompt_message(message)} "
                    "\033[90m(Ctrl+Left to go back)\033[0m"
                )
                if default is not None:
                    prompt_text += f" [{default}]"
                prompt_text += ": "

                value = pt_prompt(
                    ANSI(prompt_text),
                    default=default or "",
                    key_bindings=self._create_prompt_bindings(),
                ).strip()

                if value:
                    if choices and value not in choices:
                        valid = ", ".join(choices)
                        self.console.print(
                            f"[{self.theme['error']}]Invalid choice. Choose: {valid}[/]"
                        )
                        continue
                    return value

                if default is not None:
                    return default

        except NavigateBack:
            raise
        except (KeyboardInterrupt, EOFError):
            self._handle_interrupt()
            raise

    def _confirm_ask(self, message: str, default: bool = False) -> bool:
        """Prompt for confirmation with Ctrl+C and back handling."""
        default_text = "y" if default else "n"
        response = self._prompt_ask(
            f"{message} [y/n]",
            choices=["y", "n", "yes", "no"],
            default=default_text,
        ).lower()
        return response in {"y", "yes"}

    def _select_mode(self) -> ScanMode:
        """Mode selection dashboard."""
        table = Table(expand=True, box=box.SIMPLE_HEAVY)
        table.add_column("Key", width=5, style=f"bold {self.theme['primary']}")
        table.add_column("Mode", width=20, style=f"bold {self.theme['text']}")
        table.add_column("Description", style=self.theme["muted"])

        for definition in SCAN_MODE_DEFINITIONS:
            table.add_row(definition.key, definition.label, definition.description)

        body = Group(
            Text(
                "Choose the audit profile that matches the job you want to run.",
                style=self.theme["text"],
            ),
            Text(
                "Each profile enables a safe baseline for that target family.",
                style=self.theme["muted"],
            ),
            Text(""),
            table,
        )

        self._show_screen(
            title="Select Scan Mode",
            body=body,
            current_step=0,
            subtitle="A full-screen workspace with guided setup and live scan telemetry.",
        )

        choice = self._prompt_ask(
            "Select mode",
            choices=[definition.key for definition in SCAN_MODE_DEFINITIONS],
            default="1",
        )

        for definition in SCAN_MODE_DEFINITIONS:
            if definition.key == choice:
                return definition.mode

        raise ValueError(f"Unknown mode selection: {choice}")

    def _prompt_url_target(
        self,
        title: str,
        subtitle: str,
        mode: ScanMode | None,
        scope: Scope | None,
        target_family: str,
    ) -> str:
        """Prompt for a live website or API target."""
        self._show_screen(
            title=title,
            body=Group(
                Text(subtitle, style=self.theme["text"]),
                Text("Accepted values: full URLs or bare hostnames.", style=self.theme["muted"]),
                Text(""),
                Panel(
                    Text(
                        "Examples\nhttps://example.com\nhttps://api.example.com/v1\nexample.com",
                        style=self.theme["text"],
                    ),
                    border_style=self.theme["border"],
                    box=box.ROUNDED,
                ),
            ),
            current_step=1,
            subtitle="Target setup",
            mode=mode,
            scope=scope,
            target_family=target_family,
        )

        target = ""
        while not target:
            target = self._prompt_ask("Target URL or hostname").strip()
            if not target:
                self.console.print(
                    f"[{self.theme['error']}]Target is required[/]"
                )
                continue

            validation_errors = validate_url(target, allowed_schemes=["http", "https"])
            if validation_errors and "missing scheme" in " ".join(validation_errors).lower():
                validation_errors = validate_host(target)

            if validation_errors:
                self.console.print(
                    f"[{self.theme['error']}]Invalid target: {', '.join(validation_errors)}[/]"
                )
                target = ""

        return target

    def _prompt_project_path(
        self,
        title: str,
        subtitle: str,
        mode: ScanMode | None,
        scope: Scope | None,
        target_family: str,
    ) -> Path:
        """Prompt for a project directory path."""
        self._show_screen(
            title=title,
            body=Group(
                Text(subtitle, style=self.theme["text"]),
                Text("The directory must already exist and be readable.", style=self.theme["muted"]),
                Text(""),
                Panel(
                    Text(
                        "Examples\n~/project\n./src\n/mnt/storage/OwnProject/app",
                        style=self.theme["text"],
                    ),
                    border_style=self.theme["border"],
                    box=box.ROUNDED,
                ),
            ),
            current_step=1,
            subtitle="Target setup",
            mode=mode,
            scope=scope,
            target_family=target_family,
        )

        while True:
            raw_path = self._prompt_ask("Project directory")
            path = Path(raw_path).expanduser()
            errors = validate_path(path, must_exist=True, must_be_dir=True)
            if errors:
                self.console.print(
                    f"[{self.theme['error']}]Invalid path: {', '.join(errors)}[/]"
                )
                continue
            return path.resolve()

    def _select_custom_target_type(
        self,
        mode: ScanMode | None,
        scope: Scope | None,
        target_family: str,
    ) -> str:
        """Prompt for the custom target family."""
        table = Table(expand=True, box=box.SIMPLE_HEAVY)
        table.add_column("Key", width=5, style=f"bold {self.theme['primary']}")
        table.add_column("Target", width=18, style=f"bold {self.theme['text']}")
        table.add_column("Description", style=self.theme["muted"])
        table.add_row("1", "Website/API", "Use a URL or hostname target")
        table.add_row("2", "Codebase", "Use a project directory target")
        table.add_row("3", "Host", "Audit the local machine")
        table.add_row("4", "Containers", "Review container config files and optional local containers")

        self._show_screen(
            title="Custom Target Type",
            body=Group(
                Text("Choose what kind of asset you want the custom scan to review.", style=self.theme["text"]),
                Text("You can tailor checks after the target is selected.", style=self.theme["muted"]),
                Text(""),
                table,
            ),
            current_step=1,
            subtitle="Target setup",
            mode=mode,
            scope=scope,
            target_family=target_family,
        )

        return self._prompt_ask(
            "Select target type",
            choices=["1", "2", "3", "4"],
            default="1",
        )

    def _collect_scope_for_mode(
        self,
        mode: ScanMode,
    ) -> tuple[ScopeManager, str]:
        """Collect the appropriate scope for the selected mode."""
        if mode == ScanMode.WEBSITE_REVIEW:
            target = self._prompt_url_target(
                "Website Target",
                "Enter the website URL or hostname you want to review.",
                mode=mode,
                scope=None,
                target_family="website",
            )
            return ScopeManager.from_args(urls=[target]), "website"

        if mode == ScanMode.API_REVIEW:
            target = self._prompt_url_target(
                "API Target",
                "Enter the API base URL or endpoint you want to review.",
                mode=mode,
                scope=None,
                target_family="api",
            )
            return ScopeManager.from_args(urls=[target]), "api"

        if mode == ScanMode.RESILIENCE_TEST:
            target = self._prompt_url_target(
                "Resilience Target",
                "Enter the URL or hostname to measure for performance and bounded load.",
                mode=mode,
                scope=None,
                target_family="website",
            )
            return ScopeManager.from_args(urls=[target]), "website"

        if mode == ScanMode.CODEBASE_REVIEW:
            path = self._prompt_project_path(
                "Codebase Target",
                "Choose the project directory to scan for secrets, dependencies, and config risks.",
                mode=mode,
                scope=None,
                target_family="codebase",
            )
            return ScopeManager.from_args(paths=[path]), "codebase"

        if mode == ScanMode.HOST_HARDENING:
            return ScopeManager.from_args(local=True), "host"

        if mode == ScanMode.CONTAINER_REVIEW:
            path = self._prompt_project_path(
                "Container Target",
                "Choose the project directory that contains Docker or container configuration files.",
                mode=mode,
                scope=None,
                target_family="container",
            )
            inspect_local = self._confirm_ask(
                "Inspect running local containers too?",
                default=True,
            )
            return ScopeManager.from_args(paths=[path], local=inspect_local), "container"

        if mode == ScanMode.CUSTOM:
            target_type = self._select_custom_target_type(mode=mode, scope=None, target_family="custom")
            if target_type == "1":
                target = self._prompt_url_target(
                    "Custom Website/API Target",
                    "Enter the URL or hostname for your custom review.",
                    mode=mode,
                    scope=None,
                    target_family="website",
                )
                return ScopeManager.from_args(urls=[target]), "website"
            if target_type == "2":
                path = self._prompt_project_path(
                    "Custom Codebase Target",
                    "Choose the project directory for your custom review.",
                    mode=mode,
                    scope=None,
                    target_family="codebase",
                )
                return ScopeManager.from_args(paths=[path]), "codebase"
            if target_type == "3":
                return ScopeManager.from_args(local=True), "host"

            path = self._prompt_project_path(
                "Custom Container Target",
                "Choose the project directory that contains container configuration files.",
                mode=mode,
                scope=None,
                target_family="container",
            )
            inspect_local = self._confirm_ask(
                "Inspect running local containers too?",
                default=True,
            )
            return ScopeManager.from_args(paths=[path], local=inspect_local), "container"

        raise ValueError(f"Unsupported mode: {mode}")

    def _apply_custom_defaults(self, target_family: str) -> None:
        """Apply a safe baseline profile for custom mode based on target family."""
        if target_family in {"website", "api"}:
            enable_checks(self.config, ["tls", "website_risk", "performance"])
            self.config.check.enable_banner_grabbing = True
            self.config.output.verbose = True
            return

        if target_family == "codebase":
            enable_checks(self.config, ["secrets", "dependencies", "webapp_config", "containers"])
            return

        if target_family == "host":
            enable_checks(self.config, ["permissions", "services", "firewall", "hardening"])
            return

        if target_family == "container":
            enable_checks(self.config, ["containers"])

    def _enable_requested_custom_checks(self, check_ids: list[str] | None) -> None:
        """Enable checks explicitly requested in custom mode."""
        if not check_ids:
            return
        enable_checks(self.config, check_ids)

    def _custom_checks_body(self, target_family: str) -> Group:
        """Render the custom-check selection guidance."""
        table = Table(expand=True, box=box.SIMPLE_HEAVY)
        table.add_column("Check ID", width=16, style=f"bold {self.theme['primary']}")
        table.add_column("Name", width=18, style=f"bold {self.theme['text']}")
        table.add_column("Description", style=self.theme["muted"])

        for check_id, label, description in CUSTOM_CHECK_OPTIONS:
            table.add_row(check_id, label, description)

        return Group(
            Text(
                f"Custom mode starts with a recommended {target_family} baseline, and you can narrow or skip checks here.",
                style=self.theme["text"],
            ),
            Text(
                "Enter a comma-separated list of check IDs, or leave blank to keep the baseline.",
                style=self.theme["muted"],
            ),
            Text(""),
            table,
        )

    def run(self) -> Optional[tuple[Config, ScopeManager, dict]]:
        """Run the interactive TUI flow."""
        step = 0
        mode: Optional[ScanMode] = None
        scope_manager: Optional[ScopeManager] = None
        target_family = ""
        extra_options = {"skip_checks": None, "only_checks": None}

        while True:
            try:
                if step == 0:
                    self.config = Config()
                    mode = self._select_mode()
                    apply_scan_mode(self.config, mode)
                    step = 1
                    continue

                if step == 1:
                    if mode is None:
                        step = 0
                        continue

                    scope_manager, target_family = self._collect_scope_for_mode(mode)

                    if not scope_manager.validate():
                        self.console.print()
                        for error in scope_manager.validation_errors:
                            self.console.print(
                                f"[{self.theme['error']}]Scope error: {error}[/]"
                            )
                        continue

                    extra_options = {"skip_checks": None, "only_checks": None}
                    step = 2 if mode == ScanMode.CUSTOM else 3
                    continue

                if step == 2:
                    self._apply_custom_defaults(target_family)
                    self._show_screen(
                        title="Custom Scan Configuration",
                        body=self._custom_checks_body(target_family),
                        current_step=2,
                        subtitle="Fine-tune the baseline before launch.",
                        mode=mode,
                        scope=scope_manager.scope if scope_manager else None,
                        target_family=target_family,
                    )

                    only = self._prompt_ask(
                        "Only run checks (comma-separated, empty for baseline)",
                        default="",
                    ).strip()

                    if only:
                        extra_options["only_checks"] = only
                        self._enable_requested_custom_checks(
                            [item.strip() for item in only.split(",") if item.strip()]
                        )
                    else:
                        skip = self._prompt_ask(
                            "Skip checks (comma-separated)",
                            default="",
                        ).strip()

                        if skip:
                            extra_options["skip_checks"] = skip

                    step = 3
                    continue

                if step == 3:
                    self._show_screen(
                        title="Reporting Options",
                        body=Group(
                            Text("Reports can be generated automatically after the scan.", style=self.theme["text"]),
                            Text("JSON and HTML are written in the project folder, and PDF goes to Downloads.", style=self.theme["muted"]),
                            Text(""),
                            Panel(
                                Text(
                                    "Artifacts\n• JSON report\n• HTML report\n• PDF report\n• Terminal summary",
                                    style=self.theme["text"],
                                ),
                                border_style=self.theme["border"],
                                box=box.ROUNDED,
                            ),
                        ),
                        current_step=3,
                        subtitle="Output configuration",
                        mode=mode,
                        scope=scope_manager.scope if scope_manager else None,
                        target_family=target_family,
                    )

                    save_report = self._confirm_ask(
                        "Save findings to report files?",
                        default=True,
                    )

                    self.config.output.json_report_path = None
                    self.config.output.html_report_path = None
                    self.config.output.pdf_report_path = None

                    if save_report:
                        timestamp = time.strftime("%Y%m%d_%H%M%S")
                        self.config.output.json_report_path = Path(
                            f"audit_report_{timestamp}.json"
                        )
                        self.config.output.html_report_path = Path(
                            f"audit_report_{timestamp}.html"
                        )

                        from .utils import get_downloads_path

                        downloads = get_downloads_path()
                        self.config.output.pdf_report_path = (
                            downloads / f"audit_report_{timestamp}.pdf"
                        )

                        self.console.print(
                            f"[{self.theme['muted']}]Reports will be saved as audit_report_{timestamp}.*[/]"
                        )

                    step = 4
                    continue

                if step == 4:
                    from .cli import LEGAL_WARNING

                    self._show_screen(
                        title="Authorization Check",
                        body=Group(
                            Panel(
                                Text.from_markup(LEGAL_WARNING.strip()),
                                border_style=self.theme["error"],
                                box=box.HEAVY,
                                padding=(1, 2),
                            ),
                            Text(""),
                            Text(
                                "You must have explicit permission for every target you scan.",
                                style=f"bold {self.theme['warning']}",
                            ),
                        ),
                        current_step=4,
                        subtitle="Final confirmation before launch.",
                        mode=mode,
                        scope=scope_manager.scope if scope_manager else None,
                        target_family=target_family,
                    )

                    auth = self._confirm_ask(
                        "Do you have explicit authorization to audit this target?",
                        default=False,
                    )

                    if not auth:
                        self.console.print(
                            f"\n[bold {self.theme['error']}]Authorization required. Exiting.[/]"
                        )
                        return None

                    self.config.authorization_confirmed = True
                    return self.config, scope_manager, extra_options

            except NavigateBack:
                if step == 0:
                    continue
                if step == 1:
                    step = 0
                elif step == 2:
                    step = 1
                elif step == 3:
                    step = 2 if mode == ScanMode.CUSTOM else 1
                elif step == 4:
                    step = 3
                continue
            except (KeyboardInterrupt, EOFError):
                return None
            except Exception as e:
                self.console.print(f"[{self.theme['error']}]Error: {e}[/]")
                return None

    def _build_scan_layout(self, state: ScanProgressState) -> Layout:
        """Build the full-screen live scan layout."""
        frame = self.SPINNER_FRAMES[int(time.perf_counter() * 12) % len(self.SPINNER_FRAMES)]
        progress_total = max(state.total_checks, 1)

        header = Panel(
            Group(
                Text(
                    f"{frame}  {state.mode_label}",
                    style=f"bold {self.theme['primary']}",
                ),
                Text(
                    "Live audit workspace",
                    style=self.theme["muted"],
                ),
            ),
            border_style=self.theme["border"],
            box=box.SQUARE,
            padding=(0, 1),
        )

        hero = Panel(
            Group(
                Text(
                    state.current_check_name,
                    style=f"bold {self.theme['text']}",
                ),
                Text(state.current_message, style=self.theme["muted"]),
                Text(""),
                ProgressBar(
                    total=progress_total,
                    completed=state.completed_checks,
                    width=None,
                    complete_style=self.theme["accent"],
                    finished_style=self.theme["secondary"],
                    pulse_style=self.theme["secondary"],
                ),
                Text(""),
                Text(
                    f"{state.completed_checks}/{state.total_checks} checks complete   •   "
                    f"{state.findings_count} findings   •   {state.errors_count} errors   •   "
                    f"{state.elapsed_seconds:0.1f}s",
                    style=self.theme["text"],
                ),
            ),
            title=f"[bold {self.theme['secondary']}]Execution[/]",
            border_style=self.theme["border"],
            box=box.ROUNDED,
            padding=(1, 2),
        )

        checks_table = Table.grid(expand=True)
        checks_table.add_column(ratio=1)
        checks_table.add_column(justify="right", width=10)

        if state.check_names:
            for index, check_name in enumerate(state.check_names, start=1):
                if index <= state.completed_checks:
                    marker = f"[bold {self.theme['complete']}]done[/]"
                elif check_name == state.current_check_name:
                    marker = f"[bold {self.theme['accent']}]live[/]"
                else:
                    marker = f"[{self.theme['muted']}]queued[/]"
                checks_table.add_row(check_name, marker)
        else:
            checks_table.add_row("Preparing scan plan", f"[{self.theme['muted']}]queued[/]")

        checks_panel = Panel(
            checks_table,
            title=f"[bold {self.theme['secondary']}]Checks[/]",
            border_style=self.theme["border"],
            box=box.ROUNDED,
            padding=(1, 1),
        )

        scope_panel = Panel(
            "\n".join(state.scope_lines or ["Scope information unavailable"]),
            title=f"[bold {self.theme['secondary']}]Scope[/]",
            border_style=self.theme["border"],
            box=box.ROUNDED,
            padding=(1, 1),
        )

        activity_panel = Panel(
            "\n".join(state.recent_events or ["Waiting for the first check to start"]),
            title=f"[bold {self.theme['secondary']}]Activity[/]",
            border_style=self.theme["border"],
            box=box.ROUNDED,
            padding=(1, 1),
        )

        layout = Layout(name="scan")
        layout.split_column(
            Layout(header, name="header", size=4),
            Layout(name="body", ratio=1),
            Layout(
                Panel(
                    Align.center(
                        Text(
                            "Scan is running in a full-screen workspace. Results will print when execution finishes.",
                            style=self.theme["muted"],
                        )
                    ),
                    border_style=self.theme["border"],
                    box=box.SQUARE,
                    padding=(0, 1),
                ),
                name="footer",
                size=3,
            ),
        )
        layout["body"].split_row(
            Layout(name="left", ratio=3),
            Layout(name="right", ratio=2),
        )
        layout["left"].split_column(
            Layout(hero, ratio=2),
            Layout(scope_panel, ratio=1),
        )
        layout["right"].split_column(
            Layout(checks_panel, ratio=2),
            Layout(activity_panel, ratio=1),
        )
        return layout

    @contextmanager
    def _mute_console_logging(self, logger: logging.Logger | None):
        """Mute console logging while the live workspace is active."""
        if logger is None:
            yield
            return

        original_levels: list[tuple[logging.Handler, int]] = []
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(
                handler, logging.FileHandler
            ):
                original_levels.append((handler, handler.level))
                handler.setLevel(logging.CRITICAL + 1)

        try:
            yield
        finally:
            for handler, level in original_levels:
                handler.setLevel(level)

    def run_with_progress(self, scan_func, *args, **kwargs) -> Any:
        """Run a task inside a full-screen live workspace."""
        from rich.live import Live

        logger = kwargs.get("logger")
        scope_summary = kwargs.pop("scope_summary", None)
        scope: Scope | None = kwargs.get("scope")
        config: Config | None = kwargs.get("config")
        skip_checks = kwargs.get("skip_checks")
        only_checks = kwargs.get("only_checks")

        selected_checks = (
            select_checks(config, skip_checks=skip_checks, only_checks=only_checks)
            if config is not None
            else []
        )
        state = ScanProgressState(
            mode_label=(config.scan.mode.replace("_", " ").title() if config else "Security Audit"),
            total_checks=len(selected_checks),
            current_message="Booting scan workspace",
            scope_lines=scope_summary.splitlines() if isinstance(scope_summary, str) else self._scope_lines(scope),
            check_names=[check_class.check_name for check_class in selected_checks],
        )
        if selected_checks:
            state.current_check_name = selected_checks[0].check_name

        lock = threading.Lock()
        stop_refresh = threading.Event()

        def progress_callback(payload: dict[str, Any]) -> None:
            with lock:
                event = payload.get("event")
                if event == "start":
                    state.total_checks = int(payload.get("total", state.total_checks))
                    state.current_message = "Launching checks"
                    state.push_event("Scan plan locked")
                elif event == "check_start":
                    state.current_check_name = str(payload.get("check_name", state.current_check_name))
                    state.current_message = f"Running {payload.get('check_id', 'check')}"
                    state.push_event(f"Started {state.current_check_name}")
                elif event == "check_end":
                    state.completed_checks = int(payload.get("current", state.completed_checks))
                    state.findings_count = int(payload.get("findings_count_total", state.findings_count))
                    state.errors_count = int(payload.get("errors_count_total", state.errors_count))
                    check_name = str(payload.get("check_name", "check"))
                    findings_count = int(payload.get("findings_count", 0))
                    status = str(payload.get("status", "ok"))
                    if status == "failed":
                        state.push_event(f"{check_name} failed")
                    elif findings_count > 0:
                        state.push_event(f"{check_name} finished with {findings_count} findings")
                    else:
                        state.push_event(f"{check_name} finished clean")
                    if state.completed_checks < len(state.check_names):
                        state.current_check_name = state.check_names[state.completed_checks]
                        state.current_message = "Preparing next check"
                elif event == "complete":
                    state.completed_checks = state.total_checks
                    state.findings_count = int(payload.get("findings_count", state.findings_count))
                    state.errors_count = int(payload.get("errors_count", state.errors_count))
                    state.current_message = "Audit complete"
                    state.finished = True
                    state.push_event("All checks completed")

        kwargs["progress_callback"] = progress_callback

        with self._mute_console_logging(logger):
            with Live(
                self._build_scan_layout(state),
                console=self.console,
                screen=True,
                auto_refresh=False,
                transient=True,
            ) as live:
                def refresh_loop() -> None:
                    while not stop_refresh.wait(0.08):
                        with lock:
                            live.update(self._build_scan_layout(state), refresh=True)

                refresher = threading.Thread(target=refresh_loop, daemon=True)
                refresher.start()

                try:
                    result = scan_func(*args, **kwargs)
                    with lock:
                        state.finished = True
                        state.current_message = "Rendering reports"
                        live.update(self._build_scan_layout(state), refresh=True)
                    time.sleep(0.35)
                    return result
                except Exception:
                    with lock:
                        state.failed = True
                        state.current_message = "Scan failed"
                        state.push_event("Execution stopped due to an exception")
                        live.update(self._build_scan_layout(state), refresh=True)
                    time.sleep(0.35)
                    raise
                finally:
                    stop_refresh.set()
                    refresher.join(timeout=1.0)

    def wait_for_user(self) -> bool:
        """Wait for the user to continue or exit."""
        self._show_screen(
            title="Scan Complete",
            body=Group(
                Text(
                    "The audit finished and reports have been written where configured.",
                    style=self.theme["text"],
                ),
                Text(
                    "You can launch another scan from this workspace immediately.",
                    style=self.theme["muted"],
                ),
            ),
            current_step=4,
            subtitle="Session wrap-up",
        )

        try:
            choice = Confirm.ask(
                "[bold #7dd3fc]▶[/] Another scan?",
                default=True,
            )
        except (KeyboardInterrupt, EOFError):
            self.console.print(
                f"\n[bold {self.theme['secondary']}]Exiting CACHE WRAITH. Stay safe.[/]"
            )
            return False

        if not choice:
            self.console.print(
                f"\n[bold {self.theme['secondary']}]Thank you for using CACHE WRAITH. Stay safe.[/]"
            )
            time.sleep(0.5)

        return choice
