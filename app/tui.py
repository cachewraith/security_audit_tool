"""CACHE WRAITH - Cyberpunk-style Terminal UI for the security audit tool."""

import re
import sys
import time
from importlib.metadata import PackageNotFoundError, version as get_package_version
from pathlib import Path
from typing import Any, Optional, Tuple

from prompt_toolkit import prompt as pt_prompt
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.key_binding import KeyBindings
from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from .config import Config
from .core.scan_modes import SCAN_MODE_DEFINITIONS, apply_scan_mode, enable_checks
from .models import ScanMode
from .report.terminal_reporter import TerminalReporter
from .utils import validate_url, validate_host, validate_path
from .scope import ScopeManager


THEME = {
    "primary": "bright_cyan",
    "secondary": "bright_blue",
    "accent": "bright_magenta",
    "success": "bright_green",
    "warning": "bright_yellow",
    "error": "bright_red",
    "text": "bright_white",
    "dim": "cyan",
    "border": "cyan",
    "prompt": "bright_cyan",
}


class NavigateBack(Exception):
    """Raised when the user requests to go back to the previous step."""


class TUI:
    """Cyberpunk dashboard UI for interactive scans."""

    RICH_TAG_RE = re.compile(r"\[/?[^\]]+\]")

    def __init__(self):
        self.console = Console()
        self.reporter = TerminalReporter(use_colors=sys.stdout.isatty())
        self.config = Config()
        self.theme = THEME

    def _print_banner(self) -> None:
        """Print CACHE WRAITH banner."""
        banner = r"""
 ██████╗ █████╗  ██████╗██╗  ██╗███████╗    ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
██╔════╝██╔══██╗██╔════╝██║  ██║██╔════╝    ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║
██║     ███████║██║     ███████║█████╗      ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
██║     ██╔══██║██║     ██╔══██║██╔══╝      ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║
╚██████╗██║  ██║╚██████╗██║  ██║███████╗    ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║
 ╚═════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝     ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
"""
        self.console.print(
            Align.center(Text(banner, style=f"bold {self.theme['primary']}"))
        )
        subtitle = Text(
            "▛▜  CACHE WRAITH SECURITY AUDIT TOOL  ▛▜",
            style=f"bold {self.theme['secondary']}",
        )
        self.console.print(Align.center(subtitle))
        self.console.print()

    def _get_header(self) -> Panel:
        """Create header panel."""
        grid = Table.grid(expand=True)
        grid.add_column(justify="left", ratio=1)
        grid.add_column(justify="right", ratio=1)

        title = Text.assemble(
            ("🛡 ", f"bold {self.theme['primary']}"),
            ("CACHE WRAITH", f"bold {self.theme['text']}"),
        )

        try:
            version_str = get_package_version("cache-wraith-audit-tool")
        except PackageNotFoundError:
            version_str = "1.0.4"

        version = Text(f"v{version_str}", self.theme["dim"])
        grid.add_row(title, version)

        subtitle = Text(
            "► AUTHORIZED USE ONLY • DEFENSIVE SECURITY ◄",
            style=f"bold {self.theme['dim']}",
        )
        author = Text(
            "Made by Somonor Hong",
            style=f"bold {self.theme['secondary']}",
        )

        return Panel(
            Group(grid, subtitle, Text(""), author),
            border_style=self.theme["border"],
            box=box.ROUNDED,
        )

    def _centered_info_box(self, title: str, subtitle: str = "") -> None:
        """Draw a centered info box without fake input preview."""
        self.console.print(self._get_header())
        self.console.print()

        content = [
            Text(f"▶ {title.upper()}", style=f"bold {self.theme['primary']}")
        ]

        if subtitle:
            content.append(Text(f"  {subtitle}", style=self.theme["dim"]))

        self.console.print(
            Align.center(
                Panel(
                    Group(*content),
                    width=80,
                    padding=(1, 2),
                    border_style=self.theme["border"],
                    box=box.ROUNDED,
                )
            )
        )

    def _handle_interrupt(self, message: str = "Operation cancelled by user.") -> None:
        """Render cancellation message."""
        self.console.print(f"\n[{self.theme['warning']}]◈ {message} ◈[/]")

    def _plain_prompt_message(self, message: str) -> str:
        """Remove Rich tags for prompt_toolkit."""
        return self.RICH_TAG_RE.sub("", message).strip()

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
                    "\033[36m(Ctrl+Left to go back)\033[0m"
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
                            f"[{self.theme['error']}]◈ Invalid choice. Choose: {valid} ◈[/]"
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
        self.console.print(self._get_header())
        self.console.print()

        table = Table(box=box.SIMPLE, show_header=False, expand=True)
        table.add_column("Key", style=f"bold {self.theme['primary']}", width=4)
        table.add_column("Mode", style=f"bold {self.theme['text']}", width=18)
        table.add_column("Description", style=self.theme["dim"])

        for definition in SCAN_MODE_DEFINITIONS:
            table.add_row(
                f"[{definition.key}]",
                definition.label,
                definition.description,
            )

        self.console.print(
            Align.center(
                Panel(
                    table,
                    title=f"[bold {self.theme['secondary']}]◈ SELECT SCAN MODE ◈[/]",
                    width=90,
                    padding=(1, 2),
                    border_style=self.theme["border"],
                )
            )
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

    def _prompt_url_target(self, title: str, subtitle: str) -> str:
        """Prompt for a live website/API target."""
        self.console.clear()
        self._print_banner()
        self._centered_info_box(title, subtitle)

        target = ""
        while not target:
            target = self._prompt_ask("Target URL or Hostname").strip()
            if not target:
                self.console.print(
                    f"[{self.theme['error']}]◈ Error: target is required ◈[/]"
                )
                continue

            validation_errors = validate_url(target, allowed_schemes=["http", "https"])
            if validation_errors and "missing scheme" in " ".join(validation_errors).lower():
                validation_errors = validate_host(target)

            if validation_errors:
                self.console.print(
                    f"[{self.theme['error']}]◈ Invalid target: {', '.join(validation_errors)} ◈[/]"
                )
                target = ""

        return target

    def _prompt_project_path(self, title: str, subtitle: str) -> Path:
        """Prompt for a project directory path."""
        self.console.clear()
        self._print_banner()
        self._centered_info_box(title, subtitle)

        while True:
            raw_path = self._prompt_ask(
                f"[bold {self.theme['prompt']}]▶[/] Project directory",
            )
            path = Path(raw_path).expanduser()
            errors = validate_path(path, must_exist=True, must_be_dir=True)
            if errors:
                self.console.print(
                    f"[{self.theme['error']}]◈ Invalid path: {', '.join(errors)} ◈[/]"
                )
                continue
            return path.resolve()

    def _select_custom_target_type(self) -> str:
        """Prompt for the custom target family."""
        self.console.clear()
        self._print_banner()

        table = Table(box=box.SIMPLE, show_header=False, expand=True)
        table.add_column("Key", style=f"bold {self.theme['primary']}", width=4)
        table.add_column("Target", style=f"bold {self.theme['text']}", width=18)
        table.add_column("Description", style=self.theme["dim"])
        table.add_row("[1]", "Website/API", "Use a URL or hostname target")
        table.add_row("[2]", "Codebase", "Use a project directory target")
        table.add_row("[3]", "Host", "Audit the local machine")
        table.add_row("[4]", "Containers", "Use container config files and optional local containers")

        self.console.print(
            Align.center(
                Panel(
                    table,
                    title=f"[bold {self.theme['secondary']}]◈ CUSTOM TARGET TYPE ◈[/]",
                    width=90,
                    padding=(1, 2),
                    border_style=self.theme["border"],
                )
            )
        )

        return self._prompt_ask(
            "Select target type",
            choices=["1", "2", "3", "4"],
            default="1",
        )

    def _collect_scope_for_mode(self, mode: ScanMode) -> tuple[ScopeManager, str]:
        """Collect the appropriate scope for the selected mode."""
        if mode == ScanMode.WEBSITE_REVIEW:
            target = self._prompt_url_target(
                "Website Target",
                "Enter the website URL or hostname you want to review.",
            )
            return ScopeManager.from_args(urls=[target]), "website"

        if mode == ScanMode.API_REVIEW:
            target = self._prompt_url_target(
                "API Target",
                "Enter the API base URL or endpoint you want to review.",
            )
            return ScopeManager.from_args(urls=[target]), "api"

        if mode == ScanMode.RESILIENCE_TEST:
            target = self._prompt_url_target(
                "Resilience Target",
                "Enter the URL or hostname to measure for performance and bounded load.",
            )
            return ScopeManager.from_args(urls=[target]), "website"

        if mode == ScanMode.CODEBASE_REVIEW:
            path = self._prompt_project_path(
                "Codebase Target",
                "Choose the project directory to scan for secrets, dependencies, and config risks.",
            )
            return ScopeManager.from_args(paths=[path]), "codebase"

        if mode == ScanMode.HOST_HARDENING:
            self.console.clear()
            self._print_banner()
            self._centered_info_box(
                "Host Hardening Target",
                "This mode audits the local machine for permissions, services, firewall, and hardening issues.",
            )
            return ScopeManager.from_args(local=True), "host"

        if mode == ScanMode.CONTAINER_REVIEW:
            path = self._prompt_project_path(
                "Container Target",
                "Choose the project directory that contains Docker or container configuration files.",
            )
            inspect_local = self._confirm_ask(
                f"\n[bold {self.theme['prompt']}]▶[/] Inspect running local containers too?",
                default=True,
            )
            return ScopeManager.from_args(paths=[path], local=inspect_local), "container"

        if mode == ScanMode.CUSTOM:
            target_type = self._select_custom_target_type()
            if target_type == "1":
                target = self._prompt_url_target(
                    "Custom Website/API Target",
                    "Enter the URL or hostname for your custom review.",
                )
                return ScopeManager.from_args(urls=[target]), "website"
            if target_type == "2":
                path = self._prompt_project_path(
                    "Custom Codebase Target",
                    "Choose the project directory for your custom review.",
                )
                return ScopeManager.from_args(paths=[path]), "codebase"
            if target_type == "3":
                self.console.clear()
                self._print_banner()
                self._centered_info_box(
                    "Custom Host Target",
                    "This custom review will audit the local machine.",
                )
                return ScopeManager.from_args(local=True), "host"

            path = self._prompt_project_path(
                "Custom Container Target",
                "Choose the project directory that contains container configuration files.",
            )
            inspect_local = self._confirm_ask(
                f"\n[bold {self.theme['prompt']}]▶[/] Inspect running local containers too?",
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

    def run(self) -> Optional[Tuple[Config, ScopeManager, dict]]:
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
                    self.console.clear()
                    self._print_banner()
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
                        for error in scope_manager.validation_errors:
                            self.console.print(
                                f"[{self.theme['error']}]◈ Scope Error: {error} ◈[/]"
                            )
                        continue

                    extra_options = {"skip_checks": None, "only_checks": None}
                    step = 2 if mode == ScanMode.CUSTOM else 3
                    continue

                if step == 2:
                    self._apply_custom_defaults(target_family)
                    self.console.clear()
                    self._print_banner()
                    self._centered_info_box("Custom Scan Configuration")

                    only = self._prompt_ask(
                        "Only run checks (comma-separated, empty for all)",
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
                    self.console.clear()
                    self._print_banner()
                    self._centered_info_box("Reporting Options")

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
                            f"\n[{self.theme['dim']}]◈ Reports saved as: audit_report_{timestamp}.* ◈[/]"
                        )

                    step = 4
                    continue

                if step == 4:
                    from .cli import LEGAL_WARNING

                    self.console.clear()
                    self.console.print(self._get_header())
                    self.console.print()

                    warning_panel = Panel(
                        Align.center(
                            Group(
                                Text(
                                    "◈◈◈  LEGAL DISCLAIMER  ◈◈◈",
                                    style=f"bold {self.theme['error']} underline",
                                    justify="center",
                                ),
                                Text("\n"),
                                Text.from_markup(LEGAL_WARNING.strip()),
                            )
                        ),
                        border_style=self.theme["error"],
                        padding=(2, 4),
                        box=box.HEAVY,
                        width=96,
                    )

                    self.console.print(Align.center(warning_panel))
                    self.console.print()

                    self.console.print(
                        Align.center(
                            f"[bold {self.theme['text']}]◈ Do you have explicit authorization to audit this target? ◈[/]"
                        )
                    )

                    auth = self._confirm_ask(
                        "Do you have explicit authorization to audit this target?",
                        default=False,
                    )

                    if not auth:
                        self.console.print(
                            f"\n[bold {self.theme['error']}]◈ Authorization required. Exiting. ◈[/]"
                        )
                        return None

                    self.config.authorization_confirmed = True

                    self.console.print(
                        f"\n[bold {self.theme['success']}]◈ Setup complete. Initializing CACHE WRAITH... ◈[/]\n"
                    )
                    time.sleep(1)
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
                self.console.print(f"[{self.theme['error']}]◈ Error: {e} ◈[/]")
                return None

    def run_with_progress(self, scan_func, *args, **kwargs) -> Any:
        """Run a task with a progress dashboard."""
        with Progress(
            SpinnerColumn(style=self.theme["primary"]),
            TextColumn(f"[bold {self.theme['primary']}]{{task.description}}[/]"),
            BarColumn(
                bar_width=None,
                complete_style=self.theme["success"],
                finished_style=self.theme["primary"],
            ),
            TextColumn("[{task.percentage:>3.0f}%]", style=self.theme["dim"]),
            TimeElapsedColumn(),
            console=self.console,
            expand=True,
        ) as progress:
            task = progress.add_task("◈ Scanning security targets...", total=100)
            progress.tasks[task].total = None

            result = scan_func(*args, **kwargs)

            progress.update(
                task,
                completed=100,
                description=f"[{self.theme['success']}]◈ Audit complete! ◈[/]",
            )

            return result

    def wait_for_user(self) -> bool:
        """Wait for user to continue or exit."""
        self.console.print()
        self.console.print(
            Align.center(
                f"[bold {self.theme['success']}]◈◈◈ CACHE WRAITH AUDIT COMPLETED ◈◈◈[/]"
            )
        )
        self.console.print()

        self.console.print(
            f"[{self.theme['dim']}]◈ Reports in project folder | PDF in Downloads ◈[/]\n"
        )

        try:
            choice = Confirm.ask(
                f"[bold {self.theme['prompt']}]▶[/] Another scan?",
                default=True,
            )
        except (KeyboardInterrupt, EOFError):
            self.console.print(
                f"\n[bold {self.theme['secondary']}]◈ Exiting CACHE WRAITH. Stay safe! ◈[/]"
            )
            return False

        if not choice:
            self.console.print(
                f"\n[bold {self.theme['secondary']}]◈ Thank you for using CACHE WRAITH. Stay safe! ◈[/]"
            )
            time.sleep(1)

        return choice
