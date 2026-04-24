"""CACHE WRAITH - Cyberpunk-style Terminal UI for the security audit tool."""

import re
import sys
import time
from importlib.metadata import PackageNotFoundError, version as get_package_version
from pathlib import Path
from typing import Any, Optional, Tuple

from prompt_toolkit import prompt as pt_prompt
from prompt_toolkit.formatted_text import ANSI
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
from .core.scan_modes import SCAN_MODE_DEFINITIONS, apply_scan_mode
from .models import ScanMode
from .report.terminal_reporter import TerminalReporter
from .utils import validate_url, validate_host
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

    def _prompt_ask(
        self,
        message: str,
        choices: Optional[list[str]] = None,
        default: Optional[str] = None,
    ) -> str:
        """Prompt for text input with Ctrl+C handling."""
        try:
            while True:
                prompt_text = f"\n\033[96m▶\033[0m {self._plain_prompt_message(message)}"
                if default is not None:
                    prompt_text += f" [{default}]"
                prompt_text += ": "

                value = pt_prompt(
                    ANSI(prompt_text),
                    default=default or "",
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

        except (KeyboardInterrupt, EOFError):
            self._handle_interrupt()
            raise

    def _confirm_ask(self, *args, **kwargs) -> bool:
        """Prompt for confirmation with Ctrl+C handling."""
        try:
            return Confirm.ask(*args, **kwargs)
        except (KeyboardInterrupt, EOFError):
            self._handle_interrupt()
            raise

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

        choice = Prompt.ask(
            f"\n[bold {self.theme['prompt']}]▶[/] Select mode",
            choices=["1", "2", "3", "4"],
            default="1",
        )

        for definition in SCAN_MODE_DEFINITIONS:
            if definition.key == choice:
                return definition.mode

        raise ValueError(f"Unknown mode selection: {choice}")

    def run(self) -> Optional[Tuple[Config, ScopeManager, dict]]:
        """Run the interactive TUI flow."""
        try:
            self.console.clear()
            self._print_banner()

            # 1. Welcome & URL Input
            self._centered_info_box(
                "Target Configuration",
                "Enter the URL (e.g., https://example.com) or hostname (e.g., example.com) you have permission to audit.",
            )

            url = ""
            while not url:
                url = Prompt.ask(
                    f"[bold {self.theme['prompt']}]▶[/] Target URL or Hostname"
                ).strip()
                if not url:
                    self.console.print(
                        f"[{self.theme['error']}]◈ Error: URL is required ◈[/]"
                    )
                    continue

                # Validate the URL or hostname
                validation_errors = validate_url(url, allowed_schemes=["http", "https"])

                # If URL validation fails due to missing scheme, try hostname validation
                if validation_errors and "missing scheme" in " ".join(validation_errors).lower():
                    validation_errors = validate_host(url)

                if validation_errors:
                    self.console.print(
                        f"[{self.theme['error']}]◈ Invalid target: {', '.join(validation_errors)} ◈[/]"
                    )
                    url = ""
                    continue

            # 2. Scan Mode
            self.console.clear()
            self._print_banner()
            mode = self._select_mode()
            apply_scan_mode(self.config, mode)

            extra_options = {"skip_checks": None, "only_checks": None}

            if mode == ScanMode.CUSTOM:
                self.console.clear()
                self._print_banner()
                self._centered_info_box("Custom Scan Configuration")

                only = Prompt.ask(
                    f"[bold {self.theme['prompt']}]▶[/] Only run checks "
                    "(comma-separated, empty for all)",
                    default="",
                ).strip()

                if only:
                    extra_options["only_checks"] = only
                else:
                    skip = Prompt.ask(
                        f"[bold {self.theme['prompt']}]▶[/] Skip checks "
                        "(comma-separated)",
                        default="",
                    ).strip()

                    if skip:
                        extra_options["skip_checks"] = skip

            # 3. Reports
            self.console.clear()
            self._print_banner()
            self._centered_info_box("Reporting Options")

            save_report = Confirm.ask(
                f"\n[bold {self.theme['prompt']}]▶[/] Save findings to report files?",
                default=True,
            )

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

            # 4. Authorization
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

            auth = Confirm.ask(
                f"[bold {self.theme['prompt']}]▶[/]",
                default=False,
                show_default=True,
            )

            if not auth:
                self.console.print(
                    f"\n[bold {self.theme['error']}]◈ Authorization required. Exiting. ◈[/]"
                )
                return None

            self.config.authorization_confirmed = True

            scope_manager = ScopeManager.from_args(urls=[url])
            if not scope_manager.validate():
                for error in scope_manager.validation_errors:
                    self.console.print(
                        f"[{self.theme['error']}]◈ Scope Error: {error} ◈[/]"
                    )
                return None

        except (KeyboardInterrupt, EOFError):
            return None
        except Exception as e:
            self.console.print(f"[{self.theme['error']}]◈ Error: {e} ◈[/]")
            return None

        self.console.print(
            f"\n[bold {self.theme['success']}]◈ Setup complete. Initializing CACHE WRAITH... ◈[/]\n"
        )
        time.sleep(1)

        return self.config, scope_manager, extra_options

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