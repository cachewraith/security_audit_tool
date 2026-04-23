"""Dashboard-style Terminal UI for the security audit tool."""

import sys
import time
from pathlib import Path
from typing import Optional, Tuple, Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.live import Live
from rich.align import Align
from rich.columns import Columns
from rich.table import Table
from rich import box

from .models import SeverityLevel, AuditSummary
from .report.terminal_reporter import TerminalReporter
from .config import Config
from .scope import ScopeManager

class TUI:
    """Professional Dashboard UI for interactive scans."""

    def __init__(self):
        self.console = Console()
        self.reporter = TerminalReporter(use_colors=sys.stdout.isatty())
        self.config = Config()

    def _get_header(self) -> Panel:
        """Create the dashboard header panel."""
        grid = Table.grid(expand=True)
        grid.add_column(justify="left", ratio=1)
        grid.add_column(justify="right", ratio=1)
        
        title = Text.assemble(
            ("🛡️  ", "bold blue"),
            ("SECURITY AUDIT TOOL", "bold cyan"),
        )
        version = Text("v1.0.1", "dim")
        
        grid.add_row(title, version)
        
        subtitle = Text("Authorized Use Only · Defensive Security Assessment", "dim italic")
        author = Text("Made by Somonor Hong", "bold blue")
        
        return Panel(
            Group(grid, subtitle, Text(""), author),
            style="white on blue",
            box=box.ROUNDED,
        )

    def _centered_input_box(self, title: str, subtitle: str = "") -> None:
        """Draw a centered input box layout."""
        self.console.clear()
        self.console.print(self._get_header())
        self.console.print("\n" * 2)
        
        panel_content = Text.assemble(
            (f"{title}\n", "bold white"),
            (f"{subtitle}", "dim") if subtitle else ""
        )
        
        self.console.print(
            Align.center(
                Panel(
                    panel_content,
                    width=80,
                    padding=(1, 2),
                    border_style="cyan",
                    box=box.DOUBLE,
                )
            )
        )

    def _select_mode(self) -> str:
        """Mode selection dashboard."""
        self.console.clear()
        self.console.print(self._get_header())
        self.console.print("\n")
        
        table = Table(box=box.SIMPLE, show_header=False, expand=True)
        table.add_column("Key", style="bold cyan", width=4)
        table.add_column("Mode", style="bold white", width=15)
        table.add_column("Description", style="dim")
        
        modes = [
            ("1", "Standard", "Safe, read-only checks (default)"),
            ("2", "Full Scan", "All checks including TLS and Banner grabbing"),
            ("3", "Pentest", "Comprehensive + Performance + Vulnerability tests"),
            ("4", "Custom", "Select specific checks (advanced)"),
        ]
        
        for k, m, d in modes:
            table.add_row(f"[{k}]", m, d)
            
        self.console.print(
            Align.center(
                Panel(
                    table,
                    title="[bold blue]Select Scan Mode[/]",
                    width=80,
                    padding=(1, 2),
                    border_style="blue",
                )
            )
        )
        
        choice = Prompt.ask("\n[bold cyan]❯[/] Select mode", choices=["1", "2", "3", "4"], default="1")
        mode_map = {"1": "Standard", "2": "Full Scan", "3": "Pentest", "4": "Custom"}
        return mode_map[choice]

    def run(self) -> Optional[Tuple[Config, ScopeManager, dict]]:
        """Run the interactive TUI flow."""
        self.console.clear()
        
        # 1. Welcome & URL Input
        self._centered_input_box(
            "Target Configuration",
            "Enter the URL or hostname you have permission to audit."
        )
        
        url = ""
        while not url:
            url = Prompt.ask("\n[bold cyan]❯[/] Target URL").strip()
            if not url:
                self.console.print("[red]Error: URL is required.[/]")

        # 2. Scan Mode
        mode = self._select_mode()
        
        extra_options = {"skip_checks": None, "only_checks": None}
        if mode == "Full Scan":
            self.config.check.tls_check = True
            self.config.check.enable_banner_grabbing = True
            self.config.check.performance_test = True
            self.config.check.vulnerability_scan = True
        elif mode == "Pentest":
            self.config.check.tls_check = True
            self.config.check.enable_banner_grabbing = True
            self.config.check.performance_test = True
            self.config.check.vulnerability_scan = True
            self.config.check.load_test = True
            self.config.output.verbose = True
        elif mode == "Custom":
            self._centered_input_box("Custom Scan Configuration")
            only = Prompt.ask("[bold cyan]❯[/] Only run checks (comma-separated, empty for all)")
            if only:
                extra_options["only_checks"] = only
            else:
                skip = Prompt.ask("[bold cyan]❯[/] Skip checks (comma-separated)")
                if skip:
                    extra_options["skip_checks"] = skip

        # 3. Reports
        self._centered_input_box("Reporting Options")
        save_report = Confirm.ask("\n[bold cyan]❯[/] Save findings to report files?", default=True)
        if save_report:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            self.config.output.json_report_path = Path(f"audit_report_{timestamp}.json")
            self.config.output.html_report_path = Path(f"audit_report_{timestamp}.html")
            downloads = Path.home() / "Downloads"
            if downloads.exists():
                self.config.output.pdf_report_path = downloads / f"audit_report_{timestamp}.pdf"
            else:
                self.config.output.pdf_report_path = Path(f"audit_report_{timestamp}.pdf")
            
            self.console.print(f"\n[dim]Reports will be saved as audit_report_{timestamp}.*[/]")

        # 4. Authorization
        from .cli import LEGAL_WARNING
        self.console.clear()
        self.console.print(self._get_header())
        self.console.print("\n" * 2)
        
        warning_panel = Panel(
            Align.center(
                Group(
                    Text("⚠️  LEGAL DISCLAIMER  ⚠️", style="bold red underline", justify="center"),
                    Text("\n"),
                    Text.from_markup(LEGAL_WARNING.strip())
                )
            ),
            border_style="red",
            padding=(2, 4),
            box=box.HEAVY,
            width=90,
        )
        self.console.print(Align.center(warning_panel))
        self.console.print("\n")
        
        # Print centered question separately
        self.console.print(Align.center("[bold white]Do you have explicit authorization to audit this target?[/]"))
        
        # Simple prompt for the Y/N input
        auth = Confirm.ask(
            "[bold cyan]❯[/]", 
            default=False,
            show_default=True
        )
        if not auth:
            self.console.print("\n[bold red]⛔ Authorization required to proceed. Exiting.[/]")
            return None

        self.config.authorization_confirmed = True

        # Build scope
        try:
            scope_manager = ScopeManager.from_args(urls=[url])
            if not scope_manager.validate():
                for error in scope_manager.validation_errors:
                    self.console.print(f"[red]Scope Error: {error}[/]")
                return None
        except Exception as e:
            self.console.print(f"[red]Error building scope: {e}[/]")
            return None

        self.console.print("\n[bold green]✅ Setup complete. Initializing scanner...[/]\n")
        time.sleep(1)
        return self.config, scope_manager, extra_options

    def run_with_progress(self, scan_func, *args, **kwargs) -> Any:
        """Run a task with a rich progress dashboard."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
            expand=True,
        ) as progress:
            task = progress.add_task("[cyan]Scanning security targets...", total=100)
            
            # We wrap the actual scan_func
            # Since scan_func is synchronous and doesn't yield progress yet,
            # we just show an indeterminate pulse for now or pulse the bar
            progress.tasks[task].total = None # Indeterminate
            
            result = scan_func(*args, **kwargs)
            
            progress.update(task, completed=100, description="[green]Audit complete!")
            return result

    def wait_for_user(self) -> bool:
        """Wait for user to decide whether to continue or exit."""
        self.console.print("\n" + "━" * 80)
        self.console.print(Align.center("[bold green]✨ Security Audit Successfully Completed! ✨[/]"))
        self.console.print("━" * 80 + "\n")
        
        self.console.print("[dim]You can find your reports in the project folder and PDF in Downloads.[/]\n")
        
        choice = Confirm.ask("[bold cyan]❯[/] Would you like to perform another scan?", default=True)
        if not choice:
            self.console.print("\n[bold blue]Thank you for using Security Audit Tool. Stay safe![/]")
            time.sleep(1)
            
        return choice
