from __future__ import annotations

import itertools
import re
import shutil
import sys
import threading
import time
import textwrap
from contextlib import contextmanager
from typing import Iterator, TextIO

from ..models import AuditSummary, Finding, SeverityLevel


class TerminalReporter:
    """Clean terminal reporter with wrapping text and animated loading."""

    ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[38;5;196m"
    ORANGE = "\033[38;5;214m"
    YELLOW = "\033[38;5;220m"
    GREEN = "\033[38;5;82m"
    CYAN = "\033[38;5;81m"
    BLUE = "\033[38;5;117m"
    PURPLE = "\033[38;5;141m"
    GRAY = "\033[38;5;245m"
    SILVER = "\033[38;5;250m"
    WHITE = "\033[97m"

    SEVERITY_STYLE = {
        SeverityLevel.CRITICAL: {"color": RED, "icon": "⛔", "label": "CRITICAL"},
        SeverityLevel.HIGH: {"color": ORANGE, "icon": "🔥", "label": "HIGH"},
        SeverityLevel.MEDIUM: {"color": YELLOW, "icon": "⚡", "label": "MEDIUM"},
        SeverityLevel.LOW: {"color": GREEN, "icon": "✅", "label": "LOW"},
        SeverityLevel.INFO: {"color": BLUE, "icon": "ℹ", "label": "INFO"},
    }

    SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, use_colors: bool = True, width: int = 100):
        self.use_colors = use_colors
        self.width = width
        self._spinner_thread: threading.Thread | None = None
        self._spinner_stop = threading.Event()
        self._spinner_stream: TextIO = sys.stderr
        self._spinner_message = ""
        self._spinner_interval = 0.08

    # ----------------------------
    # basic helpers
    # ----------------------------
    def _c(self, text: str, color: str) -> str:
        if not self.use_colors:
            return text
        return f"{color}{text}{self.RESET}"

    def _plain(self, text: str) -> str:
        return self.ANSI_RE.sub("", text)

    def _plain_len(self, text: str) -> int:
        return len(self._plain(text))

    def _term_width(self) -> int:
        return shutil.get_terminal_size((self.width, 24)).columns

    def _effective_width(self) -> int:
        return max(72, min(self.width, self._term_width()))

    def _hr(self, char: str = "─", color: str | None = None) -> str:
        line = char * self._effective_width()
        return self._c(line, color) if color else line

    def _pad(self, text: str, width: int) -> str:
        return text + (" " * max(0, width - self._plain_len(text)))

    def _wrap_plain(self, text: str, width: int, initial_indent: str = "", subsequent_indent: str = "") -> list[str]:
        if not text:
            return [initial_indent.rstrip()]
        wrapped = textwrap.wrap(
            text,
            width=width,
            initial_indent=initial_indent,
            subsequent_indent=subsequent_indent,
            replace_whitespace=False,
            drop_whitespace=False,
            break_long_words=True,
            break_on_hyphens=False,
        )
        return wrapped or [initial_indent.rstrip()]

    def _box(self, lines: list[str], color: str | None = None) -> str:
        width = self._effective_width()
        inner = width - 4
        top = f"┌{'─' * (width - 2)}┐"
        bottom = f"└{'─' * (width - 2)}┘"
        out = [self._c(top, color) if color else top]
        for line in lines:
            out.append(f"│ {self._pad(line, inner)} │")
        out.append(self._c(bottom, color) if color else bottom)
        return "\n".join(out)

    def _section(self, title: str, color: str, icon: str = "") -> str:
        label = f"{icon} {title}".strip()
        return self._c(label, f"{self.BOLD}{color}")

    def _kv_block(self, items: list[tuple[str, str]], color: str | None = None) -> str:
        lines: list[str] = []
        width = self._effective_width() - 6
        for key, value in items:
            prefix = f"{key}: "
            wrapped = self._wrap_plain(value, width, initial_indent=prefix, subsequent_indent=" " * len(prefix))
            lines.extend(wrapped)
        return self._box(lines, color=color)

    # ----------------------------
    # header / summary
    # ----------------------------
    def _header(self) -> str:
        width = self._effective_width()
        title = "SECURITY AUDIT TOOL"
        subtitle = "Authorized Use Only · Defensive Scanner"

        title_line = title.center(width)
        subtitle_line = subtitle.center(width)

        return "\n".join([
            self._c(title_line, f"{self.BOLD}{self.CYAN}"),
            self._c(subtitle_line, self.GRAY),
            self._c("═" * width, self.GRAY),
        ])

    def _severity_summary(self, summary: AuditSummary) -> str:
        counts = summary.count_by_severity()
        parts = []
        for sev in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO]:
            count = counts.get(sev, 0)
            if count <= 0:
                continue
            style = self.SEVERITY_STYLE.get(sev, {"color": self.GRAY, "icon": "•", "label": sev.value.upper()})
            parts.append(self._c(f"{style['icon']} {style['label']}: {count}", style["color"]))
        if not parts:
            parts.append(self._c("✅ No findings", self.GREEN))
        return "   ".join(parts)

    # ----------------------------
    # finding formatting
    # ----------------------------
    def _wrap_field(self, label: str, text: str, width: int) -> list[str]:
        lines: list[str] = []
        raw_lines = (text or "").splitlines() or [""]
        prefix = f"{label}: "
        for idx, raw in enumerate(raw_lines):
            initial = prefix if idx == 0 else " " * len(prefix)
            wrapped = self._wrap_plain(raw, width, initial_indent=initial, subsequent_indent=" " * len(prefix))
            lines.extend(wrapped)
        return lines

    def _bullet_block(self, label: str, text: str, width: int, bullet_color: str) -> list[str]:
        lines: list[str] = []
        title = self._c(label, f"{self.BOLD}{bullet_color}")
        lines.append(title)
        raw_lines = (text or "").splitlines()

        if not raw_lines:
            lines.append("  -")
            return lines

        for raw in raw_lines:
            if not raw.strip():
                lines.append("")
                continue
            wrapped = self._wrap_plain(
                raw.strip(),
                width,
                initial_indent="  • ",
                subsequent_indent="    ",
            )
            lines.extend(wrapped)
        return lines

    def _finding_card(self, finding: Finding, index: int, total: int) -> str:
        style = self.SEVERITY_STYLE.get(
            finding.severity,
            {"color": self.GRAY, "icon": "•", "label": finding.severity.value.upper()},
        )
        color = style["color"]
        width = self._effective_width() - 6

        header = f"[{index}/{total}] {style['icon']} {style['label']}  {finding.title}"
        lines: list[str] = []
        lines.extend(self._wrap_plain(header, width))
        lines.append("")

        meta_parts = [
            ("Target", str(finding.target)),
            ("Category", str(finding.category.value)),
            ("Check", str(finding.check_id)),
            ("ID", str(finding.id)),
        ]
        for key, value in meta_parts:
            lines.extend(self._wrap_field(key, value, width))

        lines.append("")
        lines.extend(self._bullet_block("Evidence", finding.evidence or "", width, self.BLUE))
        lines.append("")
        lines.extend(self._bullet_block("Remediation", finding.remediation or "", width, self.GREEN))

        return self._box(lines, color=color)

    # ----------------------------
    # main report
    # ----------------------------
    def generate(self, summary: AuditSummary, output: TextIO | None = None) -> str:
        lines: list[str] = []

        lines.append(self._header())
        lines.append("")

        lines.append(self._section("SUMMARY", self.CYAN))
        lines.append(
            self._kv_block(
                [
                    ("Findings", str(len(summary.findings))),
                    ("Targets", str(summary.target_count)),
                    ("Duration", f"{summary.duration_seconds:.2f}s"),
                    ("Errors", str(len(summary.errors))),
                ],
                color=self.GRAY,
            )
        )
        lines.append("")

        lines.append(self._section("SEVERITY BREAKDOWN", self.ORANGE))
        lines.append(self._severity_summary(summary))
        lines.append(self._c("─" * self._effective_width(), self.GRAY))
        lines.append("")

        if summary.findings:
            lines.append(self._section("DETAILED FINDINGS", self.PURPLE))
            lines.append("")

            severity_order = {
                SeverityLevel.CRITICAL: 0,
                SeverityLevel.HIGH: 1,
                SeverityLevel.MEDIUM: 2,
                SeverityLevel.LOW: 3,
                SeverityLevel.INFO: 4,
            }

            sorted_findings = sorted(
                summary.findings,
                key=lambda f: (severity_order.get(f.severity, 99), f.category.value),
            )

            for i, finding in enumerate(sorted_findings, 1):
                lines.append(self._finding_card(finding, i, len(sorted_findings)))
                if i < len(sorted_findings):
                    lines.append("")

        if summary.errors:
            lines.append("")
            lines.append(self._section("ERRORS", self.RED))
            error_lines: list[str] = []
            width = self._effective_width() - 6
            for err in summary.errors:
                error_lines.extend(
                    self._wrap_plain(err, width, initial_indent="• ", subsequent_indent="  ")
                )
            lines.append(self._box(error_lines, color=self.RED))

        lines.append("")
        lines.append(self._c("Audit completed successfully", self.GREEN))

        output_text = "\n".join(lines)
        if output:
            output.write(output_text + "\n")
        return output_text

    def print_summary_only(self, summary: AuditSummary) -> str:
        lines = [
            self._header(),
            "",
            self._kv_block(
                [
                    ("Findings", str(len(summary.findings))),
                    ("Targets", str(summary.target_count)),
                    ("Duration", f"{summary.duration_seconds:.2f}s"),
                ],
                color=self.GRAY,
            ),
            "",
            self._severity_summary(summary),
        ]
        return "\n".join(lines)

    # ----------------------------
    # loading animation
    # ----------------------------
    def _progress_line(self, frame: str, message: str, elapsed: float) -> str:
        width = self._term_width()
        spinner = self._c(frame, self.CYAN)
        timer = self._c(f"{elapsed:5.1f}s", self.GRAY)
        text = f"{spinner} {message} {timer}"
        plain_len = self._plain_len(text)
        if plain_len < width - 1:
            text += " " * (width - plain_len - 1)
        return "\r" + text

    def start_loading(
        self,
        message: str = "Running security audit...",
        stream: TextIO | None = None,
        interval: float = 0.08,
    ) -> None:
        self.stop_loading(clear=True)
        self._spinner_stream = stream or sys.stderr
        self._spinner_message = message
        self._spinner_interval = interval
        self._spinner_stop.clear()

        def _spin() -> None:
            start = time.perf_counter()
            for frame in itertools.cycle(self.SPINNER_FRAMES):
                if self._spinner_stop.is_set():
                    break
                elapsed = time.perf_counter() - start
                self._spinner_stream.write(self._progress_line(frame, self._spinner_message, elapsed))
                self._spinner_stream.flush()
                time.sleep(self._spinner_interval)

        self._spinner_thread = threading.Thread(target=_spin, daemon=True)
        self._spinner_thread.start()

    def update_loading(self, message: str) -> None:
        self._spinner_message = message

    def stop_loading(self, final_message: str | None = None, clear: bool = False) -> None:
        if self._spinner_thread is None:
            return

        self._spinner_stop.set()
        self._spinner_thread.join(timeout=1.0)
        self._spinner_thread = None

        width = self._term_width()
        if clear:
            self._spinner_stream.write("\r" + (" " * (width - 1)) + "\r")
        elif final_message:
            line = f"\r{self._c('✔', self.GREEN)} {final_message}"
            plain_len = self._plain_len(line)
            if plain_len < width - 1:
                line += " " * (width - plain_len - 1)
            self._spinner_stream.write(line + "\n")
        else:
            self._spinner_stream.write("\n")
        self._spinner_stream.flush()

    @contextmanager
    def loading(
        self,
        message: str = "Running security audit...",
        stream: TextIO | None = None,
        success_message: str = "Audit completed",
    ) -> Iterator[None]:
        self.start_loading(message=message, stream=stream)
        try:
            yield
        finally:
            self.stop_loading(final_message=success_message)