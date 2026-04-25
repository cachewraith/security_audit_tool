"""Tests for TUI interaction behavior."""

from datetime import datetime
from types import SimpleNamespace

import pytest

from app.tui import NavigateBack, TUI
from app.models import AuditSummary, Category, ConfidenceLevel, Finding, SeverityLevel


class TestTUIInterrupts:
    """Tests for clean Ctrl+C handling in the TUI."""

    def test_wait_for_user_handles_keyboard_interrupt(self, monkeypatch) -> None:
        """Ctrl+C at the replay prompt should exit cleanly."""
        tui = TUI()

        def raise_interrupt(*args, **kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr(tui, "_prompt_ask", raise_interrupt)

        assert tui.wait_for_user() is False

    def test_wait_for_user_renders_findings_summary(self, monkeypatch) -> None:
        """Completion screen should show the findings that were detected."""
        tui = TUI()
        tui._last_summary = AuditSummary(
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
            target_count=1,
            findings=[
                Finding(
                    title="SQL Injection Vulnerability: example.com",
                    category=Category.APPLICATION,
                    severity=SeverityLevel.CRITICAL,
                    confidence=ConfidenceLevel.HIGH,
                    target="example.com",
                    evidence="SQL error found",
                    remediation="Use parameterized queries",
                ),
                Finding(
                    title="Missing recommended website security headers",
                    category=Category.WEBAPP_CONFIG,
                    severity=SeverityLevel.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    target="https://example.com",
                    evidence="Missing headers",
                    remediation="Add security headers",
                ),
            ],
        )

        captured = {}

        monkeypatch.setattr(
            tui,
            "_show_screen",
            lambda **kwargs: captured.update(kwargs),
        )
        monkeypatch.setattr(tui, "_prompt_ask", lambda *args, **kwargs: "q")

        assert tui.wait_for_user() is False

        console = tui.console
        with console.capture() as capture:
            console.print(captured["body"])
        rendered = capture.get()

        assert "SQL Injection Vulnerability: example.com" in rendered
        assert "Missing recommended website security headers" in rendered
        assert "CRITICAL" in rendered
        assert "MEDIUM" in rendered
        assert "finding number" in rendered.lower()

    def test_completion_body_handles_clean_scan(self) -> None:
        """Completion view should clearly report a clean scan."""
        tui = TUI()
        summary = AuditSummary(
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
            target_count=1,
        )

        body = tui._build_completion_body(summary)

        with tui.console.capture() as capture:
            tui.console.print(body)
        rendered = capture.get()

        assert "no findings were detected" in rendered.lower()
        assert "Findings" in rendered
        assert "0" in rendered
        assert "y to launch another scan" in rendered.lower()

    def test_finding_detail_body_shows_full_message(self) -> None:
        """Detail view should include the full evidence and remediation message."""
        tui = TUI()
        finding = Finding(
            title="Permissive CORS policy detected",
            category=Category.WEBAPP_CONFIG,
            severity=SeverityLevel.MEDIUM,
            confidence=ConfidenceLevel.HIGH,
            target="https://example.com",
            evidence="Access-Control-Allow-Origin allows * while credentials are enabled.",
            remediation="Restrict allowed origins and disable credentialed wildcard CORS.",
            references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
            check_id="website_risk",
            metadata={"owasp_top_10": ["A05:2021-Security Misconfiguration"]},
        )

        body = tui._build_finding_detail_body(finding, 1, 3)

        with tui.console.capture() as capture:
            tui.console.print(body)
        rendered = capture.get()

        assert "What We Found" in rendered
        assert "Access-Control-Allow-Origin allows * while credentials are enabled." in rendered
        assert "Recommended Fix" in rendered
        assert "Restrict allowed origins and disable credentialed wildcard CORS." in rendered
        assert "website_risk" in rendered

    def test_wait_for_user_can_open_finding_detail(self, monkeypatch) -> None:
        """Choosing a finding number should open the detail screen before returning."""
        tui = TUI()
        tui._last_summary = AuditSummary(
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
            target_count=1,
            findings=[
                Finding(
                    title="Missing recommended website security headers",
                    category=Category.WEBAPP_CONFIG,
                    severity=SeverityLevel.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    target="https://example.com",
                    evidence="Missing CSP and HSTS headers.",
                    remediation="Add the baseline security headers.",
                ),
            ],
        )

        seen_titles: list[str] = []
        answers = iter(["1", "y"])

        monkeypatch.setattr(
            tui,
            "_show_screen",
            lambda **kwargs: seen_titles.append(kwargs["title"]),
        )
        monkeypatch.setattr(tui, "_prompt_ask", lambda *args, **kwargs: next(answers))
        monkeypatch.setattr(tui, "_wait_for_enter", lambda *args, **kwargs: None)

        assert tui.wait_for_user() is True
        assert seen_titles == ["Scan Complete", "Finding Detail", "Scan Complete"]


class TestTUITextPrompt:
    """Tests for prompt-toolkit backed text entry."""

    def test_prompt_ask_accepts_default_choice(self, monkeypatch) -> None:
        """Empty input should fall back to the provided default."""
        tui = TUI()

        monkeypatch.setattr("app.tui.pt_prompt", lambda *args, **kwargs: "")

        assert tui._prompt_ask("Select mode", choices=["1", "2"], default="1") == "1"

    def test_prompt_ask_propagates_back_navigation(self, monkeypatch) -> None:
        """Ctrl+Left should surface as a back-navigation signal."""
        tui = TUI()

        def raise_back(*args, **kwargs):
            raise NavigateBack

        monkeypatch.setattr("app.tui.pt_prompt", raise_back)

        with pytest.raises(NavigateBack):
            tui._prompt_ask("Select mode", choices=["1", "2"], default="1")


class TestTUIIdentityHeader:
    """Tests for auth identity rendering in the TUI header."""

    def test_render_shell_shows_logged_in_email(self, monkeypatch) -> None:
        """Workspace header should show the saved login email in the top-right area."""
        monkeypatch.setattr(
            "app.tui.TokenStore.load",
            lambda _self: SimpleNamespace(user=SimpleNamespace(email="alice@example.com")),
        )

        tui = TUI()
        layout = tui._render_shell(
            title="Select Scan Mode",
            body="Body",
            current_step=0,
            subtitle="Subtitle",
        )

        with tui.console.capture() as capture:
            tui.console.print(layout)
        rendered = capture.get()

        assert "alice@example.com" in rendered
