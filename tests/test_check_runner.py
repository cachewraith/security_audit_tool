"""Tests for check execution progress updates."""

from __future__ import annotations

import logging

from app.checks.base import BaseCheck
from app.config import Config
from app.core.check_runner import run_checks
from app.models import Category, ConfidenceLevel, Scope, SeverityLevel


class SuccessfulCheck(BaseCheck):
    """A check that returns one finding."""

    check_id = "successful"
    check_name = "Successful Check"
    category = Category.APPLICATION

    def run(self):
        result = self._create_result()
        result.findings.append(
            self._create_finding(
                title="Test finding",
                severity=SeverityLevel.LOW,
                target="example.com",
                evidence="Evidence",
                remediation="Fix it",
                confidence=ConfidenceLevel.HIGH,
            )
        )
        return self._finish_result(result)


class FailingCheck(BaseCheck):
    """A check that raises an exception."""

    check_id = "failing"
    check_name = "Failing Check"
    category = Category.APPLICATION

    def run(self):
        raise RuntimeError("boom")


class TestCheckRunnerProgress:
    """Progress callbacks should track execution state cleanly."""

    def test_run_checks_emits_progress_events(self, monkeypatch) -> None:
        """Progress callbacks should receive lifecycle events for each check."""
        config = Config()
        scope = Scope(allowed_hosts=["example.com"])
        logger = logging.getLogger("test_check_runner")
        logger.handlers = []
        logger.addHandler(logging.NullHandler())

        monkeypatch.setattr(
            "app.core.check_runner.get_available_checks",
            lambda _config: [SuccessfulCheck, FailingCheck],
        )

        events: list[dict[str, object]] = []

        summary = run_checks(
            scope=scope,
            config=config,
            logger=logger,
            progress_callback=events.append,
        )

        assert len(summary.findings) == 1
        assert len(summary.errors) == 1

        event_names = [event["event"] for event in events]
        assert event_names == [
            "start",
            "check_start",
            "check_end",
            "check_start",
            "check_end",
            "complete",
        ]

        assert events[0]["total"] == 2
        assert events[2]["status"] == "ok"
        assert events[2]["findings_count_total"] == 1
        assert events[4]["status"] == "failed"
        assert events[4]["errors_count_total"] == 1
        assert events[5]["findings_count"] == 1
        assert events[5]["errors_count"] == 1
