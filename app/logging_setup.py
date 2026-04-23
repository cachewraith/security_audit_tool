"""Logging configuration for the security audit tool."""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class StructuredLogFormatter(logging.Formatter):
    """Custom formatter for structured logging."""
    
    def __init__(self, include_timestamp: bool = True):
        super().__init__()
        self.include_timestamp = include_timestamp
    
    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.utcnow().isoformat() if self.include_timestamp else ""
        level = record.levelname
        message = record.getMessage()
        
        # Include extra fields if present
        extra_fields = []
        if hasattr(record, 'check_id'):
            extra_fields.append(f"check={record.check_id}")
        if hasattr(record, 'target'):
            extra_fields.append(f"target={record.target}")
        
        extra = " ".join(extra_fields)
        
        if self.include_timestamp:
            if extra:
                return f"[{timestamp}] [{level}] {extra} {message}"
            return f"[{timestamp}] [{level}] {message}"
        else:
            if extra:
                return f"[{level}] {extra} {message}"
            return f"[{level}] {message}"


def setup_logging(
    verbose: bool = False,
    quiet: bool = False,
    log_file: Optional[Path] = None,
) -> logging.Logger:
    """Configure logging for the application.
    
    Args:
        verbose: Enable DEBUG level logging
        quiet: Suppress all but ERROR logging
        log_file: Optional path to write structured logs
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("security_audit")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers = []  # Clear existing handlers
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    if not quiet:
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_level = logging.DEBUG if verbose else logging.INFO
        console_handler.setLevel(console_level)
        
        # Simple format for console
        console_format = StructuredLogFormatter(include_timestamp=verbose)
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)
    else:
        # Even in quiet mode, show errors
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.ERROR)
        console_format = StructuredLogFormatter(include_timestamp=False)
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)
    
    # File handler for structured logging
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, mode='a')
        file_handler.setLevel(logging.DEBUG)
        file_format = StructuredLogFormatter(include_timestamp=True)
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
    
    return logger


def log_audit_start(
    logger: logging.Logger,
    scope_summary: str,
    config_summary: dict,
) -> None:
    """Log the start of an audit run."""
    logger.info("=" * 70)
    logger.info("SECURITY AUDIT STARTED")
    logger.info(f"Timestamp: {datetime.utcnow().isoformat()}")
    logger.info(scope_summary)
    logger.debug(f"Configuration: {config_summary}")
    logger.info("=" * 70)


def log_audit_end(
    logger: logging.Logger,
    summary: dict,
) -> None:
    """Log the end of an audit run."""
    logger.info("=" * 70)
    logger.info("SECURITY AUDIT COMPLETED")
    logger.info(f"Timestamp: {datetime.utcnow().isoformat()}")
    logger.info(f"Duration: {summary.get('duration_seconds', 0):.2f} seconds")
    logger.info(f"Findings: {summary.get('findings_count', 0)}")
    logger.info(f"Errors: {summary.get('errors_count', 0)}")
    
    # Severity breakdown
    severity_counts = summary.get('severity_counts', {})
    if severity_counts:
        logger.info("Severity breakdown:")
        for sev, count in sorted(
            severity_counts.items(),
            key=lambda x: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}.get(x[0], -1),
            reverse=True
        ):
            if count > 0:
                logger.info(f"  - {sev.upper()}: {count}")
    
    logger.info("=" * 70)


def log_finding(logger: logging.Logger, finding: dict) -> None:
    """Log a single finding with structured data."""
    extra = {
        'check_id': finding.get('check_id', 'unknown'),
        'target': finding.get('target', 'unknown'),
    }
    
    level = logging.INFO
    severity = finding.get('severity', 'info')
    if severity == 'critical':
        level = logging.CRITICAL
    elif severity == 'high':
        level = logging.ERROR
    elif severity == 'medium':
        level = logging.WARNING
    
    message = f"[{finding.get('category', 'unknown').upper()}] "
    message += f"{finding.get('title', 'Unknown')} "
    message += f"(Severity: {severity.upper()})"
    
    logger.log(level, message, extra=extra)


def log_check_start(logger: logging.Logger, check_id: str, check_name: str) -> None:
    """Log the start of a security check."""
    logger.debug(f"Starting check: {check_name} (ID: {check_id})")


def log_check_end(
    logger: logging.Logger,
    check_id: str,
    check_name: str,
    findings_count: int,
    error: Optional[str] = None,
) -> None:
    """Log the end of a security check."""
    if error:
        logger.error(f"Check failed: {check_name} (ID: {check_id}) - {error}")
    else:
        logger.debug(f"Completed check: {check_name} (ID: {check_id}) - {findings_count} findings")
