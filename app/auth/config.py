"""Configuration values for CLI authentication."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


DEFAULT_API_BASE_URL = "https://portal-api.hushstackcambodia.site"
DEFAULT_CLIENT_NAME = "security-audit"
DEFAULT_REQUESTED_ABILITIES = ("cli",)


@dataclass(frozen=True)
class AuthConfig:
    """Static configuration for Laravel-backed CLI auth."""

    api_base_url: str = DEFAULT_API_BASE_URL
    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 20.0
    request_timeout_seconds: float = 30.0
    user_agent: str = "security-audit-cli"
    keyring_service_name: str = "security-audit-cli"
    storage_filename: str = "auth.json"

    @property
    def storage_dir(self) -> Path:
        """Return the config directory used by the CLI."""
        xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
        if xdg_config_home:
            return Path(xdg_config_home) / "security-audit"

        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "SecurityAudit"

        return Path.home() / ".config" / "security-audit"

    @property
    def storage_path(self) -> Path:
        """Return the file used to persist auth state."""
        return self.storage_dir / self.storage_filename
