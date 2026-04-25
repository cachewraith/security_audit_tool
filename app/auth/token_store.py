"""Local storage for CLI auth tokens."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .config import AuthConfig
from .exceptions import StorageError
from .models import AuthSession

try:
    import keyring  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    keyring = None


class TokenStore:
    """Persist auth state in keyring when available, else a local file."""

    def __init__(self, config: AuthConfig) -> None:
        self.config = config
        self._account_name = self.config.api_base_url

    @property
    def storage_path(self) -> Path:
        """Expose the file path used by the fallback store."""
        return self.config.storage_path

    def load(self) -> AuthSession | None:
        """Load the saved auth session if present."""
        keyring_payload = self._load_from_keyring()
        if keyring_payload:
            return AuthSession.from_dict(keyring_payload)

        if not self.storage_path.exists():
            return None

        try:
            payload = json.loads(self.storage_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise StorageError(f"Could not read auth state from {self.storage_path}.") from exc

        if not isinstance(payload, dict):
            raise StorageError("Stored auth state is invalid.")

        return AuthSession.from_dict(payload)

    def save(self, session: AuthSession) -> None:
        """Persist the provided auth session."""
        payload = session.to_dict()
        saved_to_keyring = self._save_to_keyring(payload)
        if saved_to_keyring:
            self._remove_file_silently()
            return

        try:
            self.config.storage_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.config.storage_dir, 0o700)
            self.storage_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            os.chmod(self.storage_path, 0o600)
        except Exception as exc:
            raise StorageError(f"Could not persist auth state to {self.storage_path}.") from exc

    def clear(self) -> None:
        """Delete any saved auth session."""
        keyring_cleared = self._clear_keyring()
        self._remove_file_silently()
        if not keyring_cleared and self.storage_path.exists():
            raise StorageError(f"Could not remove auth state at {self.storage_path}.")

    def _load_from_keyring(self) -> dict | None:
        if keyring is None:
            return None
        try:
            payload = keyring.get_password(self.config.keyring_service_name, self._account_name)
        except Exception:
            return None
        if not payload:
            return None
        try:
            data = json.loads(payload)
        except ValueError as exc:
            raise StorageError("Stored keyring auth state is invalid.") from exc
        return data if isinstance(data, dict) else None

    def _save_to_keyring(self, payload: dict) -> bool:
        if keyring is None:
            return False
        try:
            keyring.set_password(
                self.config.keyring_service_name,
                self._account_name,
                json.dumps(payload),
            )
            return True
        except Exception:
            return False

    def _clear_keyring(self) -> bool:
        if keyring is None:
            return True
        try:
            keyring.delete_password(self.config.keyring_service_name, self._account_name)
            return True
        except Exception:
            return True

    def _remove_file_silently(self) -> None:
        try:
            self.storage_path.unlink(missing_ok=True)
        except Exception:
            pass
