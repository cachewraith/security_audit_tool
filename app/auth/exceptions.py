"""Auth-specific exception types."""

from __future__ import annotations


class AuthError(Exception):
    """Base exception for CLI auth failures."""


class NetworkError(AuthError):
    """Raised when the backend could not be reached safely."""


class StorageError(AuthError):
    """Raised when local token storage fails."""


class ApiError(AuthError):
    """Raised when the backend returns a handled API error."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        error_code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code

    def __str__(self) -> str:
        return self.message
