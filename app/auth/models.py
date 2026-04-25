"""Models used by the Laravel-backed CLI auth flow."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def _unwrap_data(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the API payload's data object when present."""
    data = payload.get("data")
    if isinstance(data, dict):
        return data
    return payload


@dataclass(frozen=True)
class UserIdentity:
    """Represents the authenticated user returned by the API."""

    id: int | None
    email: str
    username: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    provider: str | None = None
    role_name: str | None = None
    role_slug: str | None = None

    @property
    def full_name(self) -> str:
        """Return the best user-facing name."""
        parts = [part for part in [self.first_name, self.last_name] if part]
        if parts:
            return " ".join(parts)
        return self.username or self.email

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "UserIdentity":
        """Create a user model from an API payload."""
        user_data = payload.get("user") if isinstance(payload.get("user"), dict) else payload
        role = user_data.get("role")
        role_name = None
        role_slug = None
        if isinstance(role, dict):
            role_name = role.get("name")
            role_slug = role.get("slug")

        return cls(
            id=user_data.get("id"),
            email=user_data.get("email", ""),
            username=user_data.get("username"),
            first_name=user_data.get("first_name"),
            last_name=user_data.get("last_name"),
            provider=user_data.get("provider"),
            role_name=role_name,
            role_slug=role_slug,
        )


@dataclass(frozen=True)
class DeviceLoginSession:
    """Data returned when the CLI starts the browser login flow."""

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    interval: int
    expires_in: int

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "DeviceLoginSession":
        """Parse the start-login response."""
        data = _unwrap_data(payload)
        return cls(
            device_code=str(data["device_code"]),
            user_code=str(data["user_code"]),
            verification_uri=str(data["verification_uri"]),
            verification_uri_complete=str(data["verification_uri_complete"]),
            interval=max(1, int(data["interval"])),
            expires_in=max(1, int(data["expires_in"])),
        )


@dataclass(frozen=True)
class TokenInfo:
    """Token metadata returned by the backend."""

    name: str | None = None
    expires_at: str | None = None
    abilities: list[str] = field(default_factory=list)

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "TokenInfo":
        """Create token metadata from an API payload."""
        token = payload.get("token")
        if not isinstance(token, dict):
            return cls()
        abilities = token.get("abilities")
        return cls(
            name=token.get("name"),
            expires_at=token.get("expires_at"),
            abilities=list(abilities) if isinstance(abilities, list) else [],
        )


@dataclass(frozen=True)
class AuthSession:
    """The locally stored authenticated session."""

    access_token: str
    token_type: str
    user: UserIdentity
    expires_at: str | None = None
    refresh_token: str | None = None
    refresh_expires_at: str | None = None
    token_name: str | None = None
    abilities: list[str] = field(default_factory=list)
    api_base_url: str | None = None
    saved_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @classmethod
    def from_exchange_payload(
        cls,
        payload: dict[str, Any],
        *,
        api_base_url: str,
    ) -> "AuthSession":
        """Build a stored session from a successful exchange response."""
        data = _unwrap_data(payload)
        user = UserIdentity.from_payload(data)
        token = TokenInfo.from_payload(data)
        return cls(
            access_token=str(data["access_token"]),
            token_type=str(data.get("token_type", "Bearer")),
            user=user,
            expires_at=data.get("expires_at"),
            refresh_token=data.get("refresh_token"),
            refresh_expires_at=data.get("refresh_expires_at"),
            token_name=token.name,
            abilities=token.abilities,
            api_base_url=api_base_url,
        )

    @classmethod
    def from_me_payload(
        cls,
        payload: dict[str, Any],
        *,
        access_token: str,
        api_base_url: str,
    ) -> "AuthSession":
        """Reconstruct a stored session from a `/me` response."""
        data = _unwrap_data(payload)
        user = UserIdentity.from_payload(data)
        token = TokenInfo.from_payload(data)
        return cls(
            access_token=access_token,
            token_type="Bearer",
            user=user,
            expires_at=token.expires_at,
            token_name=token.name,
            abilities=token.abilities,
            api_base_url=api_base_url,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthSession":
        """Deserialize a stored session."""
        user = UserIdentity.from_payload(data["user"])
        return cls(
            access_token=str(data["access_token"]),
            token_type=str(data.get("token_type", "Bearer")),
            user=user,
            expires_at=data.get("expires_at"),
            refresh_token=data.get("refresh_token"),
            refresh_expires_at=data.get("refresh_expires_at"),
            token_name=data.get("token_name"),
            abilities=list(data.get("abilities", [])),
            api_base_url=data.get("api_base_url"),
            saved_at=str(data.get("saved_at", datetime.now(UTC).isoformat())),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the session for local storage."""
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_at": self.expires_at,
            "refresh_token": self.refresh_token,
            "refresh_expires_at": self.refresh_expires_at,
            "token_name": self.token_name,
            "abilities": self.abilities,
            "api_base_url": self.api_base_url,
            "saved_at": self.saved_at,
            "user": {
                "id": self.user.id,
                "email": self.user.email,
                "username": self.user.username,
                "first_name": self.user.first_name,
                "last_name": self.user.last_name,
                "provider": self.user.provider,
                "role": {
                    "name": self.user.role_name,
                    "slug": self.user.role_slug,
                },
            },
        }
