"""Service layer for Laravel-backed CLI authentication."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version as get_package_version
from typing import Callable

from .api_client import ApiClient
from .config import DEFAULT_CLIENT_NAME, DEFAULT_REQUESTED_ABILITIES, AuthConfig
from .exceptions import ApiError, AuthError
from .models import AuthSession, DeviceLoginSession
from .token_store import TokenStore


@dataclass(frozen=True)
class LoginPollUpdate:
    """Represents the current state of the login poll loop."""

    state: str
    message: str
    wait_seconds: int


class AuthService:
    """Orchestrates CLI login, storage, and session inspection."""

    def __init__(
        self,
        client: ApiClient,
        store: TokenStore,
        config: AuthConfig,
    ) -> None:
        self.client = client
        self.store = store
        self.config = config

    def start_login(self) -> DeviceLoginSession:
        """Start the device/browser login flow."""
        payload = self.client.post(
            "/api/cli/auth/start",
            json={
                "client_name": DEFAULT_CLIENT_NAME,
                "client_version": self._app_version(),
                "device_name": socket.gethostname(),
                "requested_abilities": list(DEFAULT_REQUESTED_ABILITIES),
            },
        )
        return DeviceLoginSession.from_payload(payload)

    def poll_for_token(
        self,
        start: DeviceLoginSession,
        *,
        on_update: Callable[[LoginPollUpdate], None] | None = None,
    ) -> AuthSession:
        """Poll the backend until the login transaction resolves."""
        interval = start.interval
        deadline = time.monotonic() + start.expires_in

        while True:
            if time.monotonic() >= deadline:
                raise ApiError("Login expired. Run `security-audit login` again.", error_code="expired_token")

            try:
                payload = self.client.post(
                    "/api/cli/auth/exchange",
                    json={"device_code": start.device_code},
                )
            except ApiError as exc:
                code = exc.error_code or ""
                if code == "authorization_pending":
                    if on_update:
                        on_update(LoginPollUpdate("pending", exc.message, interval))
                    time.sleep(interval)
                    continue
                if code == "slow_down":
                    interval += 2
                    if on_update:
                        on_update(LoginPollUpdate("slow_down", exc.message, interval))
                    time.sleep(interval)
                    continue
                if code in {"expired_token", "invalid_device_code", "already_consumed"}:
                    raise ApiError(self._terminal_error_message(code, exc.message), error_code=code) from exc
                raise

            session = AuthSession.from_exchange_payload(payload, api_base_url=self.config.api_base_url)
            self.store.save(session)
            return session

    def whoami(self) -> AuthSession:
        """Fetch the current authenticated user."""
        session = self.require_session()
        try:
            payload = self.client.get("/api/cli/auth/me", bearer_token=session.access_token)
        except ApiError as exc:
            if exc.status_code == 401:
                self.store.clear()
                raise ApiError("Your saved login is no longer valid. Run `security-audit login` again.") from exc
            raise

        updated_session = AuthSession.from_me_payload(
            payload,
            access_token=session.access_token,
            api_base_url=self.config.api_base_url,
        )
        if session.refresh_token and not updated_session.refresh_token:
            updated_session = AuthSession(
                access_token=updated_session.access_token,
                token_type=updated_session.token_type,
                user=updated_session.user,
                expires_at=updated_session.expires_at,
                refresh_token=session.refresh_token,
                refresh_expires_at=session.refresh_expires_at,
                token_name=updated_session.token_name,
                abilities=updated_session.abilities,
                api_base_url=updated_session.api_base_url,
                saved_at=updated_session.saved_at,
            )
        self.store.save(updated_session)
        return updated_session

    def logout(self) -> str:
        """Log out of the backend and clear local state."""
        session = self.store.load()
        if session is None:
            return "No local login was found."

        message = "Local login removed."
        try:
            self.client.post("/api/cli/auth/logout", bearer_token=session.access_token)
            message = "CLI token revoked and local login removed."
        except ApiError as exc:
            if exc.status_code != 401:
                raise
            message = "Backend session was already invalid. Local login removed."
        finally:
            self.store.clear()
        return message

    def require_session(self) -> AuthSession:
        """Load the saved session or raise a helpful error."""
        session = self.store.load()
        if session is None:
            raise AuthError("You are not logged in. Run `security-audit login` first.")
        return session

    def _app_version(self) -> str:
        try:
            return get_package_version("cache-wraith-audit-tool")
        except PackageNotFoundError:
            return "1.0.0"

    @staticmethod
    def _terminal_error_message(error_code: str, default: str) -> str:
        mapping = {
            "expired_token": "Login expired before approval completed. Run `security-audit login` again.",
            "invalid_device_code": "The backend rejected this login request. Start a new login attempt.",
            "already_consumed": "This login request was already completed. Start a new login attempt.",
        }
        return mapping.get(error_code, default)


def require_authenticated_session(config: AuthConfig) -> None:
    """Require an existing local authenticated session before using the tool."""
    store = TokenStore(config)
    session = store.load()
    if session is None:
        raise AuthError("Login required. Run `security-audit login` first.")
