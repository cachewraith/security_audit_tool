"""HTTP client for the Laravel CLI auth API."""

from __future__ import annotations

from typing import Any

import httpx

from .config import AuthConfig
from .exceptions import ApiError, NetworkError


class ApiClient:
    """Small wrapper around the backend auth endpoints."""

    def __init__(self, config: AuthConfig, *, debug: bool = False) -> None:
        self.config = config
        self.debug = debug
        self._client = httpx.Client(
            base_url=self.config.api_base_url.rstrip("/"),
            timeout=httpx.Timeout(
                timeout=self.config.request_timeout_seconds,
                connect=self.config.connect_timeout_seconds,
                read=self.config.read_timeout_seconds,
            ),
            headers={
                "Accept": "application/json",
                "User-Agent": self.config.user_agent,
            },
            follow_redirects=False,
        )

    def close(self) -> None:
        """Release the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> "ApiClient":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def post(
        self,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        bearer_token: str | None = None,
    ) -> dict[str, Any]:
        """Send a POST request and parse the JSON body."""
        return self._request("POST", path, json=json, bearer_token=bearer_token)

    def get(self, path: str, *, bearer_token: str | None = None) -> dict[str, Any]:
        """Send a GET request and parse the JSON body."""
        return self._request("GET", path, bearer_token=bearer_token)

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        bearer_token: str | None = None,
    ) -> dict[str, Any]:
        headers: dict[str, str] = {}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"

        try:
            response = self._client.request(method, path, json=json, headers=headers)
        except httpx.TimeoutException as exc:
            raise NetworkError("The backend timed out. Check your connection and try again.") from exc
        except httpx.HTTPError as exc:
            raise NetworkError("Could not reach the backend. Check DNS, network, and TLS settings.") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise ApiError(
                "The backend returned an unexpected response format.",
                status_code=response.status_code,
            ) from exc

        if response.is_success:
            return payload if isinstance(payload, dict) else {"data": payload}

        message = "The backend rejected the request."
        error_code = None
        if isinstance(payload, dict):
            message = str(payload.get("message") or payload.get("error") or message)
            error_code = payload.get("error")
            if error_code is None:
                errors = payload.get("errors")
                if isinstance(errors, dict):
                    first_field = next(iter(errors.values()), None)
                    if isinstance(first_field, list) and first_field:
                        message = str(first_field[0])

        raise ApiError(message, status_code=response.status_code, error_code=error_code)
