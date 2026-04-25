"""Tests for HTTP error handling in the auth API client."""

from __future__ import annotations

import httpx
import pytest

from app.auth.api_client import ApiClient
from app.auth.config import AuthConfig
from app.auth.exceptions import ApiError, NetworkError


def test_api_client_maps_backend_error_payload() -> None:
    """API errors should preserve backend message and code."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={
                "success": False,
                "error": "authorization_pending",
                "message": "Login not completed in browser yet.",
            },
        )

    client = ApiClient(AuthConfig())
    client.close()
    client._client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="https://portal-api.hushstackcambodia.site",
    )

    with pytest.raises(ApiError) as exc_info:
        client.post("/api/cli/auth/exchange", json={"device_code": "abc"})

    assert exc_info.value.error_code == "authorization_pending"
    assert str(exc_info.value) == "Login not completed in browser yet."

    client.close()


def test_api_client_raises_network_error_on_timeout() -> None:
    """Transport failures should become human-friendly network errors."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    client = ApiClient(AuthConfig())
    client.close()
    client._client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="https://portal-api.hushstackcambodia.site",
    )

    with pytest.raises(NetworkError, match="timed out"):
        client.get("/api/cli/auth/me")

    client.close()
