"""HTTP fetching helpers for passive website posture analysis."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request

from ...config import Config
from .models import WebsiteResponse


class WebsiteFetcher:
    """Fetch website responses with conservative limits for passive review."""

    USER_AGENT = "SecurityAudit-WebsiteReview/2.0"
    MAX_BODY_BYTES = 1024 * 1024

    def __init__(self, config: Config) -> None:
        self._config = config
        self._ssl_context = ssl.create_default_context()
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = ssl.CERT_NONE

    def fetch(self, url: str) -> WebsiteResponse:
        """Fetch a URL and normalize the response for analysis."""
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": self.USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
            method="GET",
        )

        timeout = max(
            self._config.rate_limit.connection_timeout,
            self._config.rate_limit.read_timeout,
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=timeout,
                context=self._ssl_context,
            ) as response:
                body_bytes = response.read(self.MAX_BODY_BYTES + 1)
                headers = {key.lower(): value for key, value in response.headers.items()}
                cookies = response.headers.get_all("Set-Cookie", [])
                return WebsiteResponse(
                    requested_url=url,
                    final_url=response.geturl(),
                    status_code=response.status,
                    headers=headers,
                    body=body_bytes[: self.MAX_BODY_BYTES].decode("utf-8", errors="ignore"),
                    cookies=cookies,
                    truncated=len(body_bytes) > self.MAX_BODY_BYTES,
                )
        except urllib.error.HTTPError as exc:
            body, truncated = self._read_error_body(exc)
            return WebsiteResponse(
                requested_url=url,
                final_url=exc.geturl(),
                status_code=exc.code,
                headers={key.lower(): value for key, value in exc.headers.items()},
                body=body,
                cookies=exc.headers.get_all("Set-Cookie", []),
                error=f"HTTP {exc.code}",
                truncated=truncated,
            )
        except Exception as exc:
            return WebsiteResponse(
                requested_url=url,
                final_url=url,
                status_code=0,
                headers={},
                body="",
                error=str(exc),
            )

    def _read_error_body(self, exc: urllib.error.HTTPError) -> tuple[str, bool]:
        """Read a bounded amount of response data from an HTTP error."""
        try:
            body_bytes = exc.read(self.MAX_BODY_BYTES + 1)
        except Exception:
            return "", False
        return (
            body_bytes[: self.MAX_BODY_BYTES].decode("utf-8", errors="ignore"),
            len(body_bytes) > self.MAX_BODY_BYTES,
        )
