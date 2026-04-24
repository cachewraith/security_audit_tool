"""Data structures for passive website posture analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import ParseResult, urlparse

from ...models import ConfidenceLevel, SeverityLevel


@dataclass(slots=True)
class WebsiteResponse:
    """Normalized HTTP response data for website posture checks."""

    requested_url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    body: str
    cookies: list[str] = field(default_factory=list)
    error: str | None = None
    truncated: bool = False


@dataclass(slots=True)
class PageForm:
    """Reduced representation of an HTML form."""

    action: str
    method: str
    autocomplete: str
    has_password: bool = False
    hidden_field_names: list[str] = field(default_factory=list)

    def has_csrf_token(self) -> bool:
        """Return whether the form appears to contain a CSRF token field."""
        csrf_markers = ("csrf", "xsrf", "_token", "authenticity", "requestverification")
        return any(any(marker in name for marker in csrf_markers) for name in self.hidden_field_names)


@dataclass(slots=True)
class WebsitePageAnalysis:
    """Parsed data derived from a fetched website response."""

    response: WebsiteResponse
    forms: list[PageForm]
    lower_body: str
    parsed_final_url: ParseResult

    @classmethod
    def from_response(
        cls,
        response: WebsiteResponse,
        forms: list[PageForm],
    ) -> "WebsitePageAnalysis":
        """Build a reusable analysis object from a response and parsed forms."""
        return cls(
            response=response,
            forms=forms,
            lower_body=response.body.lower(),
            parsed_final_url=urlparse(response.final_url),
        )

    @property
    def final_scheme(self) -> str:
        """Return the normalized final URL scheme."""
        return self.parsed_final_url.scheme.lower()

    @property
    def final_path(self) -> str:
        """Return the normalized final URL path."""
        return self.parsed_final_url.path.lower() or "/"

    @property
    def is_https(self) -> bool:
        """Return whether the final response was served over HTTPS."""
        return self.final_scheme == "https"


@dataclass(slots=True)
class WebsiteFindingSpec:
    """Structured finding details before they are converted into Finding models."""

    title: str
    severity: SeverityLevel
    evidence: str
    remediation: str
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    metadata: dict[str, object] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
