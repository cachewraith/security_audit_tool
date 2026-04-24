"""HTML parsing helpers for passive website posture analysis."""

from __future__ import annotations

import re
from html.parser import HTMLParser

from .models import PageForm

MIXED_CONTENT_RE = re.compile(
    r"""(?is)<(?P<tag>script|iframe|img|audio|video|source|embed|link|form)\b[^>]*?(?:src|href|action)=["'](?P<url>http://[^"']+)["']""",
)


class _FormParser(HTMLParser):
    """Small HTML parser for extracting form properties once per page."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[PageForm] = []
        self._current_form: PageForm | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): (value or "") for key, value in attrs}
        tag_name = tag.lower()

        if tag_name == "form":
            self._current_form = PageForm(
                action=attrs_dict.get("action", ""),
                method=attrs_dict.get("method", "get").lower(),
                autocomplete=attrs_dict.get("autocomplete", "").lower(),
            )
            self.forms.append(self._current_form)
            return

        if tag_name != "input" or self._current_form is None:
            return

        input_type = attrs_dict.get("type", "").lower()
        input_name = attrs_dict.get("name", "").lower()

        if input_type == "password":
            self._current_form.has_password = True
        if input_type == "hidden" and input_name:
            self._current_form.hidden_field_names.append(input_name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current_form = None


def extract_forms(body: str) -> list[PageForm]:
    """Parse forms from an HTML body, returning an empty list on parser errors."""
    if "<form" not in body.lower():
        return []

    parser = _FormParser()
    try:
        parser.feed(body)
    except Exception:
        return []
    return parser.forms


def find_mixed_content_urls(body: str) -> list[str]:
    """Return mixed-content resource URLs embedded in an HTTPS page."""
    matches = []
    for match in MIXED_CONTENT_RE.finditer(body):
        url = match.group("url")
        if url not in matches:
            matches.append(url)
    return matches
