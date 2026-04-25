"""Browser helpers for auth verification."""

from __future__ import annotations

import webbrowser


def open_browser(url: str) -> bool:
    """Best-effort browser launcher."""
    try:
        return bool(webbrowser.open(url, new=2, autoraise=True))
    except Exception:
        return False
