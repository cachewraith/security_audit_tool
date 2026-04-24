"""Tests for TUI interaction behavior."""

from app.tui import TUI


class TestTUIInterrupts:
    """Tests for clean Ctrl+C handling in the TUI."""

    def test_wait_for_user_handles_keyboard_interrupt(self, monkeypatch) -> None:
        """Ctrl+C at the replay prompt should exit cleanly."""
        tui = TUI()

        def raise_interrupt(*args, **kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr("app.tui.Confirm.ask", raise_interrupt)

        assert tui.wait_for_user() is False


class TestTUITextPrompt:
    """Tests for prompt-toolkit backed text entry."""

    def test_prompt_ask_accepts_default_choice(self, monkeypatch) -> None:
        """Empty input should fall back to the provided default."""
        tui = TUI()

        monkeypatch.setattr("app.tui.pt_prompt", lambda *args, **kwargs: "")

        assert tui._prompt_ask("Select mode", choices=["1", "2"], default="1") == "1"
