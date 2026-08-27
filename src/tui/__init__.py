"""Full-screen interface for IMAP Migration Tools."""


def main() -> None:
    """Launch the optional Textual application with actionable dependency guidance."""
    try:
        from tui.app import main as run
    except ModuleNotFoundError as exc:
        if exc.name in {"dotenv", "platformdirs", "textual"}:
            raise SystemExit('The full-screen interface requires: pip install "imap-migration-tools[tui]"') from None
        raise
    run()
