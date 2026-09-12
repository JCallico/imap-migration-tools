"""Optional native desktop GUI."""


def main() -> None:
    """Launch the desktop application with an actionable dependency error."""
    try:
        from gui.app import main as launch
    except ModuleNotFoundError as exc:
        if exc.name in {"wx", "platformdirs"}:
            raise SystemExit(
                'Desktop dependencies unavailable. Install: pip install "imap-migration-tools[gui]"'
            ) from None
        raise
    launch()
