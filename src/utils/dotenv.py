"""Optional loading of environment variables from a ``.env`` file."""


def load_dotenv():
    """Load a ``.env`` file when ``python-dotenv`` is installed."""
    try:
        from dotenv import find_dotenv as _find_dotenv
        from dotenv import load_dotenv as _load_dotenv
    except ModuleNotFoundError as exc:
        if exc.name == "dotenv":
            return
        raise

    _load_dotenv(_find_dotenv(usecwd=True), override=False)
