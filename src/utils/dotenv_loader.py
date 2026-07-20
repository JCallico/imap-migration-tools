def load_dotenv():
    """Load a .env file if python-dotenv is installed; silently skip if not."""
    try:
        from dotenv import load_dotenv as _load_dotenv

        _load_dotenv()
    except ImportError:
        pass
