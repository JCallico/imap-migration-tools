"""Loading of environment variables from a ``.env`` file."""

import os
from dataclasses import dataclass

ENV_FILE_VARIABLE = "IMAP_TOOLS_ENV_FILE"


@dataclass(frozen=True)
class DotenvLoadResult:
    """Environment keys added from the discovered ``.env`` file."""

    dotenv_keys: frozenset[str] = frozenset()


def load_dotenv() -> DotenvLoadResult:
    """Load ``.env`` without overriding the OS environment and report its keys.

    ``IMAP_TOOLS_ENV_FILE`` names one exact file to load instead of discovering ``.env`` from the working directory.
    """
    try:
        from dotenv import find_dotenv as _find_dotenv
        from dotenv import load_dotenv as _load_dotenv
    except ModuleNotFoundError as exc:
        if exc.name == "dotenv":
            return DotenvLoadResult()
        raise

    configured = os.environ.get(ENV_FILE_VARIABLE, "")
    if configured:
        path = os.path.expanduser(configured)
        if not os.path.isfile(path):
            raise SystemExit(f"Configuration file not found ({ENV_FILE_VARIABLE}): {path}")
    else:
        path = _find_dotenv(usecwd=True)
    existing_keys = frozenset(os.environ)
    _load_dotenv(path, override=False)
    return DotenvLoadResult(frozenset(os.environ).difference(existing_keys))
