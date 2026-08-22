"""Loading of environment variables from a ``.env`` file."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class DotenvLoadResult:
    """Environment keys added from the discovered ``.env`` file."""

    dotenv_keys: frozenset[str] = frozenset()


def load_dotenv() -> DotenvLoadResult:
    """Load ``.env`` without overriding the OS environment and report its keys."""
    try:
        from dotenv import find_dotenv as _find_dotenv
        from dotenv import load_dotenv as _load_dotenv
    except ModuleNotFoundError as exc:
        if exc.name == "dotenv":
            return DotenvLoadResult()
        raise

    existing_keys = frozenset(os.environ)
    _load_dotenv(_find_dotenv(usecwd=True), override=False)
    return DotenvLoadResult(frozenset(os.environ).difference(existing_keys))
