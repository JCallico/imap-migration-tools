"""Persistent TUI panel layout settings."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path

from platformdirs import user_config_path

LAYOUT_VERSION = 1


def default_layout_path() -> Path:
    """Return the per-user layout settings path."""
    return user_config_path("imap-migration-tools", "CallicoCode") / "tui-layout.json"


def load_layout(path: Path) -> dict[str, int]:
    """Load validated splitter sizes, ignoring missing or damaged settings."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict) or payload.get("version") != LAYOUT_VERSION:
        return {}
    splitters = payload.get("splitters")
    if not isinstance(splitters, dict):
        return {}
    return {
        key: value
        for key, value in splitters.items()
        if isinstance(key, str) and isinstance(value, int) and not isinstance(value, bool) and value > 0
    }


def save_layout(path: Path, splitters: dict[str, int]) -> None:
    """Atomically save splitter sizes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"version": LAYOUT_VERSION, "splitters": splitters}, stream, indent=2, sort_keys=True)
            stream.write("\n")
        try:
            os.chmod(temp, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()
