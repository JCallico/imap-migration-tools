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


def load_window_size(path: Path) -> tuple[int, int] | None:
    """Load a validated top-level window size when one was saved."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("version") != LAYOUT_VERSION:
        return None
    size = payload.get("window_size")
    if (
        not isinstance(size, dict)
        or not isinstance(size.get("width"), int)
        or isinstance(size.get("width"), bool)
        or not isinstance(size.get("height"), int)
        or isinstance(size.get("height"), bool)
        or size["width"] <= 0
        or size["height"] <= 0
    ):
        return None
    return size["width"], size["height"]


def save_layout(path: Path, splitters: dict[str, int], window_size: tuple[int, int] | None = None) -> None:
    """Atomically save splitter sizes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            payload = {"version": LAYOUT_VERSION, "splitters": splitters}
            if window_size is not None:
                payload["window_size"] = {"width": window_size[0], "height": window_size[1]}
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
        try:
            os.chmod(temp, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()
