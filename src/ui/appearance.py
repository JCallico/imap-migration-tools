"""Persistent native desktop appearance settings."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path

APPEARANCE_VERSION = 1
DEFAULT_OPACITY = 96
MINIMUM_OPACITY = 70
DEFAULT_ZOOM = 100
MINIMUM_ZOOM = 80
MAXIMUM_ZOOM = 150


def load_appearance(path: Path) -> dict[str, int]:
    """Load validated desktop appearance settings."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict) or payload.get("version") != APPEARANCE_VERSION:
        return {}
    opacity = payload.get("opacity")
    zoom = payload.get("zoom", DEFAULT_ZOOM)
    if not isinstance(opacity, int) or isinstance(opacity, bool) or not MINIMUM_OPACITY <= opacity <= 100:
        return {}
    if not isinstance(zoom, int) or isinstance(zoom, bool) or not MINIMUM_ZOOM <= zoom <= MAXIMUM_ZOOM:
        return {}
    return {"opacity": opacity, "zoom": zoom}


def save_appearance(path: Path, opacity: int, zoom: int = DEFAULT_ZOOM) -> None:
    """Atomically save desktop opacity and zoom settings."""
    if not isinstance(opacity, int) or isinstance(opacity, bool) or not MINIMUM_OPACITY <= opacity <= 100:
        raise ValueError(f"opacity must be between {MINIMUM_OPACITY} and 100")
    if not isinstance(zoom, int) or isinstance(zoom, bool) or not MINIMUM_ZOOM <= zoom <= MAXIMUM_ZOOM:
        raise ValueError(f"zoom must be between {MINIMUM_ZOOM} and {MAXIMUM_ZOOM}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(
                {"version": APPEARANCE_VERSION, "opacity": opacity, "zoom": zoom},
                stream,
                indent=2,
                sort_keys=True,
            )
            stream.write("\n")
        try:
            os.chmod(temp, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()
