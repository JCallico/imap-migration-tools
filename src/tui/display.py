"""Terminal capability detection and semantic display profiles."""

from __future__ import annotations

import locale
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

DisplayMode = Literal["auto", "standard", "ascii"]
DISPLAY_MODES = ("auto", "standard", "ascii")


def has_limited_color(color_system: str | None) -> bool:
    """Return whether a resolved Rich/Textual color system needs stronger state cues."""
    return color_system not in {"256", "truecolor"}


@dataclass(frozen=True)
class DisplayProfile:
    """Characters and fallback behavior used to render the TUI."""

    mode: Literal["standard", "ascii"]
    limited_color: bool
    ready: str
    missing: str
    warning: str
    saving: str
    success: str
    error: str
    vertical_separator: str
    horizontal_separator: str


def resolve_display_profile(
    mode: DisplayMode = "auto",
    *,
    environ: Mapping[str, str] | None = None,
    encoding: str | None = None,
) -> DisplayProfile:
    """Resolve explicit or conservatively detected terminal capabilities."""
    environment = os.environ if environ is None else environ
    terminal = environment.get("TERM", "").lower()
    preferred_encoding = encoding or locale.getpreferredencoding(False)
    ascii_mode = mode == "ascii" or (mode == "auto" and (terminal == "dumb" or "utf" not in preferred_encoding.lower()))
    limited_color = ascii_mode or terminal == "dumb" or "NO_COLOR" in environment
    if ascii_mode:
        return DisplayProfile("ascii", limited_color, "OK", "--", "!!", "..", "OK", "XX", "|", "-")
    return DisplayProfile("standard", limited_color, "✓", "○", "⚠", "●", "✓", "✗", "│", "─")
