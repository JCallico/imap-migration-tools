"""Registry of stage runners, kept separate so stage modules can import each other's helpers without cycles."""

from __future__ import annotations

from .authoring import check_ci, run_implementation
from .stages import run_analysis

RUNNERS = {"analysis": run_analysis, "implementation": run_implementation}

__all__ = ["RUNNERS", "check_ci"]
