"""Registry of stage runners, kept separate so stage modules can import each other's helpers without cycles."""

from __future__ import annotations

from .authoring import check_ci, run_feedback, run_implementation
from .review import run_review
from .stages import run_analysis

RUNNERS = {
    "analysis": run_analysis,
    "implementation": run_implementation,
    "review": run_review,
    "feedback": run_feedback,
}

__all__ = ["RUNNERS", "check_ci"]
