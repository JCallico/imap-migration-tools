"""Definitions and bootstrap for the ``agent:*`` state labels."""

from __future__ import annotations

from dataclasses import dataclass

from . import state
from .gh import Gh


@dataclass(frozen=True)
class LabelSpec:
    name: str
    color: str
    description: str


LABELS = (
    LabelSpec(state.ANALYZING, "1d76db", "Agent loop: analysis in progress"),
    LabelSpec(state.NEEDS_INFO, "fbca04", "Agent loop: waiting for more information from the reporter"),
    LabelSpec(state.AWAITING_APPROVAL, "d93f0b", "Agent loop: analysis ready; administrator /approve or /revise"),
    LabelSpec(state.IMPLEMENTING, "5319e7", "Agent loop: implementation in progress"),
    LabelSpec(state.AI_REVIEW, "0e8a16", "Agent loop: cross-model AI review in progress"),
    LabelSpec(state.CHANGES_REQUESTED, "e99695", "Agent loop: addressing review feedback"),
    LabelSpec(state.READY_FOR_ADMIN, "0052cc", "Agent loop: ready for administrator review"),
    LabelSpec(state.WAITING_QUOTA, "c5def5", "Agent loop: paused until a subscription limit resets"),
    LabelSpec(state.BLOCKED, "b60205", "Agent loop: needs an administrator decision"),
    LabelSpec(state.PAUSED, "000000", "Agent loop: paused by an administrator"),
    LabelSpec(state.ADOPT, "bfdadc", "Agent loop: administrator opted this existing item in"),
)


def bootstrap_labels(gh: Gh, apply: bool) -> list[str]:
    """Create or update every agent label; without ``apply`` only describe the changes."""
    owner, name = gh.repo_parts()
    lines = []
    for spec in LABELS:
        if not apply:
            lines.append(f"would create/update {spec.name} (#{spec.color}): {spec.description}")
            continue
        gh.run(
            [
                "label",
                "create",
                spec.name,
                "--repo",
                f"{owner}/{name}",
                "--color",
                spec.color,
                "--description",
                spec.description,
                "--force",
            ]
        )
        lines.append(f"created/updated {spec.name}")
    return lines
