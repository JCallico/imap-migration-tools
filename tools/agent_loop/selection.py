"""Model selection under quota limits while enforcing implementation/review model separation."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from .config import AUTHOR_STAGES, LONG_STAGES, LoopConfig, ModelRef

# Returns (usable, reason) for an engine; long_stage stages do not start on a low engine.
UsableFn = Callable[[str, bool], "tuple[bool, str]"]


@dataclass(frozen=True)
class Selection:
    model: ModelRef | None
    reason: str = ""

    @property
    def waiting(self) -> bool:
        return self.model is None


def reviewer_allowed(candidate: ModelRef, authors: Iterable[ModelRef], require_distinct_vendor: bool) -> bool:
    """A reviewer may not share a model, or by default a vendor, with any model that authored the change."""
    for author in authors:
        if candidate.key == author.key:
            return False
        if require_distinct_vendor and candidate.vendor == author.vendor:
            return False
    return True


def select_reviewer(config: LoopConfig, authors: Iterable[ModelRef], usable: UsableFn) -> Selection:
    authors = tuple(authors)
    stage = config.stage("review")
    blocked_by_policy = []
    for candidate in stage.candidates:
        if not reviewer_allowed(candidate, authors, config.policy.require_distinct_review_vendor):
            blocked_by_policy.append(str(candidate))
            continue
        ok, why = usable(candidate.engine, False)
        if ok:
            return Selection(candidate)
    if len(blocked_by_policy) == len(stage.candidates):
        return Selection(None, "no configured reviewer is distinct from the pull request's author models")
    return Selection(None, "waiting for reviewer quota")


def select_author(
    config: LoopConfig,
    stage_name: str,
    usable: UsableFn,
    existing_authors: Iterable[ModelRef] = (),
) -> Selection:
    """Choose a model for a code-authoring stage, keeping at least one valid reviewer available."""
    if stage_name not in AUTHOR_STAGES:
        raise ValueError(f"{stage_name} is not a code-authoring stage")
    existing = tuple(existing_authors)
    review = config.stage("review")
    reasons = []
    for candidate in config.stage(stage_name).candidates:
        authors = (*existing, candidate)
        if not any(
            reviewer_allowed(reviewer, authors, config.policy.require_distinct_review_vendor)
            for reviewer in review.candidates
        ):
            reasons.append(f"{candidate} would leave no valid reviewer")
            continue
        ok, why = usable(candidate.engine, stage_name in LONG_STAGES)
        if ok:
            return Selection(candidate)
        reasons.append(why)
    return Selection(None, "; ".join(reason for reason in reasons if reason) or "waiting for quota")


def select_stage_model(config: LoopConfig, stage_name: str, usable: UsableFn) -> Selection:
    """Choose a model for a stage that does not author code (analysis, summaries)."""
    reasons = []
    for candidate in config.stage(stage_name).candidates:
        ok, why = usable(candidate.engine, stage_name in LONG_STAGES)
        if ok:
            return Selection(candidate)
        reasons.append(why)
    return Selection(None, "; ".join(reason for reason in reasons if reason) or "waiting for quota")
