"""Label state machine: decides the next dispatcher action for each open issue and pull request."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from .authz import (
    AGENT_LABEL_PREFIX,
    Authorizer,
    evaluate_approval,
    label_applied_by_admin,
    latest_analysis,
    parse_analysis,
    untrusted_label_changes,
)
from .config import LoopConfig, ModelRef, parse_model_ref
from .selection import UsableFn, select_author, select_reviewer, select_stage_model
from .snapshot import Item, LabelEvent

ANALYZING = "agent:analyzing"
NEEDS_INFO = "agent:needs-info"
AWAITING_APPROVAL = "agent:awaiting-approval"
IMPLEMENTING = "agent:implementing"
AI_REVIEW = "agent:ai-review"
CHANGES_REQUESTED = "agent:changes-requested"
READY_FOR_ADMIN = "agent:ready-for-admin"
WAITING_QUOTA = "agent:waiting-quota"
BLOCKED = "agent:blocked"
PAUSED = "agent:paused"
ADOPT = "agent:adopt"

STATE_LABELS = (
    ANALYZING,
    NEEDS_INFO,
    AWAITING_APPROVAL,
    IMPLEMENTING,
    AI_REVIEW,
    CHANGES_REQUESTED,
    READY_FOR_ADMIN,
)

# Lower runs first: finish in-flight work before starting new work.
PRIORITY = {
    "admin_changes": 0,
    "feedback": 1,
    "ci_fix": 2,
    "review": 3,
    "implementation": 4,
    "analysis": 5,
}

_RUN_MARKER = re.compile(r"<!--\s*agent-loop:run\s+stage=(\w+)\s+model=(\S+)\s*-->")
_UNAUTHORIZED_MARKER = "agent-loop:unauthorized comment="

RUN_STAGE = "run_stage"
WAIT = "wait"
SKIP = "skip"
REVERT_LABEL = "revert_label"
REPLY_UNAUTHORIZED = "reply_unauthorized"
SET_LABELS = "set_labels"


@dataclass
class Action:
    kind: str
    item: Item
    stage: str | None = None
    model: ModelRef | None = None
    reason: str = ""
    add_labels: tuple[str, ...] = ()
    remove_labels: tuple[str, ...] = ()
    event: LabelEvent | None = None
    comment_id: str | None = None
    notes: str = ""
    priority: int = 99

    def describe(self) -> str:
        kind = "PR" if self.item.is_pr else "issue"
        target = f"{kind} #{self.item.number}"
        if self.kind == RUN_STAGE:
            text = f"{target}: run {self.stage} with {self.model}"
        elif self.kind == WAIT:
            text = f"{target}: {self.stage} waiting"
        elif self.kind == REVERT_LABEL and self.event is not None:
            verb = "remove" if self.event.added else "restore"
            text = f"{target}: {verb} {self.event.label} (changed by {self.event.actor or 'unknown'}, not an admin)"
        elif self.kind == REPLY_UNAUTHORIZED:
            text = f"{target}: reply that only administrators can issue commands"
        elif self.kind == SET_LABELS:
            text = f"{target}: labels +{list(self.add_labels)} -{list(self.remove_labels)}"
        else:
            text = f"{target}: skip"
        return f"{text} — {self.reason}" if self.reason else text


@dataclass
class Context:
    config: LoopConfig
    authorizer: Authorizer
    usable: UsableFn
    now: datetime
    actions: list[Action] = field(default_factory=list)


def run_markers(item: Item, authorizer: Authorizer) -> list[tuple[str, ModelRef]]:
    """Return ``(stage, model)`` pairs recorded by the bot for completed stage runs on an item."""
    markers = []
    for comment in item.comments:
        if not authorizer.is_bot(comment.author):
            continue
        for stage, model in _RUN_MARKER.findall(comment.body):
            try:
                markers.append((stage, parse_model_ref(model)))
            except ValueError:
                continue
    return markers


def run_marker(stage: str, model: ModelRef) -> str:
    return f"<!-- agent-loop:run stage={stage} model={model} -->"


def author_models(item: Item, authorizer: Authorizer) -> list[ModelRef]:
    return [
        model for stage, model in run_markers(item, authorizer) if stage in ("implementation", "feedback", "ci_fix")
    ]


def effective_labels(item: Item, reverts: Iterable[LabelEvent]) -> set[str]:
    labels = set(item.labels)
    for event in reverts:
        if event.added:
            labels.discard(event.label)
        else:
            labels.add(event.label)
    return labels


def already_replied_unauthorized(item: Item, comment_id: str, authorizer: Authorizer) -> bool:
    marker = f"{_UNAUTHORIZED_MARKER}{comment_id}"
    return any(authorizer.is_bot(comment.author) and marker in comment.body for comment in item.comments)


def unauthorized_marker(comment_id: str) -> str:
    return f"<!-- {_UNAUTHORIZED_MARKER}{comment_id} -->"


def _stage_action(ctx: Context, item: Item, stage: str, priority_key: str, **kwargs) -> Action:
    if stage == "review":
        selection = select_reviewer(ctx.config, author_models(item, ctx.authorizer), ctx.usable)
    elif stage in ("implementation", "feedback", "ci_fix"):
        selection = select_author(ctx.config, stage, ctx.usable, author_models(item, ctx.authorizer))
    else:
        selection = select_stage_model(ctx.config, stage, ctx.usable)
    priority = PRIORITY[priority_key]
    if selection.waiting:
        return Action(WAIT, item, stage=stage, reason=selection.reason, priority=priority)
    return Action(RUN_STAGE, item, stage=stage, model=selection.model, priority=priority, **kwargs)


def _reanalyses_since_admin(item: Item, ctx: Context) -> int:
    """Count analyses posted since the last trusted administrator comment."""
    last_admin = max(
        (comment.created_at for comment in item.comments if ctx.authorizer.comment_is_trusted(comment)),
        default=None,
    )
    count = 0
    for comment in item.comments:
        if ctx.authorizer.is_bot(comment.author) and parse_analysis(comment) is not None:
            if last_admin is None or comment.created_at > last_admin:
                count += 1
    return count


def _reply_after_needs_info(item: Item, ctx: Context) -> bool:
    analysis = latest_analysis(item, ctx.authorizer)
    since = analysis.comment.created_at if analysis else item.created_at
    return any(
        comment.created_at > since
        and not ctx.authorizer.is_bot(comment.author)
        and (comment.author == item.author or ctx.authorizer.is_admin(comment.author))
        for comment in item.comments
    )


def _decide_issue(item: Item, labels: set[str], ctx: Context) -> list[Action]:
    config = ctx.config
    has_state = any(label in labels for label in STATE_LABELS)
    if not has_state:
        since = config.github.enabled_since
        if since is not None and item.created_at < since and not label_applied_by_admin(item, ADOPT, ctx.authorizer):
            return [Action(SKIP, item, reason=f"created before {since:%Y-%m-%d}; an administrator can apply {ADOPT}")]
        return [_stage_action(ctx, item, "analysis", "analysis", add_labels=(ANALYZING,), reason="new issue")]
    if ANALYZING in labels:
        return [_stage_action(ctx, item, "analysis", "analysis", reason="analysis in progress")]
    if NEEDS_INFO in labels:
        if not _reply_after_needs_info(item, ctx):
            return [Action(SKIP, item, reason="waiting for the reporter's reply")]
        return _reanalysis(item, ctx, "reporter replied", remove=(NEEDS_INFO,))
    if AWAITING_APPROVAL in labels:
        decision = evaluate_approval(item, ctx.authorizer)
        actions = [
            Action(REPLY_UNAUTHORIZED, item, comment_id=comment.id, reason=f"command from {comment.author}")
            for comment in decision.ignored
            if not already_replied_unauthorized(item, comment.id, ctx.authorizer)
        ]
        if decision.status == "approved":
            actions.append(
                _stage_action(
                    ctx,
                    item,
                    "implementation",
                    "implementation",
                    add_labels=(IMPLEMENTING,),
                    remove_labels=(AWAITING_APPROVAL,),
                    reason=f"approved by {decision.command.author}",  # type: ignore[union-attr]
                )
            )
        elif decision.status == "revise":
            actions.append(
                _stage_action(
                    ctx,
                    item,
                    "analysis",
                    "analysis",
                    add_labels=(ANALYZING,),
                    remove_labels=(AWAITING_APPROVAL,),
                    notes=decision.notes,
                    reason=f"revision requested by {decision.command.author}",  # type: ignore[union-attr]
                )
            )
        elif decision.status in ("stale", "no_analysis"):
            actions += _reanalysis(item, ctx, decision.reason, remove=(AWAITING_APPROVAL,))
        else:
            actions.append(Action(SKIP, item, reason="waiting for administrator /approve or /revise"))
        return actions
    if IMPLEMENTING in labels:
        return [_stage_action(ctx, item, "implementation", "implementation", reason="implementation in progress")]
    return [Action(SKIP, item, reason="no issue action for current labels")]


def _reanalysis(item: Item, ctx: Context, reason: str, remove: tuple[str, ...]) -> list[Action]:
    limit = ctx.config.policy.max_reanalyses_without_admin
    if _reanalyses_since_admin(item, ctx) > limit:
        return [Action(SKIP, item, reason=f"re-analysis limit ({limit}) reached; waiting for an administrator")]
    return [
        _stage_action(
            ctx,
            item,
            "analysis",
            "analysis",
            add_labels=(ANALYZING,),
            remove_labels=remove,
            reason=f"re-analysis: {reason}",
        )
    ]


def _ai_review_rounds(item: Item, ctx: Context) -> int:
    return sum(1 for stage, _model in run_markers(item, ctx.authorizer) if stage == "review")


def _admin_requested_changes(item: Item, ctx: Context) -> bool:
    ready_events = [event for event in item.label_events if event.label == READY_FOR_ADMIN and event.added]
    since = max((event.created_at for event in ready_events), default=None)
    reviews = [
        review
        for review in item.reviews
        if review.submitted_at is not None
        and ctx.authorizer.is_admin(review.author)
        and (since is None or review.submitted_at > since)
    ]
    if not reviews:
        return False
    return max(reviews, key=lambda review: review.submitted_at).state == "CHANGES_REQUESTED"  # type: ignore[arg-type,return-value]


def _decide_pr(item: Item, labels: set[str], ctx: Context) -> list[Action]:
    if not any(label in labels for label in STATE_LABELS):
        if label_applied_by_admin(item, ADOPT, ctx.authorizer):
            return [
                _stage_action(ctx, item, "review", "review", add_labels=(AI_REVIEW,), reason="adopted by administrator")
            ]
        return [Action(SKIP, item, reason="not managed by the agent loop")]
    if READY_FOR_ADMIN in labels:
        if _admin_requested_changes(item, ctx):
            return [
                _stage_action(
                    ctx,
                    item,
                    "feedback",
                    "admin_changes",
                    add_labels=(CHANGES_REQUESTED,),
                    remove_labels=(READY_FOR_ADMIN,),
                    reason="administrator requested changes",
                )
            ]
        return [Action(SKIP, item, reason="waiting for administrator review")]
    if CHANGES_REQUESTED in labels:
        return [_stage_action(ctx, item, "feedback", "feedback", reason="addressing review feedback")]
    if AI_REVIEW in labels:
        rounds = _ai_review_rounds(item, ctx)
        if rounds >= ctx.config.policy.max_ai_review_rounds:
            return [
                Action(
                    SET_LABELS,
                    item,
                    add_labels=(BLOCKED,),
                    remove_labels=(AI_REVIEW,),
                    reason=f"{rounds} AI review rounds reached; escalating to the administrator",
                )
            ]
        return [_stage_action(ctx, item, "review", "review", reason=f"AI review round {rounds + 1}")]
    if IMPLEMENTING in labels:
        return [_stage_action(ctx, item, "implementation", "implementation", reason="implementation in progress")]
    return [Action(SKIP, item, reason="no pull request action for current labels")]


def decide(item: Item, ctx: Context) -> list[Action]:
    """Return the dispatcher actions for one open item, most important first."""
    if item.is_pr and not has_agent_label(item):
        return []  # pull requests are managed only when the loop created them or an administrator adopted them
    if item.truncated:
        return [Action(SKIP, item, reason="comment or label history exceeds fetch limits; handle manually")]
    reverts = untrusted_label_changes(item, ctx.authorizer)
    actions = [Action(REVERT_LABEL, item, event=event, reason="agent labels are restricted") for event in reverts]
    labels = effective_labels(item, reverts)
    if PAUSED in labels:
        return [*actions, Action(SKIP, item, reason=f"{PAUSED} applied by an administrator")]
    if BLOCKED in labels:
        return [*actions, Action(SKIP, item, reason=f"{BLOCKED}; waiting for an administrator")]
    if item.is_pr:
        return actions + _decide_pr(item, labels, ctx)
    return actions + _decide_issue(item, labels, ctx)


def plan(items: Iterable[Item], ctx: Context) -> list[Action]:
    """Decide actions for every item and order them by priority."""
    if ctx.config.paused:
        return []
    actions = [action for item in items for action in decide(item, ctx)]
    return sorted(actions, key=lambda action: (action.priority, action.item.number))


def has_agent_label(item: Item) -> bool:
    return any(label.startswith(AGENT_LABEL_PREFIX) for label in item.labels)
