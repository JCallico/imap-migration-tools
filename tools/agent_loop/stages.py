"""Stage runners: execute a model-backed stage for one item and apply its outcome on GitHub."""

from __future__ import annotations

import time
from dataclasses import dataclass, replace

from . import analysis, repo_ops, state
from .authz import Authorizer, latest_analysis
from .config import ModelRef
from .engines import (
    READ_ONLY,
    SECRET_READ_DENIALS,
    EngineRun,
    build_command,
    is_readable_by_stages,
    run_engine,
    stage_environment,
)
from .notify import GitHubNotifier, Notification
from .quota import AUTH, QUOTA_EXHAUSTED, SUCCESS, TRANSIENT, UNCLASSIFIED
from .worktree import WorktreeError, detached_checkout


@dataclass
class StageContext:
    """What a stage runner needs from the dispatcher runtime."""

    runtime: object  # dispatcher.Runtime; typed loosely to avoid an import cycle
    authorizer: Authorizer

    @property
    def gh(self):
        return self.runtime.gh

    @property
    def config(self):
        return self.runtime.config


def _actual_model(run: EngineRun, requested: ModelRef) -> ModelRef:
    """Record the model the engine reported using; fall back to the requested one."""
    if len(run.actual_models) == 1:
        return replace(requested, model=next(iter(run.actual_models)))
    return requested


def _notify(ctx: StageContext, item, key: str, message: str) -> None:
    notifier = GitHubNotifier(ctx.gh, ctx.config.notify.mention)
    notifier.send(Notification(item.number, key, message, is_pr=item.is_pr))


def _block(ctx: StageContext, item, reason: str) -> str:
    """Stop work on an item and ask the administrator to decide; never echoes model output."""
    repo_ops.set_labels(ctx.gh, item, add=[state.BLOCKED], remove=[state.WAITING_QUOTA])
    _notify(ctx, item, f"blocked-{item.number}-{len(item.comments)}", f"Needs your decision: {reason.rstrip('. ')}.")
    return f"blocked {'PR' if item.is_pr else 'issue'} #{item.number}: {reason}"


def _pause_for_quota(ctx: StageContext, item, engine: str) -> str:
    entry = ctx.runtime.ledger.get(engine)
    when = time.strftime("%Y-%m-%d %H:%M %Z", time.localtime(entry.resume_at)) if entry.resume_at else "later"
    repo_ops.set_labels(ctx.gh, item, add=[state.WAITING_QUOTA])
    repo_ops.upsert_status(
        ctx.gh,
        item,
        ctx.runtime.bot_login,
        f"Paused: the {engine} subscription limit was reached. Work resumes automatically after about {when}.",
    )
    return f"paused {'PR' if item.is_pr else 'issue'} #{item.number}: {engine} {entry.status} until {when}"


def settle_run(ctx: StageContext, item, ref: ModelRef, run: EngineRun, what: str) -> str | None:
    """Record a run's quota effects; return a result line when the run did not succeed, otherwise ``None``."""
    runtime = ctx.runtime
    if run.snapshot is not None:
        runtime.ledger.record_snapshot(run.snapshot)
    classification = run.classification
    assert classification is not None
    runtime.ledger.record_classification(ref.engine, classification)
    kind = "PR" if item.is_pr else "issue"
    if classification.kind in (QUOTA_EXHAUSTED, UNCLASSIFIED):
        return _pause_for_quota(ctx, item, ref.engine)
    if classification.kind == TRANSIENT:
        return f"retrying {kind} #{item.number} next tick: transient {ref.engine} error"
    if classification.kind == AUTH:
        return _block(ctx, item, f"the {ref.engine} CLI reported an authentication problem; run `agent_loop doctor`")
    if classification.kind != SUCCESS:
        return _block(ctx, item, f"the {what} run did not complete ({classification.detail or classification.kind})")
    return None


def run_analysis(ctx: StageContext, action: state.Action) -> str:
    """Analyze an issue read-only and post either a spec for approval or questions for the reporter."""
    runtime = ctx.runtime
    item = action.item
    ref = action.model
    assert ref is not None
    config = ctx.config
    skill_text = analysis.load_skill(runtime.repo_root)
    repo_ops.set_labels(ctx.gh, item, add=[state.ANALYZING, *action.add_labels], remove=action.remove_labels)
    previous = latest_analysis(item, ctx.authorizer)
    # Comments posted while the model runs are newer than this and are picked up by the next tick.
    seen = max([item.created_at, *(comment.created_at for comment in item.comments)])
    checkout = config.resolved_worktree_dir() / f"issue-{item.number}"
    if not is_readable_by_stages(checkout):
        # Reading the checkout would be denied by the stage's own secret-protection rules.
        return _block(
            ctx, item, f"the checkout directory {checkout} lies inside a location stages may not read; set worktree_dir"
        )
    try:
        with detached_checkout(runtime.repo_root, config.github.base_branch, checkout) as base_sha:
            prompt = analysis.build_prompt(
                item,
                ctx.authorizer,
                skill_text,
                base_branch=config.github.base_branch,
                base_sha=base_sha,
                previous=previous,
                revision_notes=action.notes,
            )
            command = build_command(
                ref,
                cwd=checkout,
                sandbox=READ_ONLY,
                max_turns=config.quota.max_turns,
                allowed_tools=analysis.ANALYSIS_ALLOWED_TOOLS,
                disallowed_tools=(*analysis.ANALYSIS_DENIED_TOOLS, *SECRET_READ_DENIALS),
            )
            run = run_engine(
                ref,
                command,
                prompt,
                cwd=checkout,
                env=stage_environment(runtime.environ, config.env_passthrough),
                timeout_seconds=config.quota.max_stage_minutes * 60,
                runner=runtime.engine_runner,
            )
    except WorktreeError as exc:
        return _block(ctx, item, f"could not prepare a checkout of `{config.github.base_branch}` ({exc})")

    stopped = settle_run(ctx, item, ref, run, "analysis")
    if stopped:
        return stopped

    try:
        result = analysis.parse_result(run.final_message)
    except analysis.StageOutputError as exc:
        return _block(ctx, item, f"the analysis output was invalid ({exc})")

    model = _actual_model(run, ref)
    marker = state.run_marker("analysis", model)
    mention = config.notify.mention
    if result.outcome == analysis.OUTCOME_ANALYSIS:
        body = analysis.render_analysis(
            item,
            result,
            rev=(previous.rev + 1) if previous else 1,
            model=model,
            run_marker=marker,
            mention=mention,
            base_branch=config.github.base_branch,
            base_sha=base_sha,
            seen=seen,
            revised=bool(action.notes),
        )
        next_label = state.AWAITING_APPROVAL
    else:
        body = analysis.render_needs_info(
            item,
            result,
            model=model,
            run_marker=marker,
            mention=mention,
            base_branch=config.github.base_branch,
            base_sha=base_sha,
        )
        next_label = state.NEEDS_INFO
    secrets = analysis.find_secrets(body)
    if secrets:
        return _block(ctx, item, f"the analysis output contained a possible {', '.join(secrets)} and was not posted")

    repo_ops.post_comment(ctx.gh, item.number, body)
    repo_ops.clear_status(ctx.gh, item, runtime.bot_login)
    current = (item.labels - set(action.remove_labels)) | {state.ANALYZING, *action.add_labels}
    stale = (state.ANALYZING, state.WAITING_QUOTA, state.AWAITING_APPROVAL, state.NEEDS_INFO)
    repo_ops.set_labels(
        ctx.gh,
        replace(item, labels=frozenset(current)),
        add=[next_label],
        remove=[label for label in stale if label != next_label],
    )
    if next_label == state.AWAITING_APPROVAL:
        repo_ops.assign(ctx.gh, item.number, mention)
    mismatch = " (model differed from the configured one)" if run.model_mismatch else ""
    return f"analyzed issue #{item.number} with {model}{mismatch}: {next_label}"
