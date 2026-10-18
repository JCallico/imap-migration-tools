"""Code-authoring stages: implement an approved issue, then drive its pull request to green CI.

The model only edits files inside a sandboxed worktree. The dispatcher verifies the result outside the sandbox, applies
the diff policy, and performs every commit, push, and GitHub change itself as the GitHub App.
"""

from __future__ import annotations

import logging
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from . import ci, feedback, implementation, repo_ops, state
from .analysis import StageOutputError
from .authz import (
    APPROVE,
    NOTE,
    compose_notes,
    evaluate_approval,
    latest_analysis,
    looks_like_command,
    parse_command,
    strip_analysis_marker,
)
from .config import ModelRef
from .engines import (
    SECRET_READ_DENIALS,
    WORKSPACE_WRITE,
    EngineRun,
    build_command,
    is_readable_by_stages,
    run_engine,
    stage_environment,
)
from .gh import GhError
from .policy import check_diff
from .selection import select_author
from .snapshot import Item
from .stages import StageContext, _actual_model, _block, settle_run
from .stagestate import CODING, PR_OPEN, VERIFYING, IssueProgress, ProgressStore
from .verify import VerifyResult, run_verification
from .worktree import (
    WorktreeError,
    branch_worktree,
    commit_all,
    delete_local_branch,
    has_uncommitted_changes,
    head_sha,
    issue_branch,
    issue_number_from_branch,
    push_branch,
    remove_worktree,
    sync_with_remote,
    unpushed_commits,
)

log = logging.getLogger(__name__)


@dataclass
class Cycle:
    """Outcome of one model-plus-verification cycle."""

    line: str | None = None  # set when the cycle ended early: paused, blocked, deferred, or retrying
    result: implementation.ImplementationResult | None = None
    model: ModelRef | None = None
    verification: VerifyResult | None = None
    unchanged: bool = False  # the model changed nothing, which the stage allows; verification was skipped


@dataclass(frozen=True)
class CycleRules:
    """How a code-authoring stage's cycle differs from the implementation stage's."""

    contract: str = implementation.OUTPUT_CONTRACT
    validate: Callable[[str], object] | None = None  # extra output checks; raises StageOutputError
    allow_unchanged: bool = False  # a run that changes nothing is a valid outcome (for example, declined feedback)
    branch: str = ""


def _worktree_path(ctx: StageContext, issue_number: int) -> Path:
    return ctx.config.resolved_worktree_dir() / f"impl-{issue_number}"


def _store(ctx: StageContext) -> ProgressStore:
    return ProgressStore(ctx.runtime.state_dir / "stages")


def _bot_identity(ctx: StageContext) -> tuple[str, str]:
    login = ctx.runtime.bot_login or "imap-tools-agent[bot]"
    try:
        data = ctx.gh.api(f"users/{quote(login, safe='')}") or {}
        user_id = data.get("id")
    except GhError:
        user_id = None
    prefix = f"{user_id}+" if user_id else ""
    return login, f"{prefix}{login}@users.noreply.github.com"


def _administrator_notes(item: Item, ctx: StageContext, since: datetime) -> str:
    entries = []
    for comment in sorted(item.comments, key=lambda comment: comment.created_at):
        if comment.created_at <= since or ctx.authorizer.is_bot(comment.author):
            continue
        if not ctx.authorizer.comment_is_trusted(comment):
            continue
        command = parse_command(comment.body)
        if command is None and looks_like_command(comment.body):
            continue
        if command is not None and command.name in (APPROVE, NOTE):
            continue
        entries.append((comment, command))
    return compose_notes(entries) if entries else ""


def _run_model(
    ctx: StageContext,
    ref: ModelRef,
    worktree: Path,
    prompt: str,
    progress: IssueProgress,
    store: ProgressStore,
    deadline: float,
    interrupted: bool = False,
    contract: str = implementation.OUTPUT_CONTRACT,
) -> EngineRun:
    """Run the author model in the sandboxed worktree, resuming its session when there is one.

    ``interrupted`` marks the first call after an interrupted run: the resumed session then gets a generic "continue"
    prompt. Any other call resumes the session with its own prompt, for example verification failures to repair.
    """
    runtime = ctx.runtime
    config = ctx.config
    python = sys.executable
    resume = progress.session_id if progress.session_id and progress.engine == ref.engine else None
    for attempt in (1, 2):
        command = build_command(
            ref,
            cwd=worktree,
            sandbox=WORKSPACE_WRITE,
            resume_session=resume,
            max_turns=config.quota.max_turns,
            allowed_tools=implementation.implementation_allowed_tools(python),
            disallowed_tools=(*implementation.IMPLEMENTATION_DENIED_TOOLS, *SECRET_READ_DENIALS),
        )
        run = run_engine(
            ref,
            command,
            implementation.build_resume_prompt(contract) if resume and interrupted else prompt,
            cwd=worktree,
            env=stage_environment(runtime.environ, config.env_passthrough),
            timeout_seconds=max(60.0, deadline - time.monotonic()),
            runner=runtime.engine_runner,
        )
        if run.session_id:
            progress.session_id, progress.engine = run.session_id, ref.engine
            store.save(progress)
        kind = run.classification.kind if run.classification else ""
        if resume and attempt == 1 and kind in ("unknown", "task_failure"):
            log.info("could not resume session %s (%s); starting a fresh session", resume, kind)
            # The old session could not be resumed; start a fresh one that rediscovers the work from the worktree.
            progress.session_id = ""
            store.save(progress)
            resume = None
            continue
        return run
    return run


def _author_cycle(
    ctx: StageContext,
    item: Item,
    ref: ModelRef,
    worktree: Path,
    progress: IssueProgress,
    store: ProgressStore,
    prompt: str,
    deadline: float,
    rules: CycleRules = CycleRules(),
) -> Cycle:
    """Run the model until its work passes the dispatcher's verification, or the cycle must stop."""
    runtime = ctx.runtime
    policy = ctx.config.policy
    if progress.status == CODING:
        run = _run_model(
            ctx, ref, worktree, prompt, progress, store, deadline, interrupted=True, contract=rules.contract
        )
        stopped = settle_run(ctx, item, ref, run, "implementation")
        if stopped:
            return Cycle(line=stopped)
        try:
            result = implementation.parse_result(run.final_message)
            if rules.validate is not None and result.outcome != implementation.OUTCOME_BLOCKED:
                rules.validate(run.final_message)
        except StageOutputError as exc:
            return Cycle(line=_block(ctx, item, f"the implementation output was invalid ({exc})"))
        if result.outcome == implementation.OUTCOME_BLOCKED:
            return Cycle(line=_block_with_text(ctx, item, "the model reports it cannot implement this", result.blocker))
        progress.status, progress.result_json = VERIFYING, run.final_message
        progress.model = str(_actual_model(run, ref))
        store.save(progress)
        log.info("the model reports the change is complete; verifying outside the sandbox")
    model = ModelRef(*progress.model.split(":", 2)) if progress.model.count(":") == 2 else ref
    result = implementation.parse_result(progress.result_json)
    if (
        rules.allow_unchanged
        and not has_uncommitted_changes(worktree)
        and unpushed_commits(worktree, ctx.config.github.base_branch, rules.branch) == 0
    ):
        log.info("the model changed nothing; skipping verification")
        return Cycle(result=result, model=model, unchanged=True)
    while True:
        verification = run_verification(worktree, ctx.config.verify, runtime.environ, python=sys.executable)
        if verification.ok:
            log.info("verification passed")
            return Cycle(result=result, model=model, verification=verification)
        failed = sum(1 for step in verification.steps if not step.ok)
        log.info("verification failed (%d of %d steps)", failed, len(verification.steps))
        if progress.repair_rounds >= policy.max_verify_rounds:
            return Cycle(
                line=_block(ctx, item, f"the checks still fail after {policy.max_verify_rounds} repair rounds")
            )
        if time.monotonic() >= deadline:
            return Cycle(line=f"deferred #{item.number}: stage time limit reached; verification continues next tick")
        progress.repair_rounds += 1
        store.save(progress)
        log.info("repair round %d of %d", progress.repair_rounds, policy.max_verify_rounds)
        repair = implementation.build_verify_repair_prompt(
            verification.failure_report(), progress.repair_rounds, policy.max_verify_rounds, rules.contract
        )
        run = _run_model(ctx, ref, worktree, repair, progress, store, deadline, contract=rules.contract)
        stopped = settle_run(ctx, item, ref, run, "repair")
        if stopped:
            progress.repair_rounds -= 1
            store.save(progress)
            return Cycle(line=stopped)
        try:
            result = implementation.parse_result(run.final_message)
            if rules.validate is not None and result.outcome != implementation.OUTCOME_BLOCKED:
                rules.validate(run.final_message)
        except StageOutputError as exc:
            return Cycle(line=_block(ctx, item, f"the repair output was invalid ({exc})"))
        if result.outcome == implementation.OUTCOME_BLOCKED:
            return Cycle(
                line=_block_with_text(ctx, item, "the model reports it cannot fix the failures", result.blocker)
            )
        progress.result_json = run.final_message
        progress.model = str(_actual_model(run, ref))
        store.save(progress)


def _block_with_text(ctx: StageContext, item: Item, reason: str, model_text: str) -> str:
    """Block with a model-written explanation, withheld if it looks like a credential and with mentions neutralized."""
    if implementation.contains_secret(model_text):
        return _block(ctx, item, f"{reason} (the explanation was withheld: it contained a possible credential)")
    text = implementation.public_text(" ".join(model_text.split()))[:500]
    return _block(ctx, item, f"{reason}: {text}")


def _commit_and_push(
    ctx: StageContext,
    item: Item,
    worktree: Path,
    branch: str,
    cycle: Cycle,
    message: str,
) -> str | None:
    """Commit, apply the diff policy, and push. Returns a result line only when work must stop."""
    runtime = ctx.runtime
    config = ctx.config
    base = config.github.base_branch
    name, email = _bot_identity(ctx)
    try:
        sha = commit_all(worktree, message, name, email)
    except WorktreeError as exc:
        return _block(ctx, item, f"could not commit the change ({exc})")
    if sha is None and unpushed_commits(worktree, base, branch) == 0:
        return _block(ctx, item, "the model made no changes")
    violations = check_diff(worktree, f"origin/{base}", config.policy)
    log.info("diff policy: %s", f"{len(violations)} violation(s)" if violations else "passed")
    if violations:
        return _block(ctx, item, "the change violates the diff policy: " + "; ".join(str(v) for v in violations[:5]))
    try:
        remote_url = runtime.remote_url or f"https://github.com/{runtime.gh.repo}.git"
        push_branch(worktree, remote_url, branch, runtime.gh.token_provider(), runtime.environ)
    except (WorktreeError, RuntimeError) as exc:
        return _block(ctx, item, f"could not push {branch} ({exc})")
    return None


def _existing_pull_request(ctx: StageContext, branch: str) -> dict | None:
    owner, name = ctx.gh.repo_parts()
    found = ctx.gh.api(f"repos/{owner}/{name}/pulls", fields={"head": f"{owner}:{branch}", "state": "open"}) or []
    return found[0] if found else None


def run_implementation(ctx: StageContext, action: state.Action) -> str:
    """Implement an approved issue on its own branch and open a draft pull request."""
    runtime = ctx.runtime
    config = ctx.config
    item = action.item
    ref = action.model
    assert ref is not None
    store = _store(ctx)
    progress = store.load(item.number)

    decision = evaluate_approval(
        item, ctx.authorizer, datetime.now(timezone.utc), config.policy.revision_debounce_minutes
    )
    if decision.status != "approved" or decision.analysis is None:
        return _block(
            ctx, item, f"the approval is no longer valid ({decision.status}); approve the current analysis again"
        )
    analysis = decision.analysis
    spec = strip_analysis_marker(analysis.comment.body)
    approver = decision.command.author if decision.command else None

    if progress.pr_number:
        owner, name = ctx.gh.repo_parts()
        pull = ctx.gh.api(f"repos/{owner}/{name}/pulls/{progress.pr_number}") or {}
        if pull.get("state") != "open":
            verb = "merged" if pull.get("merged_at") else "closed without merging"
            return _block(ctx, item, f"pull request #{progress.pr_number} was {verb}; decide whether to retry")

    log.info("approval by %s of analysis revision %s is still valid", approver or "unknown", analysis.rev)
    repo_ops.set_labels(
        ctx.gh,
        item,
        add=[state.IMPLEMENTING, *action.add_labels],
        remove=[state.AWAITING_APPROVAL, state.WAITING_QUOTA, *action.remove_labels],
    )
    branch = progress.branch or issue_branch(item.number, item.title)
    path = _worktree_path(ctx, item.number)
    if not is_readable_by_stages(path):
        return _block(ctx, item, f"the worktree directory {path} lies inside a location stages may not read")
    base = config.github.base_branch
    try:
        worktree = branch_worktree(runtime.repo_root, branch, base, path)
    except WorktreeError as exc:
        return _block(ctx, item, f"could not prepare the branch worktree ({exc})")
    progress.branch, progress.worktree, progress.stage = branch, str(worktree), "implementation"
    store.save(progress)

    skill = implementation.load_skill(runtime.repo_root)
    prompt = implementation.build_implementation_prompt(
        skill,
        title=item.title,
        spec=spec,
        admin_notes=_administrator_notes(item, ctx, analysis.since),
        base_branch=base,
        python=sys.executable,
        resumed=bool(progress.session_id) or has_uncommitted_changes(worktree),
    )
    deadline = time.monotonic() + config.quota.max_stage_minutes * 60
    cycle = _author_cycle(ctx, item, ref, worktree, progress, store, prompt, deadline)
    if cycle.line or cycle.result is None or cycle.verification is None or cycle.model is None:
        return cycle.line or f"deferred #{item.number}"
    if implementation.contains_secret(cycle.result.title, cycle.result.summary, *cycle.result.notes):
        return _block(ctx, item, "the model's summary contained a possible credential and was not published")

    message = implementation.commit_message(cycle.result, item.number, cycle.model)
    stopped = _commit_and_push(ctx, item, worktree, branch, cycle, message)
    if stopped:
        return stopped
    body = implementation.render_pr_body(
        cycle.result,
        issue_number=item.number,
        approver=approver,
        analysis_rev=analysis.rev,
        analysis_hash=analysis.hash,
        model=cycle.model,
        verification_summary=cycle.verification.summary(),
        test_summary=cycle.verification.test_summary(),
    )
    owner, name = ctx.gh.repo_parts()
    pull = _existing_pull_request(ctx, branch)
    if pull is None:
        log.info("opening a draft pull request from %s into %s", branch, base)
        pull = ctx.gh.api(
            f"repos/{owner}/{name}/pulls",
            method="POST",
            body={"title": cycle.result.title, "head": branch, "base": base, "body": body, "draft": True},
        )
    number = int(pull["number"])
    repo_ops.add_labels(ctx.gh, number, [state.IMPLEMENTING])
    repo_ops.post_comment(
        ctx.gh,
        number,
        f"Draft pull request opened by the agent loop. I will watch CI for each commit, repair failures "
        f"(up to {config.policy.max_ci_fix_attempts} attempts), and mark it ready for AI review once the required "
        f"checks pass.\n\n{state.run_marker('implementation', cycle.model)}",
    )
    repo_ops.post_comment(ctx.gh, item.number, f"Implementation is under way in draft pull request #{number}.")
    repo_ops.clear_status(ctx.gh, item, runtime.bot_login)
    progress.status, progress.pr_number = PR_OPEN, number
    store.save(progress)
    return f"implemented issue #{item.number} with {cycle.model}: opened draft PR #{number}"


def _ci_attempts(pr: Item, ctx: StageContext) -> int:
    return sum(1 for stage, _model in state.run_markers(pr, ctx.authorizer) if stage == "ci_fix")


def _finalize_pull_request(ctx: StageContext, pr: Item, issue_number: int | None, sha: str) -> str:
    """Mark the pull request ready and hand it to the AI review stage."""
    runtime = ctx.runtime
    if pr.is_draft and pr.node_id:
        ctx.gh.graphql(
            "mutation($id: ID!) { markPullRequestReadyForReview(input: {pullRequestId: $id}) { pullRequest { isDraft } } }",
            {"id": pr.node_id},
        )
    repo_ops.set_labels(ctx.gh, pr, add=[state.AI_REVIEW], remove=[state.IMPLEMENTING, state.WAITING_QUOTA])
    repo_ops.clear_status(ctx.gh, pr, runtime.bot_login)
    repo_ops.post_comment(
        ctx.gh, pr.number, f"All required checks passed for `{sha[:12]}`. This pull request is ready for AI review."
    )
    if issue_number is not None:
        remove_worktree(runtime.repo_root, _worktree_path(ctx, issue_number))
        delete_local_branch(runtime.repo_root, pr.head_ref or "")
    return f"PR #{pr.number} is green and ready for AI review"


def check_ci(ctx: StageContext, action: state.Action) -> str:
    """Advance a draft pull request: wait for CI, repair failures, or mark it ready for review."""
    runtime = ctx.runtime
    config = ctx.config
    pr = action.item
    sha = pr.head_sha or ""
    base = config.github.base_branch
    cache = runtime.cache
    if "required" not in cache:
        cache["required"] = ci.required_contexts(ctx.gh, base)
    status = ci.check_status(ctx.gh, sha, cache["required"])
    log.info("CI for PR #%d at %s: %s (%s)", pr.number, sha[:12], status.state, status.describe())
    issue_number = issue_number_from_branch(pr.head_ref)
    if status.state == ci.PENDING:
        return f"waiting for CI on PR #{pr.number}: {status.describe()}"
    if status.state == ci.GREEN:
        return _finalize_pull_request(ctx, pr, issue_number, sha)

    attempts = _ci_attempts(pr, ctx)
    limit = config.policy.max_ci_fix_attempts
    names = ", ".join(check.name for check in status.failed[:5])
    if attempts >= limit:
        return _block(ctx, pr, f"CI is still failing after {limit} repair attempts ({names})")
    if issue_number is None or not pr.head_ref:
        return _block(ctx, pr, f"CI failed ({names}) on a branch the agent loop does not manage")
    if not runtime.take_budget():
        return f"deferred to the next tick: repair CI failures on PR #{pr.number} ({names})"

    selection = select_author(
        config,
        "ci_fix",
        lambda engine, long: runtime.ledger.usable(engine, long_stage=long),
        state.author_models(pr, ctx.authorizer),
    )
    if selection.waiting or selection.model is None:
        repo_ops.set_labels(ctx.gh, pr, add=[state.WAITING_QUOTA])
        return f"waiting: CI repair for PR #{pr.number} — {selection.reason}"
    ref = selection.model
    return _repair_ci(ctx, action, ref, status, attempts + 1, issue_number)


def _repair_ci(
    ctx: StageContext, action: state.Action, ref: ModelRef, status: ci.CIStatus, attempt: int, issue_number: int
) -> str:
    runtime = ctx.runtime
    config = ctx.config
    pr = action.item
    branch = pr.head_ref or ""
    store = _store(ctx)
    progress = store.load(issue_number)
    path = _worktree_path(ctx, issue_number)
    base = config.github.base_branch
    repo_ops.set_labels(ctx.gh, pr, remove=[state.WAITING_QUOTA])
    try:
        worktree = branch_worktree(runtime.repo_root, branch, base, path)
        sync_with_remote(worktree, branch)
    except WorktreeError as exc:
        return _block(ctx, pr, f"could not prepare the branch worktree ({exc})")
    issue = action.related
    analysis = latest_analysis(issue, ctx.authorizer) if issue is not None else None
    spec = strip_analysis_marker(analysis.comment.body) if analysis else ""
    skill = implementation.load_skill(runtime.repo_root)
    prompt = implementation.build_ci_repair_prompt(
        skill,
        title=issue.title if issue else pr.title,
        spec=spec,
        failures=ci.failure_logs(ctx.gh, status),
        base_branch=base,
        python=sys.executable,
        attempt=attempt,
        attempts=config.policy.max_ci_fix_attempts,
    )
    progress.branch, progress.worktree = branch, str(worktree)
    progress.status, progress.session_id, progress.result_json, progress.repair_rounds = CODING, "", "", 0
    progress.stage = "ci_fix"
    store.save(progress)
    deadline = time.monotonic() + config.quota.max_stage_minutes * 60
    cycle = _author_cycle(ctx, pr, ref, worktree, progress, store, prompt, deadline)
    if cycle.line or cycle.result is None or cycle.verification is None or cycle.model is None:
        return cycle.line or f"deferred PR #{pr.number}"
    if implementation.contains_secret(cycle.result.title, cycle.result.summary, *cycle.result.notes):
        return _block(ctx, pr, "the model's summary contained a possible credential and was not published")
    message = (
        f"{implementation.public_text(cycle.result.title)}\n\n{implementation.public_text(cycle.result.summary)}\n\n"
        f"Repairs failing CI for #{issue_number} (attempt {attempt})."
    )
    stopped = _commit_and_push(ctx, pr, worktree, branch, cycle, message)
    if stopped:
        return stopped
    notes = "".join(f"\n- {implementation.public_text(note)}" for note in cycle.result.notes)
    failed = ", ".join(check.name for check in status.failed[:5])
    repo_ops.post_comment(
        ctx.gh,
        pr.number,
        f"CI repair attempt {attempt}/{config.policy.max_ci_fix_attempts} for {failed}: "
        f"{implementation.public_text(cycle.result.summary)}{notes}\n\nVerified locally before pushing "
        f"`{head_sha(worktree)[:12]}`.\n\n{state.run_marker('ci_fix', cycle.model)}",
    )
    progress.status = PR_OPEN
    store.save(progress)
    return f"repaired CI on PR #{pr.number} with {cycle.model} (attempt {attempt}); waiting for new checks"


FEEDBACK_SKILL_PATH = Path(".claude") / "skills" / "address-review-feedback" / "SKILL.md"


def _feedback_reply(response: feedback.Response, changed: bool, sha: str) -> str:
    commit = f" Changed in `{sha[:12]}`." if response.decision == feedback.FIXED and changed else ""
    return f"**{feedback.decision_label(response.decision)}.** {implementation.public_text(response.reply)}{commit}"


def run_feedback(ctx: StageContext, action: state.Action) -> str:
    """Address administrator and AI review feedback on a pull request, then send it back through CI and review."""
    runtime = ctx.runtime
    config = ctx.config
    pr = action.item
    ref = action.model
    assert ref is not None
    branch = pr.head_ref or ""
    issue_number = issue_number_from_branch(branch)
    if issue_number is None or not branch.startswith("agent/"):
        return _block(ctx, pr, "review feedback is applied only to agent/* branches the loop created")
    repo_ops.set_labels(
        ctx.gh,
        pr,
        add=[state.CHANGES_REQUESTED, *action.add_labels],
        remove=[state.WAITING_QUOTA, *action.remove_labels],
    )
    items = feedback.collect_items(pr, feedback.fetch_review_threads(ctx.gh, pr.number), ctx.authorizer)
    if not items:
        return _block(
            ctx, pr, "changes were requested, but no review item from an administrator or the AI reviewer is open"
        )
    log.info("addressing %d review item(s) on PR #%d", len(items), pr.number)
    store = _store(ctx)
    progress = store.load(issue_number)
    path = _worktree_path(ctx, issue_number)
    base = config.github.base_branch
    if not is_readable_by_stages(path):
        return _block(ctx, pr, f"the worktree directory {path} lies inside a location stages may not read")
    try:
        worktree = branch_worktree(runtime.repo_root, branch, base, path)
        sync_with_remote(worktree, branch)
    except WorktreeError as exc:
        return _block(ctx, pr, f"could not prepare the branch worktree ({exc})")
    issue = action.related
    analysis = latest_analysis(issue, ctx.authorizer) if issue is not None else None
    skill_path = runtime.repo_root / FEEDBACK_SKILL_PATH
    if not skill_path.is_file():
        raise FileNotFoundError(f"feedback skill not found: {skill_path}")
    prompt = feedback.build_prompt(
        skill_path.read_text(encoding="utf-8"),
        title=issue.title if issue else pr.title,
        spec=strip_analysis_marker(analysis.comment.body) if analysis else "",
        items=items,
        base_branch=base,
        python=sys.executable,
    )
    if progress.stage != "feedback" or progress.status == PR_OPEN:
        progress.status, progress.session_id, progress.result_json, progress.repair_rounds = CODING, "", "", 0
        progress.stage = "feedback"
    progress.branch, progress.worktree = branch, str(worktree)
    store.save(progress)
    ids = [item.id for item in items]
    rules = CycleRules(
        contract=feedback.FEEDBACK_CONTRACT,
        validate=lambda text: feedback.parse_responses(text, ids),
        allow_unchanged=True,
        branch=branch,
    )
    deadline = time.monotonic() + config.quota.max_stage_minutes * 60
    cycle = _author_cycle(ctx, pr, ref, worktree, progress, store, prompt, deadline, rules)
    if (
        cycle.line
        or cycle.result is None
        or cycle.model is None
        or (cycle.verification is None and not cycle.unchanged)
    ):
        return cycle.line or f"deferred PR #{pr.number}"
    try:
        responses = feedback.parse_responses(progress.result_json, ids)
    except StageOutputError as exc:
        return _block(ctx, pr, f"the feedback responses no longer match the open review items ({exc})")
    texts = [cycle.result.summary, *cycle.result.notes, *(response.reply for response in responses.values())]
    if implementation.contains_secret(*texts):
        return _block(ctx, pr, "the feedback responses contained a possible credential and were not published")

    changed = not cycle.unchanged
    if changed:
        message = (
            f"Address review feedback on #{pr.number}\n\n{implementation.public_text(cycle.result.summary)}\n\n"
            f"Responds to {len(items)} review item(s) for #{issue_number}."
        )
        stopped = _commit_and_push(ctx, pr, worktree, branch, cycle, message)
        if stopped:
            return stopped
    sha = head_sha(worktree)
    lines = []
    for item in items:
        response = responses[item.id]
        reply = _feedback_reply(response, changed, sha)
        if item.is_thread:
            repo_ops.reply_to_review_thread(ctx.gh, item.thread_id, reply)
            if response.decision == feedback.FIXED and changed and item.source == "ai_reviewer":
                repo_ops.resolve_review_thread(ctx.gh, item.thread_id)
        lines.append(f"- {item.describe()}: {reply}")
    heading = f"Addressed review feedback in `{sha[:12]}`." if changed else "Answered review feedback; no code changed."
    verified = f"\n\nVerified before pushing ({cycle.verification.test_summary()})." if cycle.verification else ""
    repo_ops.post_comment(
        ctx.gh,
        pr.number,
        f"{heading} {implementation.public_text(cycle.result.summary)}\n\n"
        + "\n".join(lines)
        + verified
        + f"\n\n{state.run_marker('feedback', cycle.model)}",
    )
    current = (pr.labels | {state.CHANGES_REQUESTED, *action.add_labels}) - set(action.remove_labels)
    repo_ops.set_labels(
        ctx.gh,
        replace(pr, labels=frozenset(current)),
        add=[state.IMPLEMENTING],
        remove=[state.CHANGES_REQUESTED, state.WAITING_QUOTA],
    )
    progress.status, progress.stage = PR_OPEN, ""
    store.save(progress)
    escalated = [item.describe() for item in items if responses[item.id].decision == feedback.NEEDS_ADMIN]
    if escalated:
        return _block(ctx, pr, "the author model needs your decision on: " + "; ".join(escalated))
    return f"addressed {len(items)} review item(s) on PR #{pr.number} with {cycle.model}; waiting for CI"
