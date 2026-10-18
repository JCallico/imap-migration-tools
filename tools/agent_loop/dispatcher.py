"""Dispatcher operations: one tick of the state machine, status reporting, and environment diagnostics."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

from filelock import FileLock, Timeout

from . import repo_ops, state
from .app_auth import AppAuthError, AppTokenProvider, check_private_key_file, provider_from_config
from .authz import Authorizer
from .config import AUTHOR_STAGES, LoopConfig
from .engines import (
    BLOCKED_VARIABLES,
    codex_models,
    is_blocked_variable,
    subscription_status,
)
from .gh import Gh, GhError, detect_repo
from .notify import GitHubNotifier, Notification
from .quota import QuotaLedger
from .runners import RUNNERS, check_ci
from .selection import reviewer_allowed
from .snapshot import fetch_open_items
from .stages import StageContext
from .stagestate import ProgressStore
from .worktree import WorktreeError, delete_local_branch, issue_number_from_branch, remove_worktree, repository_root

log = logging.getLogger(__name__)

PAUSE_FILE = "paused"


class DispatcherError(RuntimeError):
    """Raised when the dispatcher cannot run safely."""


@dataclass
class Runtime:
    config: LoopConfig
    gh: Gh
    token_provider: AppTokenProvider | None
    bot_login: str | None
    state_dir: Path
    ledger: QuotaLedger
    repo_root: Path = field(default_factory=Path.cwd)
    environ: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))
    engine_runner: Callable[..., subprocess.CompletedProcess] = subprocess.run
    remote_url: str | None = None  # push target override; defaults to the repository's GitHub HTTPS URL
    budget: int = 1  # model-backed stage runs still allowed in this tick
    cache: dict = field(default_factory=dict)  # per-tick lookups such as the required status checks

    def take_budget(self) -> bool:
        """Use one of this tick's model-backed stage runs; ``False`` when none remain."""
        if self.budget <= 0:
            return False
        self.budget -= 1
        return True


def build_runtime(config: LoopConfig, *, require_app: bool) -> Runtime:
    """Resolve the repository, App identity, and local state for a dispatcher command."""
    repo = config.github.repo or detect_repo()
    if not repo:
        raise DispatcherError("could not determine the repository; set [github] repo or AGENT_LOOP_REPO")
    config = replace(config, github=replace(config.github, repo=repo))
    github = config.github
    try:
        provider = provider_from_config(github)
    except AppAuthError as exc:
        raise DispatcherError(str(exc)) from exc
    if require_app and provider is None:
        raise DispatcherError(
            "GitHub App credentials are required for changes on GitHub; see docs/agent-loop.md#github-app-setup"
        )
    bot_login = github.bot_login
    if bot_login is None and provider is not None:
        try:
            slug = provider.app_info().get("slug")
        except AppAuthError as exc:
            raise DispatcherError(str(exc)) from exc
        bot_login = f"{slug}[bot]" if slug else None
    state_dir = config.resolved_state_dir()
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    ledger = QuotaLedger(
        state_dir / "quota.json",
        low_threshold_percent=config.quota.low_threshold_percent,
        unknown_backoff_max_hours=config.quota.unknown_backoff_max_hours,
    )
    try:
        repo_root = repository_root()
    except WorktreeError as exc:
        raise DispatcherError("run the dispatcher from inside a checkout of the repository") from exc
    return Runtime(
        config, Gh(repo, token_provider=provider), provider, bot_login, state_dir, ledger, repo_root=repo_root
    )


def is_paused(runtime: Runtime) -> bool:
    return runtime.config.paused or (runtime.state_dir / PAUSE_FILE).exists()


def set_paused(runtime: Runtime, paused: bool) -> None:
    marker = runtime.state_dir / PAUSE_FILE
    if paused:
        marker.write_text(datetime.now(timezone.utc).isoformat() + "\n", encoding="utf-8")
    else:
        marker.unlink(missing_ok=True)


def _usable(runtime: Runtime):
    def usable(engine: str, long_stage: bool):
        return runtime.ledger.usable(engine, long_stage=long_stage)

    return usable


def _authorizer(runtime: Runtime) -> Authorizer:
    return Authorizer(runtime.gh, runtime.bot_login, runtime.config.github.allowed_admins)


def plan_actions(runtime: Runtime, authorizer: Authorizer | None = None, items=None) -> list[state.Action]:
    authorizer = authorizer or _authorizer(runtime)
    ctx = state.Context(runtime.config, authorizer, _usable(runtime), datetime.now(timezone.utc))
    return state.plan(items if items is not None else fetch_open_items(runtime.gh), ctx)


def cleanup_worktrees(runtime: Runtime, items) -> list[str]:
    """Remove implementation worktrees (and their local branches) for work that is no longer in progress."""
    root = runtime.config.resolved_worktree_dir()
    if not root.is_dir():
        return []
    issues = {item.number: item for item in items if not item.is_pr}
    pulls = {issue_number_from_branch(item.head_ref): item for item in items if item.is_pr}
    store = ProgressStore(runtime.state_dir / "stages")
    removed = []
    for path in sorted(root.glob("impl-*")):
        suffix = path.name.removeprefix("impl-")
        if not suffix.isdigit():
            continue
        number = int(suffix)
        issue, pull = issues.get(number), pulls.get(number)
        if (
            issue is not None
            and state.IMPLEMENTING in issue.labels
            and (pull is None or {state.IMPLEMENTING, state.CHANGES_REQUESTED} & pull.labels)
        ):
            continue
        log.info("removing finished worktree %s", path)
        remove_worktree(runtime.repo_root, path)
        branch = store.load(number).branch
        if branch:
            delete_local_branch(runtime.repo_root, branch)
        removed.append(f"removed finished worktree {path.name}")
    return removed


def execute(runtime: Runtime, action: state.Action, authorizer: Authorizer | None = None) -> str:
    """Execute one planned action on GitHub."""
    number = action.item.number
    if action.kind == state.REVERT_LABEL and action.event is not None:
        if action.event.added:
            repo_ops.remove_label(runtime.gh, number, action.event.label)
        else:
            repo_ops.add_labels(runtime.gh, number, [action.event.label])
        return f"reverted: {action.describe()}"
    if action.kind == state.SET_LABELS:
        repo_ops.add_labels(runtime.gh, number, action.add_labels)
        for label in action.remove_labels:
            repo_ops.remove_label(runtime.gh, number, label)
        if state.BLOCKED in action.add_labels:
            notifier = GitHubNotifier(runtime.gh, runtime.config.notify.mention)
            key = f"blocked-{number}-{action.item.head_sha or len(action.item.comments)}"
            notifier.send(
                Notification(
                    number, key, f"Needs your decision: {action.reason.rstrip('. ')}.", is_pr=action.item.is_pr
                )
            )
        return f"done: {action.describe()}"
    if action.kind == state.REPLY_UNAUTHORIZED and action.comment_id:
        owner, name = runtime.gh.repo_parts()
        body = (
            "This command was ignored: only repository administrators can issue agent loop commands.\n\n"
            + state.unauthorized_marker(action.comment_id)
        )
        runtime.gh.api(f"repos/{owner}/{name}/issues/{number}/comments", method="POST", body={"body": body})
        return f"done: {action.describe()}"
    if action.kind == state.REACT:
        for comment_id in action.comment_ids:
            repo_ops.react(runtime.gh, comment_id)
        return f"acknowledged: {action.describe()}"
    if action.kind == state.WAIT and action.quota_wait and not action.item.is_pr:
        if state.WAITING_QUOTA not in action.item.labels:
            repo_ops.add_labels(runtime.gh, number, [state.WAITING_QUOTA])
        return f"waiting: {action.describe()}"
    if action.kind == state.CHECK_CI:
        authorizer = authorizer or _authorizer(runtime)
        authorizer.refresh()
        return check_ci(StageContext(runtime, authorizer), action)
    if action.kind == state.RUN_STAGE:
        runner = RUNNERS.get(action.stage or "")
        if runner is None:
            return f"pending (stage runner not yet available): {action.describe()}"
        authorizer = authorizer or _authorizer(runtime)
        authorizer.refresh()  # permissions are re-checked when work actually starts
        return runner(StageContext(runtime, authorizer), action)
    return action.describe()


def tick(runtime: Runtime, *, dry_run: bool) -> list[str]:
    """Run one dispatcher pass under a cross-process lock."""
    lock = FileLock(str(runtime.state_dir / "tick.lock"))
    try:
        lock.acquire(timeout=0)
    except Timeout as exc:
        raise DispatcherError("another tick is already running") from exc
    try:
        if is_paused(runtime):
            return ["agent loop is paused; no actions taken"]
        if not dry_run and not runtime.gh.as_app:
            raise DispatcherError("live ticks must run as the GitHub App; use --dry-run or configure the App")
        if runtime.bot_login is None and not dry_run:
            raise DispatcherError("bot login unknown; set [github] bot_login or configure the GitHub App")
        authorizer = _authorizer(runtime)
        log.info("tick started for %s%s as %s", runtime.gh.repo, " (dry run)" if dry_run else "", runtime.bot_login)
        items = fetch_open_items(runtime.gh)
        log.info(
            "fetched %d open item(s): %d issue(s), %d pull request(s)",
            len(items),
            sum(1 for item in items if not item.is_pr),
            sum(1 for item in items if item.is_pr),
        )
        actions = plan_actions(runtime, authorizer, items)
        log.info("planned %d action(s)", len(actions))
        if dry_run:
            lines = [f"[dry-run] {action.describe()}" for action in actions]
            if runtime.bot_login is None:
                lines.insert(0, "[dry-run] bot identity unknown: existing analyses and run markers are not recognized")
        else:
            lines = _execute_all(runtime, actions, authorizer)
            lines += cleanup_worktrees(runtime, items)
        _log_tick(runtime, dry_run, lines)
        log.info("tick finished")
        return lines or ["no open items require action"]
    finally:
        lock.release()


def _execute_all(runtime: Runtime, actions: list[state.Action], authorizer: Authorizer) -> list[str]:
    """Execute actions in priority order, limiting model-backed stage runs per tick."""
    lines = []
    runtime.budget = runtime.config.policy.max_stage_runs_per_tick
    runtime.cache = {}
    for index, action in enumerate(actions, 1):
        if action.kind == state.RUN_STAGE and action.stage in RUNNERS:
            if not runtime.take_budget():
                log.info("[%d/%d] deferred (stage run budget used): %s", index, len(actions), action.describe())
                lines.append(f"deferred to the next tick: {action.describe()}")
                continue
        log.info("[%d/%d] %s", index, len(actions), action.describe())
        started = time.monotonic()
        try:
            lines.append(execute(runtime, action, authorizer))
        except Exception as exc:  # one failing item must not stop the rest of the tick
            lines.append(f"error on #{action.item.number}: {type(exc).__name__}: {exc}")
        log.info("[%d/%d] -> %s (%.0fs)", index, len(actions), lines[-1], time.monotonic() - started)
    return lines


def _log_tick(runtime: Runtime, dry_run: bool, lines: list[str]) -> None:
    record = {"at": datetime.now(timezone.utc).isoformat(), "dry_run": dry_run, "actions": lines}
    path = runtime.state_dir / "ticks.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
    os.chmod(path, 0o600)


def status(runtime: Runtime) -> list[str]:
    config = runtime.config
    lines = [
        f"repository: {runtime.gh.repo}",
        f"configuration: {config.source or 'built-in defaults'}",
        f"identity: {runtime.bot_login or 'not configured (read-only)'}",
        f"paused: {'yes' if is_paused(runtime) else 'no'}",
        "stages:",
    ]
    for name, stage in config.stages.items():
        fallbacks = f" fallbacks={[str(ref) for ref in stage.fallbacks]}" if stage.fallbacks else ""
        lines.append(f"  {name}: {stage.primary} on_exhausted={stage.on_exhausted}{fallbacks}")
    lines.append("quota:")
    entries = runtime.ledger.all()
    if not entries:
        lines.append("  no usage recorded yet")
    for engine, entry in sorted(entries.items()):
        resume = (
            f" resume_at={time.strftime('%Y-%m-%d %H:%M', time.localtime(entry.resume_at))}" if entry.resume_at else ""
        )
        used = f" used={entry.used_percent:.0f}%" if entry.used_percent is not None else ""
        lines.append(f"  {engine}: {entry.status}{used}{resume} {entry.reason}".rstrip())
    try:
        items = fetch_open_items(runtime.gh)
    except GhError as exc:
        lines.append(f"open items: unavailable ({exc.stderr[:120]})")
        return lines
    counts: dict[str, int] = {}
    for item in items:
        for label in item.labels:
            if label.startswith("agent:"):
                counts[label] = counts.get(label, 0) + 1
    lines.append("open items by agent label:" if counts else "open items by agent label: none")
    lines += [f"  {label}: {count}" for label, count in sorted(counts.items())]
    return lines


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str
    warning: bool = False

    def render(self) -> str:
        mark = "ok  " if self.ok else ("warn" if self.warning else "FAIL")
        return f"[{mark}] {self.name}: {self.detail}"


def doctor(config: LoopConfig) -> list[Check]:
    """Verify configuration, GitHub access, App identity, CLI subscriptions, and model availability."""
    checks = [Check("configuration", True, str(config.source or "built-in defaults"))]
    gh_path = shutil.which("gh")
    checks.append(Check("gh CLI", bool(gh_path), gh_path or "install the GitHub CLI"))
    repo = config.github.repo or (detect_repo() if gh_path else None)
    checks.append(Check("repository", bool(repo), repo or "set [github] repo or AGENT_LOOP_REPO"))
    checks += _app_checks(config, repo)
    leaked = sorted(name for name in os.environ if name in BLOCKED_VARIABLES or is_blocked_variable(name))
    checks.append(
        Check(
            "stage environment",
            True,
            f"removed from stage processes: {', '.join(leaked)}" if leaked else "no API-key variables present",
            warning=bool(leaked),
        )
    )
    engines = sorted({ref.engine for stage in config.stages.values() for ref in stage.candidates})
    for engine in engines:
        if shutil.which(engine) is None:
            checks.append(Check(f"{engine} CLI", False, "not found on PATH"))
            continue
        ok, detail = subscription_status(engine)
        checks.append(Check(f"{engine} subscription", ok, detail))
    checks += _model_checks(config)
    checks += _reviewer_checks(config)
    checks.append(
        Check(
            "notifications",
            bool(config.notify.mention),
            ", ".join(f"@{login}" for login in config.notify.mention) or "set [notify] mention to administrator logins",
        )
    )
    checks.append(
        Check(
            "enabled_since",
            config.github.enabled_since is not None,
            config.github.enabled_since.isoformat()
            if config.github.enabled_since
            else "unset: every open issue will be analyzed",
            warning=config.github.enabled_since is None,
        )
    )
    return checks


def _app_checks(config: LoopConfig, repo: str | None) -> list[Check]:
    github = config.github
    if not any((github.app_id, github.installation_id, github.private_key_path)):
        return [Check("GitHub App", False, "not configured; dry-run only", warning=True)]
    checks = []
    if github.private_key_path is not None:
        try:
            check_private_key_file(github.private_key_path)
            checks.append(Check("App private key", True, str(github.private_key_path)))
        except AppAuthError as exc:
            return [Check("App private key", False, str(exc))]
    try:
        provider = provider_from_config(github)
        assert provider is not None
        info = provider.app_info()
        slug = info.get("slug")
        expected = f"{slug}[bot]" if slug else None
        checks.append(Check("App identity", bool(slug), expected or "GitHub returned no App slug"))
        if github.bot_login and expected and github.bot_login != expected:
            checks.append(Check("bot_login", False, f"configured {github.bot_login} but the App is {expected}"))
        token_gh = Gh(repo, token_provider=provider)
        if repo:
            data = token_gh.api(f"repos/{repo}")
            checks.append(Check("App installation", True, f"can access {data.get('full_name', repo)}"))
    except (AppAuthError, GhError) as exc:
        checks.append(Check("App authentication", False, str(exc)))
    return checks


def _model_checks(config: LoopConfig) -> list[Check]:
    checks = []
    codex_refs = sorted(
        {ref.model for stage in config.stages.values() for ref in stage.candidates if ref.engine == "codex"}
    )
    if codex_refs and shutil.which("codex"):
        catalog = codex_models()
        for model in codex_refs:
            if catalog is None:
                checks.append(Check(f"codex model {model}", False, "could not read the Codex model catalog", True))
            else:
                checks.append(
                    Check(
                        f"codex model {model}", model in catalog, "available" if model in catalog else "not in catalog"
                    )
                )
    claude_refs = sorted(
        {ref.model for stage in config.stages.values() for ref in stage.candidates if ref.engine == "claude"}
    )
    for model in claude_refs:
        checks.append(Check(f"claude model {model}", False, "verified on first use (actual model is recorded)", True))
    return checks


def _reviewer_checks(config: LoopConfig) -> list[Check]:
    checks = []
    review = config.stage("review")
    for name in AUTHOR_STAGES:
        for candidate in config.stage(name).candidates:
            ok = any(
                reviewer_allowed(reviewer, [candidate], config.policy.require_distinct_review_vendor)
                for reviewer in review.candidates
            )
            checks.append(
                Check(
                    f"reviewer for {name} {candidate}",
                    ok,
                    "a distinct reviewer is configured" if ok else "no configured reviewer is distinct from this model",
                )
            )
    return checks
