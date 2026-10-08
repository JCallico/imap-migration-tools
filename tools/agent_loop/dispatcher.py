"""Dispatcher operations: one tick of the state machine, status reporting, and environment diagnostics."""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from filelock import FileLock, Timeout

from . import state
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
from .selection import reviewer_allowed
from .snapshot import fetch_open_items

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
    return Runtime(config, Gh(repo, token_provider=provider), provider, bot_login, state_dir, ledger)


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


def plan_actions(runtime: Runtime) -> list[state.Action]:
    authorizer = Authorizer(runtime.gh, runtime.bot_login, runtime.config.github.allowed_admins)
    ctx = state.Context(runtime.config, authorizer, _usable(runtime), datetime.now(timezone.utc))
    return state.plan(fetch_open_items(runtime.gh), ctx)


def _label_path(runtime: Runtime, number: int) -> str:
    owner, name = runtime.gh.repo_parts()
    return f"repos/{owner}/{name}/issues/{number}/labels"


def _add_labels(runtime: Runtime, number: int, labels) -> None:
    if labels:
        runtime.gh.api(_label_path(runtime, number), method="POST", body={"labels": list(labels)})


def _remove_label(runtime: Runtime, number: int, label: str) -> None:
    try:
        runtime.gh.api(f"{_label_path(runtime, number)}/{quote(label, safe='')}", method="DELETE")
    except GhError as exc:
        if exc.returncode and "404" not in exc.stderr and "Not Found" not in exc.stderr:
            raise


def execute(runtime: Runtime, action: state.Action) -> str:
    """Execute dispatcher-owned actions. Stage runners are added in later rollout phases."""
    number = action.item.number
    if action.kind == state.REVERT_LABEL and action.event is not None:
        if action.event.added:
            _remove_label(runtime, number, action.event.label)
        else:
            _add_labels(runtime, number, [action.event.label])
        return f"reverted: {action.describe()}"
    if action.kind == state.SET_LABELS:
        _add_labels(runtime, number, action.add_labels)
        for label in action.remove_labels:
            _remove_label(runtime, number, label)
        if state.BLOCKED in action.add_labels:
            notifier = GitHubNotifier(runtime.gh, runtime.config.notify.mention)
            key = f"blocked-{number}-{action.item.head_sha or 'issue'}"
            notifier.send(Notification(number, key, f"Needs your decision: {action.reason}.", is_pr=action.item.is_pr))
        return f"done: {action.describe()}"
    if action.kind == state.REPLY_UNAUTHORIZED and action.comment_id:
        owner, name = runtime.gh.repo_parts()
        body = (
            "This command was ignored: only repository administrators can issue agent loop commands.\n\n"
            + state.unauthorized_marker(action.comment_id)
        )
        runtime.gh.api(f"repos/{owner}/{name}/issues/{number}/comments", method="POST", body={"body": body})
        return f"done: {action.describe()}"
    if action.kind == state.RUN_STAGE:
        return f"pending (stage runner not yet available): {action.describe()}"
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
        actions = plan_actions(runtime)
        if dry_run:
            lines = [f"[dry-run] {action.describe()}" for action in actions]
            if runtime.bot_login is None:
                lines.insert(0, "[dry-run] bot identity unknown: existing analyses and run markers are not recognized")
        else:
            lines = [execute(runtime, action) for action in actions]
        _log_tick(runtime, dry_run, lines)
        return lines or ["no open items require action"]
    finally:
        lock.release()


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
