"""Pull request check status: which required checks passed, failed, or have not reported, and why they failed."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .analysis import find_secrets
from .gh import Gh, GhError

GREEN = "green"
PENDING = "pending"
FAILED = "failed"

_PASSING = {"success", "neutral", "skipped"}
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT[\d:.]+Z ", re.MULTILINE)
LOG_TAIL_CHARS = 8000
MAX_LOGS = 3


@dataclass(frozen=True)
class CheckOutcome:
    name: str
    state: str  # green, pending, failed
    run_id: int | None = None
    detail: str = ""


@dataclass
class CIStatus:
    state: str
    checks: list[CheckOutcome] = field(default_factory=list)

    @property
    def failed(self) -> list[CheckOutcome]:
        return [check for check in self.checks if check.state == FAILED]

    @property
    def pending(self) -> list[CheckOutcome]:
        return [check for check in self.checks if check.state == PENDING]

    def describe(self) -> str:
        passed = sum(1 for check in self.checks if check.state == GREEN)
        return f"{passed}/{len(self.checks)} required checks passed"


def required_contexts(gh: Gh, base_branch: str) -> list[str]:
    """Names of the status checks the base branch's rules require; empty when none are configured."""
    owner, name = gh.repo_parts()
    try:
        rules = gh.api(f"repos/{owner}/{name}/rules/branches/{base_branch}") or []
    except GhError:
        return []
    contexts: list[str] = []
    for rule in rules:
        if rule.get("type") == "required_status_checks":
            for check in (rule.get("parameters") or {}).get("required_status_checks", []):
                if check.get("context") and check["context"] not in contexts:
                    contexts.append(check["context"])
    return contexts


def _run_state(run: dict) -> str:
    if run.get("status") != "completed":
        return PENDING
    return GREEN if run.get("conclusion") in _PASSING else FAILED


def check_status(gh: Gh, sha: str, required: list[str]) -> CIStatus:
    """Evaluate the required checks (or every reported check when none are required) for ``sha``."""
    owner, name = gh.repo_parts()
    data = gh.api(f"repos/{owner}/{name}/commits/{sha}/check-runs", fields={"per_page": 100}, paginate=False) or {}
    runs: dict[str, dict] = {}
    for run in data.get("check_runs", []):
        previous = runs.get(run["name"])
        if previous is None or run["id"] > previous["id"]:
            runs[run["name"]] = run
    statuses: dict[str, str] = {}
    try:
        combined = gh.api(f"repos/{owner}/{name}/commits/{sha}/status") or {}
        statuses = {entry["context"]: entry["state"] for entry in combined.get("statuses", [])}
    except GhError:
        pass
    names = required or sorted(runs)
    outcomes = []
    for check_name in names:
        if check_name in runs:
            run = runs[check_name]
            outcomes.append(CheckOutcome(check_name, _run_state(run), run["id"], str(run.get("conclusion") or "")))
        elif check_name in statuses:
            state = {"success": GREEN, "pending": PENDING}.get(statuses[check_name], FAILED)
            outcomes.append(CheckOutcome(check_name, state, None, statuses[check_name]))
        else:
            outcomes.append(CheckOutcome(check_name, PENDING, None, "not reported yet"))
    if not outcomes:
        return CIStatus(PENDING, [])
    if any(check.state == FAILED for check in outcomes):
        return CIStatus(FAILED, outcomes)
    if any(check.state == PENDING for check in outcomes):
        return CIStatus(PENDING, outcomes)
    return CIStatus(GREEN, outcomes)


def scrub(text: str) -> str:
    """Drop terminal escapes and timestamps, and redact anything that looks like a credential."""
    text = _TIMESTAMP.sub("", _ANSI.sub("", text))
    if find_secrets(text):
        text = "[log withheld: it contained a possible credential]"
    return text


def failure_logs(gh: Gh, status: CIStatus) -> list[tuple[str, str]]:
    """Return ``(check name, log tail)`` for up to ``MAX_LOGS`` failing GitHub Actions jobs."""
    owner, name = gh.repo_parts()
    logs = []
    for check in status.failed[:MAX_LOGS]:
        text = ""
        if check.run_id is not None:
            try:
                text = gh.run(["api", f"repos/{owner}/{name}/actions/jobs/{check.run_id}/logs"])
            except GhError:
                try:
                    run = gh.api(f"repos/{owner}/{name}/check-runs/{check.run_id}") or {}
                    output = run.get("output") or {}
                    text = "\n".join(str(output.get(key) or "") for key in ("title", "summary", "text"))
                except GhError:
                    text = ""
        logs.append((check.name, scrub(text)[-LOG_TAIL_CHARS:] or "(no log available)"))
    return logs
