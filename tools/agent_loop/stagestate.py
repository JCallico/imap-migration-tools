"""Per-issue progress state for multi-tick stages: branch, worktree, model session, and pull request."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

CODING = "coding"  # the model has not finished; a resumed run continues it
VERIFYING = "verifying"  # the model finished; the dispatcher still has to verify, commit, and push
PR_OPEN = "pr_open"


@dataclass
class IssueProgress:
    issue: int
    branch: str = ""
    worktree: str = ""
    status: str = CODING
    engine: str = ""
    session_id: str = ""
    pr_number: int = 0
    result_json: str = ""  # the model's accepted final message, kept so verification can resume without re-running it
    model: str = ""  # engine:model:effort the model actually ran as
    repair_rounds: int = 0
    stage: str = ""  # the authoring stage that owns an unfinished run: implementation, ci_fix, or feedback


class ProgressStore:
    def __init__(self, directory: Path):
        self.directory = Path(directory)

    def _path(self, issue: int) -> Path:
        return self.directory / f"issue-{issue}.json"

    def load(self, issue: int) -> IssueProgress:
        path = self._path(issue)
        if path.exists():
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                known = IssueProgress.__dataclass_fields__
                return IssueProgress(**{key: value for key, value in raw.items() if key in known})
            except (OSError, json.JSONDecodeError, TypeError):
                pass
        return IssueProgress(issue)

    def save(self, progress: IssueProgress) -> None:
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, tmp = tempfile.mkstemp(dir=self.directory, prefix=".issue-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(asdict(progress), handle, indent=2)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._path(progress.issue))
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
