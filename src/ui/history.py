"""Redacted, bounded local run history, isolated per project.

Every function takes the ``scope`` of one project (``Project.history_key``), so history can never be read, written,
pruned, or deleted across projects by accident. Runs live in ``<history root>/projects/<scope>/``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from platformdirs import user_data_path

MAX_RUNS = 50
MAX_BYTES = 100 * 1024 * 1024


@dataclass
class RunRecord:
    run_id: str
    operation: str
    started_at: str
    finished_at: str = ""
    status: str = "running"
    exit_code: int | None = None
    copied: int = 0
    skipped: int = 0
    failed: int = 0
    deleted: int = 0


def history_dir() -> Path:
    path = user_data_path("imap-migration-tools", "CallicoCode") / "history"
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(stat.S_IRWXU)
    except OSError:
        pass
    return path


DEFAULT_SCOPE = "default"
_SCOPE_PATTERN = re.compile(r"[^\\/\x00-\x1f]+")


def _scope_path(scope: str) -> Path:
    """Return a project's history directory without creating it, rejecting anything that could escape the root."""
    if not _SCOPE_PATTERN.fullmatch(scope) or scope in {".", ".."}:
        raise ValueError(f"Invalid history scope: {scope!r}")
    return history_dir() / "projects" / scope


def scope_dir(scope: str) -> Path:
    """Return one project's owner-only history directory, creating it and adopting pre-project history if needed."""
    path = _scope_path(scope)
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(stat.S_IRWXU)
    except OSError:
        pass
    if scope == DEFAULT_SCOPE:
        _adopt_legacy_history(path)
    return path


def _adopt_legacy_history(destination: Path) -> None:
    """Move runs recorded before projects existed into the default project, once."""
    root = history_dir()
    try:
        legacy = [entry for entry in root.iterdir() if entry.is_file() and entry.suffix in {".json", ".log"}]
    except OSError:
        return
    for entry in legacy:
        try:
            os.replace(entry, destination / entry.name)
        except OSError:
            continue


def move_scope(old: str, new: str) -> None:
    """Move a renamed project's history, refusing to merge it into leftover history of the same name."""
    if old == new:
        return
    source, target = _scope_path(old), _scope_path(new)
    if not source.exists():
        return
    if target.exists():
        raise FileExistsError(f"History for {new} already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    os.replace(source, target)


def delete_scope(scope: str) -> None:
    """Permanently delete one project's history, so a later project with the same name starts empty."""
    path = _scope_path(scope)
    if path.exists():
        shutil.rmtree(path)


def new_record(operation: str) -> RunRecord:
    now = datetime.now(timezone.utc)
    return RunRecord(now.strftime("%Y%m%dT%H%M%S.%fZ"), operation, now.isoformat())


class Redactor:
    """Remove configured secrets and token-like material from persisted output."""

    TOKEN_RE = re.compile(r"(?i)(bearer\s+|access[_ -]?token[=:]\s*)\S+")

    def __init__(self, secrets: list[str]) -> None:
        self.secrets = sorted((value for value in secrets if value), key=len, reverse=True)

    def __call__(self, line: str) -> str:
        for value in self.secrets:
            line = line.replace(value, "[REDACTED]")
        return self.TOKEN_RE.sub(r"\1[REDACTED]", line)


class HistoryWriter:
    """Stream a sanitized run log and persist its summary."""

    def __init__(self, record: RunRecord, redactor: Redactor, scope: str) -> None:
        self.record = record
        self.redactor = redactor
        self.scope = scope
        self.root = scope_dir(scope)
        self.log_path = self.root / f"{record.run_id}.log"
        self.summary_path = self.root / f"{record.run_id}.json"
        self._stream = self.log_path.open("w", encoding="utf-8")
        try:
            os.chmod(self.log_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        self.save()

    def write(self, line: str) -> str:
        sanitized = self.redactor(line)
        self._stream.write(sanitized + "\n")
        self._stream.flush()
        return sanitized

    def save(self) -> None:
        fd, temp_name = tempfile.mkstemp(prefix=f".{self.summary_path.name}.", dir=self.root, text=True)
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(asdict(self.record), stream, indent=2)
                stream.write("\n")
            try:
                os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
            os.replace(temp_path, self.summary_path)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def close(self) -> None:
        if not self._stream.closed:
            self._stream.close()
        self.save()
        prune_history(self.scope)


def load_records(scope: str) -> list[RunRecord]:
    records: list[RunRecord] = []
    for path in sorted(scope_dir(scope).glob("*.json"), reverse=True):
        try:
            records.append(RunRecord(**json.loads(path.read_text(encoding="utf-8"))))
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            continue
    return records


def read_log(run_id: str, scope: str) -> str:
    path = scope_dir(scope) / f"{run_id}.log"
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def delete_record(run_id: str, scope: str) -> None:
    for suffix in (".json", ".log"):
        path = scope_dir(scope) / f"{run_id}{suffix}"
        if path.exists():
            path.unlink()


def clear_history(scope: str) -> None:
    for path in scope_dir(scope).iterdir():
        if path.suffix in {".json", ".log"} and path.is_file():
            path.unlink()


def prune_history(scope: str) -> None:
    root = scope_dir(scope)
    summaries = sorted(root.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
    total = sum(path.stat().st_size for path in root.iterdir() if path.is_file())
    for index, summary in enumerate(summaries):
        log = summary.with_suffix(".log")
        size = summary.stat().st_size + (log.stat().st_size if log.exists() else 0)
        if index >= MAX_RUNS or total > MAX_BYTES:
            summary.unlink(missing_ok=True)
            log.unlink(missing_ok=True)
            total -= size
