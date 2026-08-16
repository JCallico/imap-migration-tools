"""Redacted, bounded local run history."""

from __future__ import annotations

import json
import os
import re
import stat
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

    def __init__(self, record: RunRecord, redactor: Redactor) -> None:
        self.record = record
        self.redactor = redactor
        self.root = history_dir()
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
        self.summary_path.write_text(json.dumps(asdict(self.record), indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(self.summary_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    def close(self) -> None:
        if not self._stream.closed:
            self._stream.close()
        self.save()
        prune_history()


def load_records() -> list[RunRecord]:
    records: list[RunRecord] = []
    for path in sorted(history_dir().glob("*.json"), reverse=True):
        try:
            records.append(RunRecord(**json.loads(path.read_text(encoding="utf-8"))))
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            continue
    return records


def read_log(run_id: str) -> str:
    path = history_dir() / f"{run_id}.log"
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def delete_record(run_id: str) -> None:
    for suffix in (".json", ".log"):
        path = history_dir() / f"{run_id}{suffix}"
        if path.exists():
            path.unlink()


def clear_history() -> None:
    for path in history_dir().iterdir():
        if path.suffix in {".json", ".log"} and path.is_file():
            path.unlink()


def prune_history() -> None:
    root = history_dir()
    summaries = sorted(root.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
    total = sum(path.stat().st_size for path in root.iterdir() if path.is_file())
    for index, summary in enumerate(summaries):
        log = summary.with_suffix(".log")
        size = summary.stat().st_size + (log.stat().st_size if log.exists() else 0)
        if index >= MAX_RUNS or total > MAX_BYTES:
            summary.unlink(missing_ok=True)
            log.unlink(missing_ok=True)
            total -= size
