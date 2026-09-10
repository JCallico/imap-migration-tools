"""A run's redacted output, progress, and durable completion summary."""

from __future__ import annotations

from datetime import datetime, timezone

from ui_core import history
from ui_core.config import SECRET_NAMES
from ui_core.operations import ProgressState, parse_output


class RunSession:
    """Own persistence independently of widget lifetime and toolkit threads."""

    def __init__(self, operation, values, writer_factory=None):
        self.record = history.new_record(operation)
        self.progress = ProgressState()
        self.redactor = history.Redactor([values.get(name, "") for name in SECRET_NAMES])
        self.writer = None
        self.warning = ""
        try:
            self.writer = (writer_factory or history.HistoryWriter)(self.record, self.redactor)
        except OSError as exc:
            self.warning = self.redactor(f"History unavailable: {exc}")

    def receive(self, line):
        sanitized = self.redactor(line)
        if self.writer:
            try:
                self.writer.write(sanitized)
            except OSError as exc:
                self.warning = self.redactor(f"History write failed: {exc}")
        parse_output(sanitized, self.progress)
        return sanitized

    def finish(self, exit_code, cancelled=False):
        self.record.status = "cancelled" if cancelled else "completed" if exit_code == 0 else "failed"
        self.record.exit_code = exit_code
        self.record.finished_at = datetime.now(timezone.utc).isoformat()
        for name in ("copied", "skipped", "failed", "deleted"):
            setattr(self.record, name, getattr(self.progress, name))
        if self.writer:
            try:
                self.writer.close()
            except OSError as exc:
                self.warning = self.redactor(f"History finalization failed: {exc}")
        return self.record
