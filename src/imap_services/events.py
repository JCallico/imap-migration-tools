"""Structured progress reporting for IMAP services."""

import threading
from dataclasses import dataclass
from typing import Callable, Optional

from imap_services.exceptions import CallbackError


@dataclass(frozen=True)
class OperationEvent:
    """A status update emitted by an operation."""

    operation: str
    phase: str
    message: str
    severity: str = "info"
    folder: Optional[str] = None
    current: Optional[int] = None
    total: Optional[int] = None


EventCallback = Callable[[OperationEvent], None]


class EventSink:
    """Serialize event delivery across operation worker threads."""

    def __init__(self, operation: str, callback: Optional[EventCallback]) -> None:
        self.operation = operation
        self.callback = callback
        self._lock = threading.Lock()

    def emit(
        self,
        phase: str,
        message: str,
        *,
        severity: str = "info",
        folder: Optional[str] = None,
        current: Optional[int] = None,
        total: Optional[int] = None,
    ) -> None:
        if self.callback is None:
            return
        event = OperationEvent(self.operation, phase, message, severity, folder, current, total)
        try:
            with self._lock:
                self.callback(event)
        except Exception as exc:
            raise CallbackError("operation event callback failed") from exc

    def message(self, message: str) -> None:
        """Accept legacy string progress reporters."""
        self.emit("progress", str(message))
