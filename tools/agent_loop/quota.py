"""Subscription quota tracking: telemetry parsing, failure classification, and a persistent per-engine ledger.

Reaching a subscription limit pauses work; it is never treated as a task failure. Unrecognized errors classify as
``unknown`` and pause with exponential backoff instead of retrying immediately.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from filelock import FileLock

AVAILABLE = "available"
LOW = "low"
EXHAUSTED = "exhausted"
UNKNOWN = "unknown"

SUCCESS = "success"
QUOTA_EXHAUSTED = "quota_exhausted"
TRANSIENT = "transient"
AUTH = "auth"
TASK_FAILURE = "task_failure"
UNCLASSIFIED = "unknown"

BACKOFF_BASE_SECONDS = 30 * 60
TRANSIENT_RETRY_SECONDS = 5 * 60


@dataclass(frozen=True)
class RateWindow:
    name: str
    used_percent: float | None
    resets_at: float | None


@dataclass(frozen=True)
class RateLimitSnapshot:
    """Usage telemetry reported by an engine during a run."""

    engine: str
    windows: tuple[RateWindow, ...] = ()
    limited: bool = False
    limited_window: str | None = None

    @property
    def used_percent(self) -> float | None:
        values = [window.used_percent for window in self.windows if window.used_percent is not None]
        return max(values) if values else None

    @property
    def reset_at(self) -> float | None:
        """Reset time of the limiting window, or of the most-used window when not limited."""
        if self.limited_window is not None:
            for window in self.windows:
                if window.name == self.limited_window and window.resets_at is not None:
                    return window.resets_at
        candidates = [window for window in self.windows if window.resets_at is not None]
        if not candidates:
            return None
        if self.limited:
            exhausted = [window for window in candidates if (window.used_percent or 0) >= 100]
            if exhausted:
                return max(window.resets_at for window in exhausted)  # type: ignore[type-var]
        return max(candidates, key=lambda window: window.used_percent or 0).resets_at

    @property
    def window_name(self) -> str | None:
        if self.limited_window is not None:
            return self.limited_window
        if not self.windows:
            return None
        return max(self.windows, key=lambda window: window.used_percent or 0).name


def codex_snapshot(rate_limits: dict | None) -> RateLimitSnapshot | None:
    """Parse the ``rate_limits`` object from a Codex rollout ``token_count`` event."""
    if not isinstance(rate_limits, dict):
        return None
    windows = []
    for name in ("primary", "secondary"):
        window = rate_limits.get(name)
        if isinstance(window, dict):
            minutes = window.get("window_minutes")
            label = f"{name}_{minutes}m" if minutes else name
            windows.append(RateWindow(label, _as_float(window.get("used_percent")), _as_float(window.get("resets_at"))))
    reached = rate_limits.get("rate_limit_reached_type")
    limited = bool(reached) or any((window.used_percent or 0) >= 100 for window in windows)
    limited_window = None
    if isinstance(reached, str):
        limited_window = next((window.name for window in windows if window.name.startswith(reached)), None)
    return RateLimitSnapshot("codex", tuple(windows), limited, limited_window)


def claude_snapshot(rate_limit_info: dict | None) -> RateLimitSnapshot | None:
    """Parse the ``rate_limit_info`` object from a Claude ``rate_limit_event``."""
    if not isinstance(rate_limit_info, dict):
        return None
    windows = []
    unified = rate_limit_info.get("unifiedWindows")
    if isinstance(unified, dict):
        for name, window in unified.items():
            if isinstance(window, dict):
                utilization = _as_float(window.get("utilization"))
                percent = utilization * 100 if utilization is not None else None
                windows.append(RateWindow(str(name), percent, _as_float(window.get("resetsAt"))))
    limited_type = rate_limit_info.get("rateLimitType")
    if not windows and rate_limit_info.get("resetsAt") is not None:
        windows.append(RateWindow(str(limited_type or "window"), None, _as_float(rate_limit_info.get("resetsAt"))))
    limited = str(rate_limit_info.get("status", "")).lower() == "rejected"
    return RateLimitSnapshot("claude", tuple(windows), limited, str(limited_type) if limited and limited_type else None)


def _as_float(value) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class Classification:
    kind: str
    reset_at: float | None = None
    detail: str = ""


_QUOTA_PATTERNS = re.compile(
    r"usage limit|rate[ _-]?limit|limit reached|hit your (usage )?limit|quota|out of (extra )?usage|"
    r"too many requests|\b429\b|insufficient_quota|credits? (exhausted|depleted)",
    re.IGNORECASE,
)
_AUTH_PATTERNS = re.compile(
    r"not logged in|log ?in again|please (run )?.*login|authenticat|unauthori[sz]ed|\b401\b|\b403\b|"
    r"invalid (api )?key|(token|session|credentials?) (has |have )?(expired|revoked)",
    re.IGNORECASE,
)
_TRANSIENT_PATTERNS = re.compile(
    r"timed? ?out|connection (reset|refused|closed|error)|network|temporar|\b50[0234]\b|\b529\b|overloaded|"
    r"econn|stream (disconnected|error)|service unavailable",
    re.IGNORECASE,
)
_RELATIVE_RESET = re.compile(
    r"(?:try again|retry|resets?|available again)\s+(?:in|after)\s+(?:about\s+)?(\d+(?:\.\d+)?)\s*"
    r"(seconds?|secs?|minutes?|mins?|hours?|hrs?|days?)",
    re.IGNORECASE,
)
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_reset_hint(text: str, now: float) -> float | None:
    """Extract a reset time from a relative phrase such as ``try again in 3 hours``."""
    match = _RELATIVE_RESET.search(text)
    if not match:
        return None
    amount = float(match.group(1))
    unit = match.group(2).lower()
    seconds = _UNIT_SECONDS["m" if unit.startswith("mi") else unit[0]]
    return now + amount * seconds


def classify_failure(
    exit_code: int | None,
    error_messages: Iterable[str],
    snapshot: RateLimitSnapshot | None = None,
    *,
    task_error: bool = False,
    timed_out: bool = False,
    now: float | None = None,
) -> Classification:
    """Classify an engine run outcome.

    Only error channels (stderr and structured error events) are inspected, never the model's own output, so a task
    that discusses rate limits cannot masquerade as a quota failure.
    """
    now = time.time() if now is None else now
    text = "\n".join(message for message in error_messages if message)
    if snapshot is not None and snapshot.limited:
        return Classification(
            QUOTA_EXHAUSTED, snapshot.reset_at or parse_reset_hint(text, now), "engine reported limit"
        )
    if exit_code == 0 and not task_error and not timed_out:
        return Classification(SUCCESS)
    if timed_out:
        return Classification(TASK_FAILURE, None, "stage exceeded its time limit")
    if _QUOTA_PATTERNS.search(text):
        return Classification(QUOTA_EXHAUSTED, parse_reset_hint(text, now), _first_line(text))
    if _AUTH_PATTERNS.search(text):
        return Classification(AUTH, None, _first_line(text))
    if _TRANSIENT_PATTERNS.search(text):
        return Classification(TRANSIENT, now + TRANSIENT_RETRY_SECONDS, _first_line(text))
    if task_error and exit_code == 0:
        return Classification(TASK_FAILURE, None, _first_line(text))
    return Classification(UNCLASSIFIED, None, _first_line(text))


def _first_line(text: str) -> str:
    return text.strip().splitlines()[0][:200] if text.strip() else ""


@dataclass
class EngineQuota:
    engine: str
    status: str = AVAILABLE
    resume_at: float | None = None
    reset_known: bool = False
    window: str | None = None
    used_percent: float | None = None
    backoff_level: int = 0
    reason: str = ""
    updated_at: float | None = None
    windows: list[dict] = field(default_factory=list)


class QuotaLedger:
    """Per-engine quota state persisted as JSON with cross-process locking."""

    def __init__(self, path: Path, low_threshold_percent: float = 80.0, unknown_backoff_max_hours: float = 6.0):
        self.path = Path(path)
        self.low_threshold_percent = low_threshold_percent
        self.max_backoff_seconds = unknown_backoff_max_hours * 3600
        self._lock = FileLock(str(self.path) + ".lock")

    def _load(self) -> dict[str, EngineQuota]:
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        known = EngineQuota.__dataclass_fields__
        return {
            name: EngineQuota(**{key: value for key, value in entry.items() if key in known})
            for name, entry in raw.items()
            if isinstance(entry, dict)
        }

    def _save(self, entries: dict[str, EngineQuota]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({name: asdict(entry) for name, entry in entries.items()}, indent=2, sort_keys=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".quota-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def get(self, engine: str) -> EngineQuota:
        with self._lock:
            return self._load().get(engine, EngineQuota(engine))

    def all(self) -> dict[str, EngineQuota]:
        with self._lock:
            return self._load()

    def _update(self, engine: str, change) -> EngineQuota:
        with self._lock:
            entries = self._load()
            entry = entries.get(engine, EngineQuota(engine))
            change(entry)
            entries[engine] = entry
            self._save(entries)
            return entry

    def record_snapshot(self, snapshot: RateLimitSnapshot, now: float | None = None) -> EngineQuota:
        """Record usage telemetry observed during a run."""
        now = time.time() if now is None else now

        def change(entry: EngineQuota) -> None:
            entry.updated_at = now
            entry.used_percent = snapshot.used_percent
            entry.window = snapshot.window_name
            entry.windows = [asdict(window) for window in snapshot.windows]
            if snapshot.limited:
                entry.status = EXHAUSTED
                entry.resume_at = snapshot.reset_at
                entry.reset_known = snapshot.reset_at is not None
                entry.reason = "engine reported limit"
            elif snapshot.used_percent is not None and snapshot.used_percent >= self.low_threshold_percent:
                entry.status = LOW
                entry.resume_at = snapshot.reset_at
                entry.reset_known = snapshot.reset_at is not None
                entry.reason = f"{snapshot.used_percent:.0f}% of {snapshot.window_name} used"
            else:
                entry.status = AVAILABLE
                entry.resume_at = None
                entry.reset_known = False
                entry.reason = ""
                entry.backoff_level = 0

        return self._update(snapshot.engine, change)

    def record_classification(self, engine: str, result: Classification, now: float | None = None) -> EngineQuota:
        """Record a run outcome; quota and unknown failures pause the engine."""
        now = time.time() if now is None else now

        def change(entry: EngineQuota) -> None:
            entry.updated_at = now
            if result.kind == SUCCESS:
                if entry.status in (EXHAUSTED, UNKNOWN):
                    entry.status = AVAILABLE
                    entry.resume_at = None
                    entry.reason = ""
                entry.backoff_level = 0
            elif result.kind in (QUOTA_EXHAUSTED, UNCLASSIFIED):
                entry.status = EXHAUSTED if result.kind == QUOTA_EXHAUSTED else UNKNOWN
                entry.reason = result.detail or result.kind
                if result.reset_at is not None:
                    entry.resume_at = result.reset_at
                    entry.reset_known = True
                else:
                    delay = min(BACKOFF_BASE_SECONDS * (2**entry.backoff_level), self.max_backoff_seconds)
                    entry.resume_at = now + delay
                    entry.reset_known = False
                    entry.backoff_level += 1
            elif result.kind == AUTH:
                entry.status = UNKNOWN
                entry.reason = f"authentication problem: {result.detail}"
                entry.resume_at = now + BACKOFF_BASE_SECONDS
                entry.reset_known = False

        return self._update(engine, change)

    def usable(self, engine: str, *, long_stage: bool, now: float | None = None) -> tuple[bool, str]:
        """Return whether a stage may start on ``engine`` and why not."""
        now = time.time() if now is None else now
        entry = self.get(engine)
        if entry.status in (EXHAUSTED, UNKNOWN):
            if entry.resume_at is not None and now < entry.resume_at:
                return False, f"{engine} {entry.status} until {_format_time(entry.resume_at)} ({entry.reason})"
            return True, "" if entry.reset_known else "probe recommended before long work"
        if entry.status == LOW and long_stage:
            if entry.resume_at is None or now < entry.resume_at:
                return False, f"{engine} quota low ({entry.reason}); reserving remaining quota for in-flight work"
        return True, ""

    def needs_probe(self, engine: str, now: float | None = None) -> bool:
        """True when a pause with an unknown reset time has elapsed and should be confirmed with a tiny call."""
        now = time.time() if now is None else now
        entry = self.get(engine)
        return (
            entry.status in (EXHAUSTED, UNKNOWN)
            and not entry.reset_known
            and entry.resume_at is not None
            and now >= entry.resume_at
        )


def _format_time(timestamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M %Z", time.localtime(timestamp))
