"""Replaceable polling-based filesystem change detection."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Callable, Union

Fingerprint = Union[str, tuple[tuple[str, int, int], ...]]


@dataclass(frozen=True)
class FilesystemChange:
    """A target whose current fingerprint differs from its previous value."""

    target: str
    previous: Fingerprint
    current: Fingerprint


@dataclass
class _Target:
    snapshot: Callable[[], Fingerprint]
    fingerprint: Fingerprint


def file_content_fingerprint(path: Path) -> str:
    """Return a content fingerprint, treating an unreadable or absent file as missing."""
    try:
        return sha256(path.read_bytes()).hexdigest()
    except OSError:
        return "missing"


def directory_fingerprint(path: Path, pattern: str) -> tuple[tuple[str, int, int], ...]:
    """Return stable metadata for matching directory entries despite concurrent changes."""
    entries: list[tuple[str, int, int]] = []
    try:
        paths = list(path.glob(pattern))
    except OSError:
        return ()
    for entry in paths:
        try:
            stat = entry.stat()
        except OSError:
            continue
        if entry.is_file():
            entries.append((entry.name, stat.st_mtime_ns, stat.st_size))
    return tuple(sorted(entries))


class PollingWatchBackend:
    """Dependency-free backend that detects changes by comparing fingerprints."""

    def __init__(self) -> None:
        self._targets: dict[str, _Target] = {}

    def watch_file(self, target: str, path: Path) -> None:
        self._register(target, lambda: file_content_fingerprint(path))

    def watch_directory(self, target: str, path: Path, pattern: str = "*") -> None:
        self._register(target, lambda: directory_fingerprint(path, pattern))

    def _register(self, target: str, snapshot: Callable[[], Fingerprint]) -> None:
        self._targets[target] = _Target(snapshot, snapshot())

    def fingerprint(self, target: str) -> Fingerprint:
        """Read a target without advancing its observed baseline."""
        return self._targets[target].snapshot()

    def refresh(self, target: str) -> Fingerprint:
        """Advance one target's baseline to its current fingerprint."""
        watched = self._targets[target]
        watched.fingerprint = watched.snapshot()
        return watched.fingerprint

    def poll(self, target: str | None = None) -> list[FilesystemChange]:
        """Return changes and advance the corresponding observed baselines."""
        names = (target,) if target is not None else tuple(self._targets)
        changes: list[FilesystemChange] = []
        for name in names:
            watched = self._targets[name]
            current = watched.snapshot()
            if current != watched.fingerprint:
                changes.append(FilesystemChange(name, watched.fingerprint, current))
                watched.fingerprint = current
        return changes


class FilesystemWatcher:
    """Stable filesystem observation facade with an injectable backend."""

    def __init__(self, backend: PollingWatchBackend | None = None) -> None:
        self._backend = backend or PollingWatchBackend()

    def watch_file(self, target: str, path: Path) -> None:
        self._backend.watch_file(target, path)

    def watch_directory(self, target: str, path: Path, pattern: str = "*") -> None:
        self._backend.watch_directory(target, path, pattern)

    def fingerprint(self, target: str) -> Fingerprint:
        return self._backend.fingerprint(target)

    def refresh(self, target: str) -> Fingerprint:
        return self._backend.refresh(target)

    def poll(self, target: str | None = None) -> list[FilesystemChange]:
        return self._backend.poll(target)
