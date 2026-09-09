"""Structured results returned by IMAP services."""

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class FolderResult:
    name: str
    processed: int = 0
    skipped: int = 0
    failed: int = 0
    deleted: int = 0


@dataclass(frozen=True)
class TransferResult:
    folders: tuple[FolderResult, ...] = ()
    artifacts: tuple[Path, ...] = ()


@dataclass(frozen=True)
class CountResult:
    folder_counts: Mapping[str, Optional[int]]
    total: int


@dataclass(frozen=True)
class ComparisonRow:
    folder: str
    source: Optional[int]
    destination: Optional[int]

    @property
    def difference(self) -> Optional[int]:
        if self.source is None or self.destination is None:
            return None
        return self.source - self.destination


@dataclass(frozen=True)
class ComparisonResult:
    rows: tuple[ComparisonRow, ...]
    source_total: int
    destination_total: int

    @property
    def matches(self) -> bool:
        return all(row.difference == 0 for row in self.rows)
