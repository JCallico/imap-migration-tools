"""Diff policy gate: rules every change must satisfy before the bot pushes it."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

from .analysis import find_secrets
from .config import PolicyConfig
from .worktree import git

SYMLINK_MODE = "120000"
SUBMODULE_MODE = "160000"


@dataclass(frozen=True)
class Violation:
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.rule}: {self.detail}"


def is_test_path(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return path.startswith(("test/", "tests/")) or name.startswith("test_") or name.endswith("_test.py")


def _matches(path: str, pattern: str) -> bool:
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        return path == prefix or path.startswith(prefix + "/")
    return fnmatch.fnmatch(path, pattern)


def check_diff(worktree: Path, base_ref: str, policy: PolicyConfig) -> list[Violation]:
    """Check the commits on ``HEAD`` since ``base_ref`` (merge-base diff) against the policy.

    Violations name rules and paths, never file content, so a rejected secret is not echoed anywhere.
    """
    violations: list[Violation] = []
    numstat = git(worktree, "diff", "--numstat", "--no-renames", f"{base_ref}...HEAD").stdout.splitlines()
    raw = git(worktree, "diff", "--raw", "--no-renames", f"{base_ref}...HEAD").stdout.splitlines()
    changed = []
    non_test_lines = 0
    for line in numstat:
        added, deleted, path = line.split("\t", 2)
        changed.append(path)
        if added == "-" or deleted == "-":
            violations.append(Violation("binary file", path))
        elif not is_test_path(path):
            non_test_lines += int(added) + int(deleted)
    for path in changed:
        for pattern in policy.protected_paths:
            if _matches(path, pattern):
                violations.append(Violation("protected path", path))
                break
    for line in raw:
        meta, _, path = line.partition("\t")
        fields = meta.lstrip(":").split()
        if len(fields) >= 2 and SYMLINK_MODE in fields[:2]:
            violations.append(Violation("symbolic link", path))
        elif len(fields) >= 2 and SUBMODULE_MODE in fields[:2]:
            violations.append(Violation("submodule", path))
    if non_test_lines > policy.max_diff_lines:
        violations.append(
            Violation(
                "diff size", f"{non_test_lines} changed lines outside tests; the limit is {policy.max_diff_lines}"
            )
        )
    added_text = "\n".join(
        line[1:]
        for line in git(worktree, "diff", "-U0", "--no-renames", f"{base_ref}...HEAD").stdout.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    for kind in find_secrets(added_text):
        violations.append(Violation("possible secret", kind))
    return violations
