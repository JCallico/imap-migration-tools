"""Disposable git worktrees that give each stage a clean checkout of the base branch."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class WorktreeError(RuntimeError):
    """Raised when a stage checkout cannot be prepared."""


def _git(repo_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), *args], capture_output=True, text=True, check=False, timeout=300
    )
    if completed.returncode != 0:
        raise WorktreeError(f"git {' '.join(args[:2])} failed: {completed.stderr.strip()[:300]}")
    return completed.stdout.strip()


def repository_root(start: Path | None = None) -> Path:
    return Path(_git(start or Path.cwd(), "rev-parse", "--show-toplevel"))


def remove_worktree(repo_root: Path, path: Path) -> None:
    if path.exists():
        try:
            _git(repo_root, "worktree", "remove", "--force", str(path))
        except WorktreeError:
            shutil.rmtree(path, ignore_errors=True)
    _git(repo_root, "worktree", "prune")


@contextmanager
def detached_checkout(repo_root: Path, base_branch: str, path: Path, remote: str = "origin") -> Iterator[str]:
    """Fetch ``remote/base_branch`` and check it out (detached) at ``path``; yields the commit SHA."""
    _git(repo_root, "fetch", "--quiet", remote, base_branch)
    remove_worktree(repo_root, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _git(repo_root, "worktree", "add", "--quiet", "--detach", str(path), f"{remote}/{base_branch}")
    try:
        yield _git(path, "rev-parse", "HEAD")
    finally:
        remove_worktree(repo_root, path)
