"""Disposable git worktrees that give each stage a clean checkout of the base branch."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

log = logging.getLogger(__name__)


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


@contextmanager
def pull_request_checkout(
    repo_root: Path, number: int, base_branch: str, path: Path, remote: str = "origin"
) -> Iterator[str]:
    """Check out pull request ``number``'s head (detached) at ``path`` with ``remote/base_branch`` fetched.

    Uses GitHub's ``refs/pull/<n>/head``, which also exists for pull requests from forks; yields the head SHA.
    """
    local_ref = f"refs/agent-loop/pull/{number}"
    _git(repo_root, "fetch", "--quiet", remote, base_branch)
    _git(repo_root, "fetch", "--quiet", remote, f"+refs/pull/{number}/head:{local_ref}")
    remove_worktree(repo_root, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _git(repo_root, "worktree", "add", "--quiet", "--detach", str(path), local_ref)
    try:
        yield _git(path, "rev-parse", "HEAD")
    finally:
        remove_worktree(repo_root, path)
        _git(repo_root, "update-ref", "-d", local_ref)


# --- persistent branch worktrees, commits, and pushes (implementation and CI repair stages) --------------------------

CHECKPOINT_DIR = ".agent-loop"
_SAFE_GIT = ("-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false")


def git(
    path: Path,
    *args: str,
    check: bool = True,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
    timeout: float = 600,
) -> subprocess.CompletedProcess:
    """Run git in ``path`` with repository hooks disabled."""
    completed = subprocess.run(
        ["git", *_SAFE_GIT, "-C", str(path), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        env=dict(env) if env is not None else None,
        input=input_text,
    )
    if check and completed.returncode != 0:
        raise WorktreeError(f"git {' '.join(args[:2])} failed: {completed.stderr.strip()[:400]}")
    return completed


def branch_slug(title: str, limit: int = 40) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:limit].strip("-")
    return slug or "change"


def issue_branch(number: int, title: str) -> str:
    return f"agent/issue-{number}-{branch_slug(title)}"


def issue_number_from_branch(branch: str | None) -> int | None:
    match = re.match(r"^agent/issue-(\d+)-", branch or "")
    return int(match.group(1)) if match else None


def _ref_exists(repo_root: Path, ref: str) -> bool:
    return git(repo_root, "show-ref", "--verify", "--quiet", ref, check=False).returncode == 0


def branch_worktree(repo_root: Path, branch: str, base_branch: str, path: Path, remote: str = "origin") -> Path:
    """Return a worktree for ``branch``: reuse ``path``, or create it from the local, remote, or base branch.

    A local branch with commits that were never pushed is kept as it is, never reset.
    """
    git(repo_root, "fetch", "--quiet", remote, base_branch)
    git(repo_root, "fetch", "--quiet", remote, branch, check=False)
    if (path / ".git").exists():
        log.info("reusing worktree %s on %s", path, branch)
        return path
    git(repo_root, "worktree", "prune")
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    if _ref_exists(repo_root, f"refs/heads/{branch}"):
        source = f"local {branch}"
        git(repo_root, "worktree", "add", "--quiet", str(path), branch)
    elif _ref_exists(repo_root, f"refs/remotes/{remote}/{branch}"):
        source = f"{remote}/{branch}"
        git(repo_root, "worktree", "add", "--quiet", "-b", branch, str(path), f"{remote}/{branch}")
    else:
        source = f"{remote}/{base_branch}"
        git(repo_root, "worktree", "add", "--quiet", "-b", branch, str(path), f"{remote}/{base_branch}")
    log.info("created worktree %s on %s from %s", path, branch, source)
    return path


def sync_with_remote(path: Path, branch: str, remote: str = "origin") -> None:
    """Fast-forward the worktree to the remote branch; refuse to proceed when the histories diverged."""
    git(path, "fetch", "--quiet", remote, branch, check=False)
    if not _ref_exists(path, f"refs/remotes/{remote}/{branch}"):
        return
    ahead_behind = git(path, "rev-list", "--left-right", "--count", f"HEAD...{remote}/{branch}").stdout.split()
    ahead, behind = int(ahead_behind[0]), int(ahead_behind[1])
    if behind and ahead:
        raise WorktreeError(f"local {branch} and {remote}/{branch} have diverged")
    if behind:
        git(path, "merge", "--quiet", "--ff-only", f"{remote}/{branch}")


def head_sha(path: Path) -> str:
    return git(path, "rev-parse", "HEAD").stdout.strip()


def has_uncommitted_changes(path: Path) -> bool:
    status = git(path, "status", "--porcelain", "--untracked-files=all", "--", ".", f":(exclude){CHECKPOINT_DIR}")
    return bool(status.stdout.strip())


def unpushed_commits(path: Path, base_branch: str, branch: str, remote: str = "origin") -> int:
    """Commits on HEAD that are on neither the remote branch nor, before it exists, the base branch."""
    target = f"{remote}/{branch}" if _ref_exists(path, f"refs/remotes/{remote}/{branch}") else f"{remote}/{base_branch}"
    return int(git(path, "rev-list", "--count", f"{target}..HEAD").stdout.strip() or 0)


def commit_all(path: Path, message: str, author_name: str, author_email: str) -> str | None:
    """Commit every change except the checkpoint directory; return the new SHA, or ``None`` when nothing changed."""
    staged = git(path, "add", "-A", "--", ".", f":(exclude){CHECKPOINT_DIR}", check=False)
    # When .gitignore also lists the checkpoint directory, git stages everything else but exits 1 with this notice.
    if staged.returncode and "ignored by one of your .gitignore files" not in staged.stderr:
        raise WorktreeError(f"git add failed: {staged.stderr.strip()[:400]}")
    if not git(path, "diff", "--cached", "--quiet", check=False).returncode:
        return None
    git(
        path,
        "-c",
        f"user.name={author_name}",
        "-c",
        f"user.email={author_email}",
        "commit",
        "--quiet",
        "--no-verify",
        "--no-gpg-sign",
        "-m",
        message,
    )
    sha = head_sha(path)
    log.info("committed %s as %s", sha[:12], author_name)
    return sha


_CREDENTIAL_HELPER = "!f() { echo username=x-access-token; echo password=$AGENT_LOOP_GIT_TOKEN; }; f"


def push_branch(path: Path, remote_url: str, branch: str, token: str, base_env: Mapping[str, str]) -> None:
    """Push ``HEAD`` to ``branch`` over HTTPS as the GitHub App, never forcing.

    The token is handed to a credential helper through the environment, so it never appears in a command line.
    """
    if not branch.startswith("agent/"):
        raise WorktreeError(f"refusing to push to {branch}: the agent loop only pushes agent/* branches")
    env = {key: value for key, value in base_env.items() if key in ("PATH", "HOME", "LANG", "TMPDIR")}
    env.update({"AGENT_LOOP_GIT_TOKEN": token, "GIT_TERMINAL_PROMPT": "0"})
    log.info("pushing %s to %s", branch, remote_url)
    git(
        path,
        "-c",
        "credential.helper=",
        "-c",
        f"credential.helper={_CREDENTIAL_HELPER}",
        "push",
        "--quiet",
        remote_url,
        f"HEAD:refs/heads/{branch}",
        env=env,
        timeout=900,
    )
    git(path, "fetch", "--quiet", "origin", branch, check=False)


def delete_local_branch(repo_root: Path, branch: str) -> None:
    git(repo_root, "branch", "-D", branch, check=False)
