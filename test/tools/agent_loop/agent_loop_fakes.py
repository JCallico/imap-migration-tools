"""Shared fakes for agent loop tests: a scripted ``gh`` runner and item builders."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent_loop.authz import Authorizer, analysis_hash, analysis_marker
from agent_loop.gh import Gh
from agent_loop.snapshot import Comment, Item, LabelEvent, Review

FIXTURES = Path(__file__).parent / "fixtures"
REPO = "owner/repo"
BOT = "imap-agent[bot]"
ADMIN = "admin-user"
T0 = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)


def at(minutes: int) -> datetime:
    return T0 + timedelta(minutes=minutes)


class FakeGhRunner:
    """Records ``gh`` invocations and answers them with a routing function."""

    def __init__(self, route: Callable[[list[str], str | None], object] | None = None):
        self.calls: list[dict] = []
        self.route = route or (lambda args, stdin: {})

    def __call__(self, command, input=None, env=None, **kwargs):
        args = list(command[1:])
        self.calls.append({"args": args, "input": input, "env": dict(env or {})})
        result = self.route(args, input)
        if isinstance(result, subprocess.CompletedProcess):
            return result
        stdout = result if isinstance(result, str) else json.dumps(result)
        return subprocess.CompletedProcess(command, 0, stdout, "")

    def api_calls(self, method: str | None = None) -> list[dict]:
        found = []
        for call in self.calls:
            args = call["args"]
            if args[:1] != ["api"] or (len(args) > 1 and args[1] == "graphql"):
                continue
            call_method = args[args.index("--method") + 1] if "--method" in args else "GET"
            if method is None or call_method == method:
                found.append(call)
        return found


def permission_route(admins: set[str], extra=None):
    """Route collaborator-permission lookups: listed logins are admins, everyone else has write."""

    def route(args, stdin):
        path = next((arg for arg in args if arg.startswith("repos/") and arg.endswith("/permission")), None)
        if path is not None:
            login = path.split("/")[-2]
            return {"permission": "admin" if login in admins else "write"}  # admins is read live
        if extra is not None:
            return extra(args, stdin)
        return {}

    return route


def make_authorizer(admins=(ADMIN,), allowed_admins=(), runner: FakeGhRunner | None = None):
    runner = runner or FakeGhRunner(permission_route(set(admins)))
    gh = Gh(REPO, runner=runner, base_env={"PATH": "/usr/bin"})
    return Authorizer(gh, BOT, allowed_admins), runner


def comment(cid: str, author: str | None, body: str, minutes: int, editors=(), edited=False) -> Comment:
    return Comment(cid, author, body, at(minutes), tuple(editors), edited or bool(editors))


def label_event(label: str, actor: str | None, minutes: int, added: bool = True) -> LabelEvent:
    return LabelEvent(label, actor, added, at(minutes))


def analysis_comment(
    title: str, body: str, text: str = "Spec", minutes: int = 10, rev: int = 1, cid="analysis"
) -> Comment:
    marker = analysis_marker(rev, analysis_hash(title, body, text), "claude:claude-opus-5-5:medium")
    return comment(cid, BOT, f"{text}\n\n{marker}", minutes)


def make_item(
    number: int = 1,
    *,
    is_pr: bool = False,
    title: str = "Add feature",
    body: str = "Please add it",
    author: str = "reporter",
    labels=(),
    comments=(),
    events=None,
    reviews=(),
    created: int = 0,
    truncated: bool = False,
) -> Item:
    if events is None:
        events = [label_event(label, BOT, 1) for label in labels]
    return Item(
        number=number,
        is_pr=is_pr,
        title=title,
        body=body,
        author=author,
        state="OPEN",
        created_at=at(created),
        labels=frozenset(labels),
        comments=tuple(comments),
        label_events=tuple(events),
        reviews=tuple(reviews),
        head_sha="abc123" if is_pr else None,
        truncated=truncated,
    )


def review(author: str, state: str, minutes: int, body: str = "") -> Review:
    return Review(author, state, at(minutes), "abc123", body)


def run_git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True).stdout.strip()


def make_world(tmp_path: Path) -> tuple[Path, Path]:
    """A bare "origin" and a clone with the skills the stages load; returns ``(origin, checkout)``."""
    origin = tmp_path / "origin.git"
    root = tmp_path / "checkout"
    subprocess.run(["git", "init", "--quiet", "--bare", "-b", "main", str(origin)], check=True)
    subprocess.run(["git", "clone", "--quiet", str(origin), str(root)], check=True, capture_output=True)
    run_git(root, "config", "user.email", "t@example.com")
    run_git(root, "config", "user.name", "T")
    run_git(root, "checkout", "-q", "-b", "main")
    (root / "README.md").write_text("project\n")
    for skill in ("implement-approved-issue", "cross-model-pr-review", "address-review-feedback"):
        path = root / ".claude" / "skills" / skill / "SKILL.md"
        path.parent.mkdir(parents=True)
        path.write_text(f"# {skill}\nFollow AGENTS.md.\n")
    run_git(root, "add", "-A")
    run_git(root, "commit", "-q", "-m", "init")
    run_git(root, "push", "-q", "origin", "main")
    return origin, root
