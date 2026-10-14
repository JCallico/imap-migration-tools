"""Administrator-only trigger authorization, command parsing, and analysis-approval binding.

Only users whose repository collaborator permission is ``admin`` can trigger write-capable actions. The dispatcher
enforces this before any model runs; skills never make authorization decisions.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .gh import Gh, GhError
from .snapshot import Comment, Item, LabelEvent

AGENT_LABEL_PREFIX = "agent:"

APPROVE = "approve"
REVISE = "revise"
NOTE = "note"

_COMMAND = re.compile(r"^/(approve|revise|note)(?:[ \t]+(.*))?$")
# A first line that looks like one of our commands but is malformed (for example "/approve now") is ignored rather
# than treated as an ordinary comment, so a typo can never be read as a request to revise.
_COMMAND_LIKE = re.compile(r"^/(approve|revise|note)\b", re.IGNORECASE)
_ANALYSIS_MARKER = re.compile(r"<!--\s*agent-loop:analysis\s+([^>]*?)\s*-->")
_MARKER_FIELD = re.compile(r"(\w+)=(\S+)")


@dataclass(frozen=True)
class Command:
    name: str
    notes: str = ""


def parse_command(body: str) -> Command | None:
    """Parse a command that must be the exact first line of a comment.

    ``/approve`` takes no arguments. ``/revise`` requires notes, taken from the rest of the first line and any
    following lines. ``/note`` marks a comment that must not trigger a revision. Quoted text, code blocks, and
    commands later in a comment never match.
    """
    lines = body.replace("\r\n", "\n").split("\n")
    first = lines[0].rstrip()
    match = _COMMAND.match(first)
    if not match:
        return None
    name, rest = match.group(1), (match.group(2) or "").strip()
    if name == APPROVE:
        return Command(APPROVE) if not rest else None
    if name == NOTE:
        return Command(NOTE, "\n".join([rest, *lines[1:]]).strip())
    notes = "\n".join([rest, *lines[1:]]).strip()
    return Command(REVISE, notes) if notes else None


def looks_like_command(body: str) -> bool:
    """True when the first line starts with one of our commands, whether or not it is well formed."""
    return bool(_COMMAND_LIKE.match(body.replace("\r\n", "\n").split("\n")[0].strip()))


def mentions(body: str, login: str | None) -> bool:
    """True when ``body`` @mentions ``login`` (a GitHub App's ``[bot]`` suffix is optional in the mention)."""
    if not login:
        return False
    name = re.escape(login.removesuffix("[bot]"))
    return bool(re.search(rf"(?<![\w/@.-])@{name}(?:\[bot\])?(?![\w-])", body, re.IGNORECASE))


def analysis_hash(issue_title: str, issue_body: str, analysis_text: str) -> str:
    """Hash binding an analysis to the exact issue text it analyzed."""
    digest = hashlib.sha256()
    for part in (issue_title, issue_body, analysis_text):
        normalized = part.replace("\r\n", "\n").strip().encode("utf-8")
        digest.update(len(normalized).to_bytes(8, "big"))
        digest.update(normalized)
    return digest.hexdigest()


def strip_analysis_marker(body: str) -> str:
    return _ANALYSIS_MARKER.sub("", body).strip()


def analysis_marker(rev: int, digest: str, model: str, seen: datetime | None = None) -> str:
    """Hidden marker binding an analysis to the issue text it analyzed.

    ``seen`` is the newest comment timestamp in the snapshot the model was given, so comments posted while the
    analysis was running are still treated as new afterwards.
    """
    seen_field = f" seen={int(seen.timestamp())}" if seen is not None else ""
    return f"<!-- agent-loop:analysis rev={rev} hash={digest} model={model}{seen_field} -->"


@dataclass(frozen=True)
class Analysis:
    comment: Comment
    rev: int
    hash: str
    model: str
    seen_at: datetime | None = None

    @property
    def since(self) -> datetime:
        """Comments after this moment were not part of the analysis."""
        return self.seen_at or self.comment.created_at

    def matches(self, item: Item) -> bool:
        return analysis_hash(item.title, item.body, strip_analysis_marker(self.comment.body)) == self.hash


def parse_analysis(comment: Comment) -> Analysis | None:
    match = _ANALYSIS_MARKER.search(comment.body)
    if not match:
        return None
    fields = dict(_MARKER_FIELD.findall(match.group(1)))
    try:
        rev = int(fields["rev"])
    except (KeyError, ValueError):
        return None
    if "hash" not in fields:
        return None
    seen_at = None
    if "seen" in fields:
        try:
            seen_at = datetime.fromtimestamp(int(fields["seen"]), timezone.utc)
        except (ValueError, OverflowError, OSError):
            seen_at = None
    return Analysis(comment, rev, fields["hash"], fields.get("model", ""), seen_at)


class Authorizer:
    """Answers whether a GitHub login is a repository administrator, caching results for one tick."""

    def __init__(self, gh: Gh, bot_login: str | None, allowed_admins: Iterable[str] = ()):
        self.gh = gh
        self.bot_login = bot_login
        self.allowed_admins = {login.lower() for login in allowed_admins}
        self._cache: dict[str, bool] = {}

    def is_bot(self, login: str | None) -> bool:
        return bool(login) and bool(self.bot_login) and login.lower() == self.bot_login.lower()  # type: ignore[union-attr]

    def is_admin(self, login: str | None) -> bool:
        if not login or login.endswith("[bot]") or self.is_bot(login):
            return False
        if self.allowed_admins and login.lower() not in self.allowed_admins:
            return False
        key = login.lower()
        if key not in self._cache:
            self._cache[key] = self._lookup(login)
        return self._cache[key]

    def _lookup(self, login: str) -> bool:
        owner, name = self.gh.repo_parts()
        try:
            data = self.gh.api(f"repos/{owner}/{name}/collaborators/{login}/permission")
        except GhError:
            return False
        return isinstance(data, dict) and data.get("permission") == "admin"

    def refresh(self) -> None:
        """Forget cached permissions so revoked access takes effect at execution time."""
        self._cache.clear()

    def comment_is_trusted(self, comment: Comment) -> bool:
        """An administrator wrote the comment and only administrators ever edited it."""
        if not self.is_admin(comment.author):
            return False
        if comment.edited and not comment.editors:
            return False
        return all(self.is_admin(editor) for editor in comment.editors)

    def is_trusted_actor(self, login: str | None) -> bool:
        return self.is_bot(login) or self.is_admin(login)


@dataclass
class ApprovalDecision:
    """Outcome of evaluating administrator comments against the latest analysis.

    ``status`` is ``no_analysis``, ``stale``, ``pending`` (nothing to act on), ``waiting`` (comments received, waiting
    for the administrator to finish), ``revise``, or ``approved``.
    """

    status: str
    analysis: Analysis | None = None
    command: Comment | None = None
    notes: str = ""
    ignored: list[Comment] = field(default_factory=list)
    reason: str = ""
    comments: list[Comment] = field(default_factory=list)  # administrator comments the loop is acting on
    ready_at: datetime | None = None


def latest_analysis(item: Item, authorizer: Authorizer) -> Analysis | None:
    analyses = [
        analysis
        for comment in item.comments
        if authorizer.is_bot(comment.author) and (analysis := parse_analysis(comment)) is not None
    ]
    return max(analyses, key=lambda analysis: (analysis.comment.created_at, analysis.rev), default=None)


def compose_notes(entries: list[tuple[Comment, Command | None]]) -> str:
    """Join the administrator's comments into revision notes for the analysis stage."""
    texts = [(comment, command.notes if command is not None else comment.body.strip()) for comment, command in entries]
    texts = [(comment, text) for comment, text in texts if text]
    if len(texts) == 1:
        return texts[0][1]
    return "\n\n".join(
        f"Comment {index} from {comment.author}:\n{text}" for index, (comment, text) in enumerate(texts, 1)
    )


def evaluate_approval(
    item: Item,
    authorizer: Authorizer,
    now: datetime | None = None,
    debounce_minutes: float = 0.0,
) -> ApprovalDecision:
    """Decide what the administrator's comments since the latest analysis ask for.

    Only comments authored, and edited, exclusively by administrators count. ``/approve`` and ``/revise <notes>`` are
    explicit: the latest explicit command wins and acts immediately. Without one, every other administrator comment is a
    request to revise: it runs immediately when it @mentions the bot, and otherwise after the administrator has been
    quiet for ``debounce_minutes`` so several comments become one revision. ``/note`` comments never trigger anything.
    Unauthorized commands are always reported in ``ignored`` so the dispatcher can answer them.
    """
    now = now or datetime.now(timezone.utc)
    analysis = latest_analysis(item, authorizer)
    since = analysis.since if analysis is not None else None
    entries: list[tuple[Comment, Command | None]] = []
    ignored: list[Comment] = []
    for comment in sorted(item.comments, key=lambda comment: comment.created_at):
        if (since is not None and comment.created_at <= since) or authorizer.is_bot(comment.author):
            continue
        command = parse_command(comment.body)
        if command is None and looks_like_command(comment.body):
            continue  # malformed command: never an implicit revision
        trusted = authorizer.comment_is_trusted(comment)
        if command is not None and not trusted:
            ignored.append(comment)
        elif trusted and not (command is not None and command.name == NOTE):
            entries.append((comment, command))
    if analysis is None:
        return ApprovalDecision("no_analysis", ignored=ignored, reason="no analysis comment from the agent loop bot")
    if analysis.comment.edited and not (
        analysis.comment.editors and all(authorizer.is_bot(editor) for editor in analysis.comment.editors)
    ):
        # The marker hash is not secret, so an edit by anyone else could forge a matching analysis.
        reason = f"analysis rev {analysis.rev} was edited by another user"
        return ApprovalDecision("stale", analysis, ignored=ignored, reason=reason)
    if not analysis.matches(item):
        reason = f"issue or analysis rev {analysis.rev} changed after it was posted"
        return ApprovalDecision("stale", analysis, ignored=ignored, reason=reason)
    if not entries:
        return ApprovalDecision("pending", analysis, ignored=ignored)
    explicit = [(comment, command) for comment, command in entries if command is not None]
    if explicit:
        last_comment, last_command = explicit[-1]
        if last_command.name == APPROVE:
            return ApprovalDecision("approved", analysis, last_comment, "", ignored, comments=[last_comment])
        notes = compose_notes([entry for entry in entries if entry[1] is None or entry[1].name == REVISE])
        return ApprovalDecision(
            "revise", analysis, last_comment, notes, ignored, comments=[comment for comment, _ in entries]
        )
    comments = [comment for comment, _ in entries]
    notes = compose_notes(entries)
    if any(mentions(comment.body, authorizer.bot_login) for comment in comments):
        return ApprovalDecision("revise", analysis, comments[-1], notes, ignored, comments=comments)
    ready_at = comments[-1].created_at + timedelta(minutes=debounce_minutes)
    if now >= ready_at:
        return ApprovalDecision("revise", analysis, comments[-1], notes, ignored, comments=comments)
    return ApprovalDecision("waiting", analysis, None, notes, ignored, comments=comments, ready_at=ready_at)


def untrusted_label_changes(item: Item, authorizer: Authorizer) -> list[LabelEvent]:
    """Return the latest change to each ``agent:*`` label when it was made by someone other than the bot or an admin."""
    latest: dict[str, LabelEvent] = {}
    for event in sorted(item.label_events, key=lambda event: event.created_at):
        if event.label.startswith(AGENT_LABEL_PREFIX):
            latest[event.label] = event
    return [event for event in latest.values() if not authorizer.is_trusted_actor(event.actor)]


def label_applied_by_admin(item: Item, label: str, authorizer: Authorizer) -> bool:
    events = [event for event in item.label_events if event.label == label]
    if label not in item.labels or not events:
        return False
    last = max(events, key=lambda event: event.created_at)
    return last.added and authorizer.is_admin(last.actor)
