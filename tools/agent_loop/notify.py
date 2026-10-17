"""Administrator notifications. The default backend uses GitHub itself: mentions, assignment, and review requests."""

from __future__ import annotations

from dataclasses import dataclass

from .gh import Gh

_KEY_MARKER = "agent-loop:notify key="


@dataclass(frozen=True)
class Notification:
    number: int
    key: str
    message: str
    is_pr: bool = False
    assign: bool = False
    request_review: bool = False


def notification_marker(key: str) -> str:
    return f"<!-- {_KEY_MARKER}{key} -->"


class Notifier:
    """Notifier interface; additional backends implement :meth:`send`."""

    def send(self, notification: Notification) -> str:
        raise NotImplementedError


class GitHubNotifier(Notifier):
    """Mention administrators in a comment, deduplicated by a hidden key marker.

    Must run as the GitHub App: GitHub does not notify users about their own comments or self-requested reviews.
    """

    def __init__(self, gh: Gh, mention: tuple[str, ...], dry_run: bool = False):
        self.gh = gh
        self.mention = mention
        self.dry_run = dry_run

    def _already_sent(self, notification: Notification) -> bool:
        owner, name = self.gh.repo_parts()
        comments = self.gh.api(f"repos/{owner}/{name}/issues/{notification.number}/comments", paginate=True) or []
        marker = notification_marker(notification.key)
        return any(marker in (comment.get("body") or "") for comment in comments)

    def body(self, notification: Notification) -> str:
        mentions = " ".join(f"@{login}" for login in self.mention)
        text = f"{mentions} {notification.message}".strip()
        return f"{text}\n\n{notification_marker(notification.key)}"

    def send(self, notification: Notification) -> str:
        target = f"{'PR' if notification.is_pr else 'issue'} #{notification.number}"
        if self.dry_run:
            return f"would notify {', '.join(self.mention) or 'nobody'} on {target}: {notification.message}"
        if not self.gh.as_app:
            raise RuntimeError("notifications must be sent as the GitHub App so administrators are notified")
        if self._already_sent(notification):
            return f"already notified on {target} ({notification.key})"
        owner, name = self.gh.repo_parts()
        self.gh.api(
            f"repos/{owner}/{name}/issues/{notification.number}/comments",
            method="POST",
            body={"body": self.body(notification)},
        )
        if notification.assign and self.mention:
            self.gh.api(
                f"repos/{owner}/{name}/issues/{notification.number}/assignees",
                method="POST",
                body={"assignees": list(self.mention)},
            )
        if notification.request_review and notification.is_pr and self.mention:
            self.gh.api(
                f"repos/{owner}/{name}/pulls/{notification.number}/requested_reviewers",
                method="POST",
                body={"reviewers": list(self.mention)},
            )
        return f"notified {', '.join(self.mention)} on {target}"
