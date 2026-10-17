"""GitHub write operations performed by the dispatcher through ``gh``."""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import quote

from .gh import Gh, GhError
from .snapshot import Item

STATUS_MARKER = "<!-- agent-loop:status -->"


def _issue_path(gh: Gh, number: int) -> str:
    owner, name = gh.repo_parts()
    return f"repos/{owner}/{name}/issues/{number}"


def add_labels(gh: Gh, number: int, labels: Iterable[str]) -> None:
    labels = list(labels)
    if labels:
        gh.api(f"{_issue_path(gh, number)}/labels", method="POST", body={"labels": labels})


def remove_label(gh: Gh, number: int, label: str) -> None:
    try:
        gh.api(f"{_issue_path(gh, number)}/labels/{quote(label, safe='')}", method="DELETE")
    except GhError as exc:
        if "404" not in exc.stderr and "Not Found" not in exc.stderr:
            raise


def set_labels(gh: Gh, item: Item, add: Iterable[str] = (), remove: Iterable[str] = ()) -> None:
    """Add and remove labels relative to the item's current labels, skipping no-op calls."""
    add_labels(gh, item.number, [label for label in dict.fromkeys(add) if label not in item.labels])
    for label in remove:
        if label in item.labels:
            remove_label(gh, item.number, label)


def post_comment(gh: Gh, number: int, body: str) -> None:
    gh.api(f"{_issue_path(gh, number)}/comments", method="POST", body={"body": body})


def update_comment(gh: Gh, node_id: str, body: str) -> None:
    gh.graphql(
        "mutation($id: ID!, $body: String!) { updateIssueComment(input: {id: $id, body: $body}) { issueComment { id } } }",
        {"id": node_id, "body": body},
    )


def upsert_status(gh: Gh, item: Item, bot_login: str | None, text: str) -> None:
    """Create or edit the single bot status comment on an item."""
    body = f"{text}\n\n{STATUS_MARKER}"
    for comment in item.comments:
        if bot_login and comment.author == bot_login and STATUS_MARKER in comment.body:
            if comment.body != body:
                update_comment(gh, comment.id, body)
            return
    post_comment(gh, item.number, body)


def clear_status(gh: Gh, item: Item, bot_login: str | None) -> None:
    """Delete the bot status comment once the condition it described is over."""
    for comment in item.comments:
        if bot_login and comment.author == bot_login and STATUS_MARKER in comment.body:
            gh.graphql(
                "mutation($id: ID!) { deleteIssueComment(input: {id: $id}) { clientMutationId } }", {"id": comment.id}
            )


def react(gh: Gh, node_id: str, content: str = "EYES") -> None:
    """Add a reaction to a comment (idempotent: reacting twice with the same content is a no-op)."""
    if content not in ("EYES", "THUMBS_UP", "ROCKET"):
        raise ValueError(f"unsupported reaction {content!r}")
    gh.graphql(
        "mutation($id: ID!) { addReaction(input: {subjectId: $id, content: "
        + content
        + "}) { reaction { content } } }",
        {"id": node_id},
    )


def assign(gh: Gh, number: int, logins: Iterable[str]) -> None:
    logins = list(logins)
    if logins:
        gh.api(f"{_issue_path(gh, number)}/assignees", method="POST", body={"assignees": logins})
