"""Immutable snapshots of issues and pull requests fetched from GitHub through ``gh api graphql``."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime

from .gh import Gh

COMMENT_LIMIT = 100
EVENT_LIMIT = 100
REVIEW_LIMIT = 50


@dataclass(frozen=True)
class Comment:
    id: str
    author: str | None
    body: str
    created_at: datetime
    editors: tuple[str | None, ...] = ()
    edited: bool = False


@dataclass(frozen=True)
class LabelEvent:
    label: str
    actor: str | None
    added: bool
    created_at: datetime


@dataclass(frozen=True)
class Review:
    author: str | None
    state: str
    submitted_at: datetime | None
    commit: str | None
    body: str = ""


@dataclass(frozen=True)
class Item:
    """An issue or pull request with the context the dispatcher needs to decide its next action."""

    number: int
    is_pr: bool
    title: str
    body: str
    author: str | None
    state: str
    created_at: datetime
    labels: frozenset[str]
    comments: tuple[Comment, ...]
    label_events: tuple[LabelEvent, ...]
    reviews: tuple[Review, ...] = ()
    head_sha: str | None = None
    is_draft: bool = False
    truncated: bool = False
    url: str = ""


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def actor_login(node: dict | None) -> str | None:
    """Normalize GraphQL actors; bot logins gain the ``[bot]`` suffix used by REST and the UI."""
    if not node:
        return None
    login = node.get("login")
    if not login:
        return None
    if node.get("__typename") == "Bot" and not login.endswith("[bot]"):
        return f"{login}[bot]"
    return login


_ACTOR = "{ __typename login }"
_COMMENTS = f"""
comments(last: {COMMENT_LIMIT}) {{
  totalCount
  nodes {{
    id body createdAt lastEditedAt
    author {_ACTOR}
    userContentEdits(first: 50) {{ nodes {{ editor {_ACTOR} }} }}
  }}
}}"""
_LABEL_EVENTS = f"""
timelineItems(last: {EVENT_LIMIT}, itemTypes: [LABELED_EVENT, UNLABELED_EVENT]) {{
  totalCount
  nodes {{
    __typename
    ... on LabeledEvent {{ createdAt actor {_ACTOR} label {{ name }} }}
    ... on UnlabeledEvent {{ createdAt actor {_ACTOR} label {{ name }} }}
  }}
}}"""
_COMMON = f"""
number title body url state createdAt
author {_ACTOR}
labels(first: 50) {{ nodes {{ name }} }}
{_COMMENTS}
{_LABEL_EVENTS}"""

ISSUES_QUERY = f"""
query($owner: String!, $name: String!, $cursor: String) {{
  repository(owner: $owner, name: $name) {{
    issues(states: OPEN, first: 25, after: $cursor, orderBy: {{field: CREATED_AT, direction: ASC}}) {{
      pageInfo {{ hasNextPage endCursor }}
      nodes {{ {_COMMON} }}
    }}
  }}
}}"""

PULLS_QUERY = f"""
query($owner: String!, $name: String!, $cursor: String) {{
  repository(owner: $owner, name: $name) {{
    pullRequests(states: OPEN, first: 25, after: $cursor, orderBy: {{field: CREATED_AT, direction: ASC}}) {{
      pageInfo {{ hasNextPage endCursor }}
      nodes {{
        {_COMMON}
        isDraft headRefOid
        reviews(last: {REVIEW_LIMIT}) {{
          nodes {{ state submittedAt body author {_ACTOR} commit {{ oid }} }}
        }}
      }}
    }}
  }}
}}"""


def item_from_node(node: dict, is_pr: bool) -> Item:
    comments_conn = node.get("comments") or {}
    comments = []
    for raw in comments_conn.get("nodes") or []:
        edits = (raw.get("userContentEdits") or {}).get("nodes") or []
        comments.append(
            Comment(
                id=raw["id"],
                author=actor_login(raw.get("author")),
                body=raw.get("body") or "",
                created_at=parse_time(raw["createdAt"]),  # type: ignore[arg-type]
                editors=tuple(actor_login(edit.get("editor")) for edit in edits),
                edited=bool(raw.get("lastEditedAt")),
            )
        )
    events_conn = node.get("timelineItems") or {}
    events = []
    for raw in events_conn.get("nodes") or []:
        label = (raw.get("label") or {}).get("name")
        if not label:
            continue
        events.append(
            LabelEvent(
                label=label,
                actor=actor_login(raw.get("actor")),
                added=raw.get("__typename") == "LabeledEvent",
                created_at=parse_time(raw["createdAt"]),  # type: ignore[arg-type]
            )
        )
    reviews = []
    for raw in (node.get("reviews") or {}).get("nodes") or []:
        reviews.append(
            Review(
                author=actor_login(raw.get("author")),
                state=raw.get("state") or "",
                submitted_at=parse_time(raw.get("submittedAt")),
                commit=(raw.get("commit") or {}).get("oid"),
                body=raw.get("body") or "",
            )
        )
    truncated = (comments_conn.get("totalCount") or 0) > len(comments) or (events_conn.get("totalCount") or 0) > len(
        events
    )
    return Item(
        number=int(node["number"]),
        is_pr=is_pr,
        title=node.get("title") or "",
        body=node.get("body") or "",
        author=actor_login(node.get("author")),
        state=node.get("state") or "",
        created_at=parse_time(node["createdAt"]),  # type: ignore[arg-type]
        labels=frozenset(label["name"] for label in (node.get("labels") or {}).get("nodes") or []),
        comments=tuple(comments),
        label_events=tuple(events),
        reviews=tuple(reviews),
        head_sha=node.get("headRefOid"),
        is_draft=bool(node.get("isDraft")),
        truncated=truncated,
        url=node.get("url") or "",
    )


def _paginate(gh: Gh, query: str, key: str) -> Iterator[dict]:
    owner, name = gh.repo_parts()
    cursor = None
    while True:
        data = gh.graphql(query, {"owner": owner, "name": name, "cursor": cursor})
        connection = (data.get("repository") or {}).get(key) or {}
        yield from connection.get("nodes") or []
        page = connection.get("pageInfo") or {}
        if not page.get("hasNextPage"):
            return
        cursor = page.get("endCursor")


def fetch_open_items(gh: Gh) -> list[Item]:
    """Fetch all open issues and pull requests with comments, label history, and reviews."""
    items = [item_from_node(node, is_pr=False) for node in _paginate(gh, ISSUES_QUERY, "issues")]
    items += [item_from_node(node, is_pr=True) for node in _paginate(gh, PULLS_QUERY, "pullRequests")]
    return items
