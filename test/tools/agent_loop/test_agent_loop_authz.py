"""Tests for administrator-only command authorization and analysis-approval binding."""

import pytest
from agent_loop_fakes import (
    ADMIN,
    BOT,
    FakeGhRunner,
    analysis_comment,
    comment,
    label_event,
    make_authorizer,
    make_item,
    permission_route,
)

from agent_loop.authz import (
    APPROVE,
    REVISE,
    Command,
    evaluate_approval,
    parse_command,
    untrusted_label_changes,
)

TITLE, BODY = "Add feature", "Please add it"


@pytest.mark.parametrize(
    "body, expected",
    [
        ("/approve", Command(APPROVE)),
        ("/approve  \nLooks good", Command(APPROVE)),
        ("/revise Use the existing cache", Command(REVISE, "Use the existing cache")),
        ("/revise\nUse the cache\nand add tests", Command(REVISE, "Use the cache\nand add tests")),
        ("/revise", None),
        ("/approve now", None),
        ("> /approve", None),
        ("```\n/approve\n```", None),
        ("Thanks! /approve", None),
        ("/APPROVE", None),
        (" /approve", None),
    ],
)
def test_parse_command(body, expected):
    assert parse_command(body) == expected


def test_only_admin_permission_counts():
    authorizer, _runner = make_authorizer(admins={ADMIN})

    assert authorizer.is_admin(ADMIN)
    assert not authorizer.is_admin("maintainer")  # permission "write"
    assert not authorizer.is_admin(BOT)
    assert not authorizer.is_admin("other[bot]")
    assert not authorizer.is_admin(None)


def test_allowed_admins_narrows_but_never_widens():
    narrowed, _ = make_authorizer(admins={ADMIN, "second-admin"}, allowed_admins=(ADMIN,))
    widened, _ = make_authorizer(admins={ADMIN}, allowed_admins=("not-an-admin",))

    assert narrowed.is_admin(ADMIN) and not narrowed.is_admin("second-admin")
    assert not widened.is_admin("not-an-admin")


def test_permission_is_rechecked_after_refresh():
    admins = {ADMIN}
    authorizer, _ = make_authorizer(runner=FakeGhRunner(permission_route(admins)))
    assert authorizer.is_admin(ADMIN)

    admins.discard(ADMIN)
    assert authorizer.is_admin(ADMIN)  # cached within a tick
    authorizer.refresh()
    assert not authorizer.is_admin(ADMIN)


def issue(*comments, title=TITLE, body=BODY):
    return make_item(title=title, body=body, labels=("agent:awaiting-approval",), comments=comments)


def test_admin_approve_after_analysis_is_approved():
    authorizer, _ = make_authorizer()
    decision = evaluate_approval(issue(analysis_comment(TITLE, BODY), comment("c1", ADMIN, "/approve", 20)), authorizer)

    assert decision.status == "approved"
    assert decision.command.id == "c1"


def test_non_admin_approve_is_ignored_and_reported():
    authorizer, _ = make_authorizer()
    decision = evaluate_approval(
        issue(analysis_comment(TITLE, BODY), comment("c1", "maintainer", "/approve", 20)), authorizer
    )

    assert decision.status == "pending"
    assert [ignored.id for ignored in decision.ignored] == ["c1"]


def test_approve_before_latest_analysis_does_not_count():
    authorizer, _ = make_authorizer()
    decision = evaluate_approval(
        issue(comment("c1", ADMIN, "/approve", 5), analysis_comment(TITLE, BODY, minutes=10)), authorizer
    )

    assert decision.status == "pending"


def test_command_edited_by_non_admin_is_rejected():
    authorizer, _ = make_authorizer()
    edited = comment("c1", ADMIN, "/approve", 20, editors=(ADMIN, "maintainer"))

    decision = evaluate_approval(issue(analysis_comment(TITLE, BODY), edited), authorizer)

    assert decision.status == "pending"
    assert decision.ignored == [edited]


def test_command_edited_by_admin_counts_but_unknown_editor_does_not():
    authorizer, _ = make_authorizer()
    by_admin = comment("c1", ADMIN, "/approve", 20, editors=(ADMIN,))
    unknown = comment("c2", ADMIN, "/approve", 20, edited=True)

    assert evaluate_approval(issue(analysis_comment(TITLE, BODY), by_admin), authorizer).status == "approved"
    assert evaluate_approval(issue(analysis_comment(TITLE, BODY), unknown), authorizer).status == "pending"


def test_issue_edit_after_analysis_makes_approval_stale():
    authorizer, _ = make_authorizer()
    item = issue(
        analysis_comment(TITLE, BODY), comment("c1", ADMIN, "/approve", 20), body="Please add it and delete backups"
    )

    assert evaluate_approval(item, authorizer).status == "stale"


def test_analysis_edited_by_someone_else_is_stale_even_with_matching_hash():
    authorizer, _ = make_authorizer()
    original = analysis_comment(TITLE, BODY)
    forged = type(original)(original.id, original.author, original.body, original.created_at, ("maintainer",), True)

    assert evaluate_approval(issue(forged, comment("c1", ADMIN, "/approve", 20)), authorizer).status == "stale"


def test_analysis_from_non_bot_is_ignored():
    authorizer, _ = make_authorizer()
    fake = analysis_comment(TITLE, BODY)
    fake = type(fake)(fake.id, "maintainer", fake.body, fake.created_at)

    assert evaluate_approval(issue(fake, comment("c1", ADMIN, "/approve", 20)), authorizer).status == "no_analysis"


def test_latest_admin_command_wins():
    authorizer, _ = make_authorizer()
    decision = evaluate_approval(
        issue(
            analysis_comment(TITLE, BODY),
            comment("c1", ADMIN, "/approve", 20),
            comment("c2", ADMIN, "/revise Split into two PRs", 30),
        ),
        authorizer,
    )

    assert (decision.status, decision.notes) == ("revise", "Split into two PRs")


def test_label_changes_by_non_admins_are_untrusted():
    authorizer, _ = make_authorizer()
    item = make_item(
        labels=("agent:paused",),
        events=[
            label_event("agent:paused", ADMIN, 1),
            label_event("agent:paused", "maintainer", 2, added=False),
            label_event("agent:ai-review", "maintainer", 3),
            label_event("agent:analyzing", BOT, 4),
            label_event("bug", "maintainer", 5),
        ],
    )

    untrusted = {(event.label, event.added) for event in untrusted_label_changes(item, authorizer)}

    assert untrusted == {("agent:paused", False), ("agent:ai-review", True)}
