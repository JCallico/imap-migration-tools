"""Tests for administrator-only command authorization and analysis-approval binding."""

import pytest
from agent_loop_fakes import (
    ADMIN,
    BOT,
    FakeGhRunner,
    analysis_comment,
    at,
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
    analysis_hash,
    analysis_marker,
    evaluate_approval,
    mentions,
    parse_analysis,
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


# --- natural conversation: administrator comments default to revision requests ----------------------------------


def review(*comments, now_minutes=60, debounce=5.0, **kwargs):
    authorizer, _ = make_authorizer()
    return evaluate_approval(
        issue(analysis_comment(TITLE, BODY), *comments, **kwargs), authorizer, at(now_minutes), debounce
    )


def test_plain_admin_comment_waits_for_the_debounce_then_revises():
    quiet = comment("c1", ADMIN, "Can we also cover the Android build?", 20)

    waiting = review(quiet, now_minutes=22)
    ready = review(quiet, now_minutes=26)

    assert waiting.status == "waiting" and waiting.ready_at == at(25) and waiting.comments == [quiet]
    assert ready.status == "revise" and ready.notes == "Can we also cover the Android build?"


def test_several_comments_become_one_revision_and_restart_the_wait():
    first = comment("c1", ADMIN, "Split S4 out", 20)
    second = comment("c2", ADMIN, "And drop S9", 24)

    waiting = review(first, second, now_minutes=26)
    ready = review(first, second, now_minutes=30)

    assert waiting.status == "waiting"
    assert ready.status == "revise" and [c.id for c in ready.comments] == ["c1", "c2"]
    assert ready.notes == "Comment 1 from admin-user:\nSplit S4 out\n\nComment 2 from admin-user:\nAnd drop S9"


def test_mentioning_the_bot_revises_immediately():
    ask = comment("c1", ADMIN, "@imap-agent can you reconsider the library choice?", 20)

    assert review(ask, now_minutes=21).status == "revise"
    assert review(comment("c2", ADMIN, "@imap-agent[bot] thoughts?", 20), now_minutes=21).status == "revise"
    assert review(comment("c3", ADMIN, "email me@imap-agent.example", 20), now_minutes=21).status == "waiting"


def test_explicit_revise_is_immediate_and_includes_other_comments():
    decision = review(
        comment("c1", ADMIN, "Keep it small", 20), comment("c2", ADMIN, "/revise Use certifi", 21), now_minutes=21
    )

    assert decision.status == "revise"
    assert "Keep it small" in decision.notes and "Use certifi" in decision.notes


def test_note_comments_never_trigger_a_revision():
    note = comment("c1", ADMIN, "/note I'll look at this tomorrow", 20)

    decision = review(note, now_minutes=200)

    assert decision.status == "pending" and decision.comments == []


def test_approve_beats_later_plain_comments_but_not_a_later_revise():
    approve = comment("c1", ADMIN, "/approve", 20)
    chat = comment("c2", ADMIN, "thanks, also FYI the release is Friday", 22)
    revise = comment("c3", ADMIN, "/revise actually split it", 23)

    assert review(approve, chat, now_minutes=100).status == "approved"
    assert review(chat, approve, now_minutes=100).status == "approved"
    assert review(approve, chat, revise, now_minutes=100).status == "revise"


def test_non_admin_comments_never_trigger_even_when_they_mention_the_bot():
    outsider = comment("c1", "maintainer", "@imap-agent please rewrite everything", 20)
    reporter = comment("c2", "reporter", "any update?", 21)

    decision = review(outsider, reporter, now_minutes=200)

    assert decision.status == "pending" and decision.ignored == []


def test_malformed_commands_are_ignored_not_treated_as_comments():
    for body in ("/approve now", "/APPROVE", "/revise", "/note"[:0] + "/Revise"):
        assert review(comment("c1", ADMIN, body, 20), now_minutes=200).status == "pending"


def test_comments_posted_while_the_analysis_ran_still_count():
    authorizer, _ = make_authorizer()
    mid_run = comment(
        "c1", ADMIN, "One more thing", 12
    )  # after the snapshot (minute 8), before the analysis (10 + run)
    posted = comment("a", BOT, f"Spec\n{analysis_marker(1, analysis_hash(TITLE, BODY, 'Spec'), 'm', at(8))}", 15)

    decision = evaluate_approval(issue(posted, mid_run), authorizer, at(60), 5.0)

    assert decision.status == "revise" and decision.comments == [mid_run]


def test_seen_marker_round_trips():
    parsed = parse_analysis(comment("a", BOT, analysis_marker(2, "h", "m", at(8)), 15))

    assert parsed.rev == 2 and parsed.seen_at == at(8) and parsed.since == at(8)


def test_mentions_helper():
    assert mentions("hey @imap-agent!", BOT) and mentions("@Imap-Agent[bot]", BOT)
    assert not mentions("a@imap-agent.io", BOT) and not mentions("@imap-agents", BOT) and not mentions("x", None)
