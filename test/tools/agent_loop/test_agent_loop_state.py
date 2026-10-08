"""Tests for the label state machine, quota-aware model selection, and reviewer separation."""

from dataclasses import replace
from datetime import timezone

from agent_loop_fakes import (
    ADMIN,
    BOT,
    T0,
    analysis_comment,
    at,
    comment,
    label_event,
    make_authorizer,
    make_item,
    review,
)

from agent_loop import state
from agent_loop.config import ModelRef, load_config
from agent_loop.selection import select_author

TITLE, BODY = "Add feature", "Please add it"
OPUS = ModelRef("claude", "claude-opus-5-5", "medium")
SOL = ModelRef("codex", "gpt-6.1-sol", "medium")
SONNET = ModelRef("claude", "claude-sonnet-5-5", "medium")


def always_usable(engine, long_stage):
    return True, ""


def context(usable=always_usable, config=None, **kwargs):
    authorizer, runner = make_authorizer(**kwargs)
    config = config or load_config(environ={})
    return state.Context(config, authorizer, usable, T0.astimezone(timezone.utc)), runner


def only(actions, kind=None):
    selected = [action for action in actions if kind is None or action.kind == kind]
    assert len(selected) == 1, [action.describe() for action in actions]
    return selected[0]


def run_comment(stage, model, minutes, cid=None):
    return comment(cid or f"run-{stage}-{minutes}", BOT, f"done\n{state.run_marker(stage, model)}", minutes)


def test_new_issue_starts_analysis_with_configured_model():
    ctx, _ = context()

    action = only(state.decide(make_item(), ctx))

    assert (action.kind, action.stage, action.model) == (state.RUN_STAGE, "analysis", OPUS)
    assert action.add_labels == (state.ANALYZING,)


def test_issue_before_enabled_since_requires_admin_adopt():
    config = load_config(environ={})
    config = replace(config, github=replace(config.github, enabled_since=at(60)))
    ctx, _ = context(config=config)

    skipped = only(state.decide(make_item(created=0), ctx))
    adopted = only(state.decide(make_item(labels=(state.ADOPT,), events=[label_event(state.ADOPT, ADMIN, 70)]), ctx))
    forged = state.decide(make_item(labels=(state.ADOPT,), events=[label_event(state.ADOPT, "maintainer", 70)]), ctx)

    assert skipped.kind == state.SKIP
    assert adopted.stage == "analysis"
    assert [action.kind for action in forged] == [state.REVERT_LABEL, state.SKIP]


def test_untrusted_state_label_is_reverted_and_ignored():
    ctx, _ = context()
    item = make_item(labels=(state.AI_REVIEW,), events=[label_event(state.AI_REVIEW, "maintainer", 5)])

    actions = state.decide(item, ctx)

    assert actions[0].kind == state.REVERT_LABEL
    assert actions[1].stage == "analysis"  # treated as a new issue once the forged label is discounted


def test_admin_pause_stops_work_and_non_admin_unpause_is_reverted():
    ctx, _ = context()
    paused = make_item(labels=(state.PAUSED, state.ANALYZING), events=[label_event(state.PAUSED, ADMIN, 2)])
    unpaused = make_item(
        labels=(state.ANALYZING,),
        events=[label_event(state.PAUSED, ADMIN, 2), label_event(state.PAUSED, "maintainer", 3, added=False)],
    )

    assert only(state.decide(paused, ctx)).kind == state.SKIP
    actions = state.decide(unpaused, ctx)
    assert [action.kind for action in actions] == [state.REVERT_LABEL, state.SKIP]


def test_admin_approval_starts_implementation_with_codex():
    ctx, _ = context()
    item = make_item(
        labels=(state.AWAITING_APPROVAL,),
        comments=[analysis_comment(TITLE, BODY), comment("c1", ADMIN, "/approve", 20)],
    )

    action = only(state.decide(item, ctx))

    assert (action.stage, action.model) == ("implementation", SOL)
    assert action.add_labels == (state.IMPLEMENTING,) and action.remove_labels == (state.AWAITING_APPROVAL,)


def test_unauthorized_command_gets_one_reply():
    ctx, _ = context()
    command = comment("c1", "maintainer", "/approve", 20)
    item = make_item(labels=(state.AWAITING_APPROVAL,), comments=[analysis_comment(TITLE, BODY), command])
    replied = make_item(
        labels=(state.AWAITING_APPROVAL,),
        comments=[analysis_comment(TITLE, BODY), command, comment("r", BOT, state.unauthorized_marker("c1"), 21)],
    )

    assert [action.kind for action in state.decide(item, ctx)] == [state.REPLY_UNAUTHORIZED, state.SKIP]
    assert [action.kind for action in state.decide(replied, ctx)] == [state.SKIP]


def test_quota_exhaustion_waits_instead_of_switching_models():
    def codex_exhausted(engine, long_stage):
        return (engine != "codex", "codex exhausted until later")

    ctx, _ = context(usable=codex_exhausted)
    item = make_item(
        labels=(state.AWAITING_APPROVAL,),
        comments=[analysis_comment(TITLE, BODY), comment("c1", ADMIN, "/approve", 20)],
    )

    action = only(state.decide(item, ctx))

    assert action.kind == state.WAIT
    assert "codex exhausted" in action.reason


def test_reviewer_is_distinct_from_pr_authors():
    ctx, _ = context()
    pr = make_item(is_pr=True, labels=(state.AI_REVIEW,), comments=[run_comment("implementation", SOL, 5)])

    action = only(state.decide(pr, ctx))

    assert (action.stage, action.model) == ("review", SONNET)


def test_review_waits_when_every_reviewer_collides_with_an_author():
    ctx, _ = context()
    pr = make_item(
        is_pr=True,
        labels=(state.AI_REVIEW,),
        comments=[run_comment("implementation", SOL, 5), run_comment("feedback", OPUS, 6)],
    )

    action = only(state.decide(pr, ctx))

    assert action.kind == state.WAIT
    assert "distinct" in action.reason


def test_author_fallback_that_would_leave_no_reviewer_is_skipped(tmp_path):
    path = tmp_path / "loop.toml"
    path.write_text(
        "[stages.implementation]\non_exhausted = 'fallback'\nfallbacks = ['claude:claude-opus-5-5:medium']\n"
    )
    config = load_config(path, environ={})

    def codex_exhausted(engine, long_stage):
        return (engine != "codex", "codex exhausted")

    selection = select_author(config, "implementation", codex_exhausted)

    assert selection.waiting
    assert "would leave no valid reviewer" in selection.reason


def test_ai_review_round_limit_escalates():
    ctx, _ = context()
    reviews = [run_comment("review", SONNET, minute) for minute in (10, 20, 30)]
    pr = make_item(is_pr=True, labels=(state.AI_REVIEW,), comments=[run_comment("implementation", SOL, 5), *reviews])

    action = only(state.decide(pr, ctx))

    assert action.kind == state.SET_LABELS
    assert action.add_labels == (state.BLOCKED,)


def test_admin_change_request_on_ready_pr_has_top_priority():
    ctx, _ = context()
    ready = make_item(
        number=7,
        is_pr=True,
        labels=(state.READY_FOR_ADMIN,),
        events=[label_event(state.READY_FOR_ADMIN, BOT, 10)],
        comments=[run_comment("implementation", SOL, 5)],
        reviews=[review("maintainer", "CHANGES_REQUESTED", 15), review(ADMIN, "CHANGES_REQUESTED", 20)],
    )
    outsider_only = replace(ready, number=8, reviews=(review("maintainer", "CHANGES_REQUESTED", 15),))
    new_issue = make_item(number=1)

    actions = state.plan([new_issue, outsider_only, ready], ctx)

    assert [(action.item.number, action.kind) for action in actions] == [
        (7, state.RUN_STAGE),
        (1, state.RUN_STAGE),
        (8, state.SKIP),
    ]
    assert actions[0].stage == "feedback" and actions[0].priority == state.PRIORITY["admin_changes"]


def test_reanalysis_is_capped_without_admin_involvement():
    ctx, _ = context()
    analyses = [analysis_comment(TITLE, BODY, minutes=10 * n, rev=n, cid=f"a{n}") for n in (1, 2, 3)]
    reply = comment("r", "reporter", "more details", 40)

    capped = state.decide(make_item(labels=(state.NEEDS_INFO,), comments=[*analyses, reply]), ctx)
    allowed = state.decide(make_item(labels=(state.NEEDS_INFO,), comments=[analyses[0], reply]), ctx)

    assert only(capped).kind == state.SKIP and "limit" in only(capped).reason
    assert only(allowed).stage == "analysis"


def test_unmanaged_pr_truncated_item_and_global_pause():
    ctx, _ = context()
    paused_config = replace(load_config(environ={}), paused=True)
    paused_ctx, _ = context(config=paused_config)

    assert state.decide(make_item(is_pr=True), ctx) == []
    assert only(state.decide(make_item(truncated=True), ctx)).kind == state.SKIP
    assert state.plan([make_item()], paused_ctx) == []
