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

    action = only(state.decide(item, ctx), state.RUN_STAGE)

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

    action = only(state.decide(item, ctx), state.WAIT)

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


def ai_review(minutes):
    return review(BOT, "COMMENTED", minutes, f"findings\n{state.run_marker('review', SONNET)}")


def test_ai_review_round_limit_escalates():
    ctx, _ = context()
    reviews = [ai_review(minute) for minute in (10, 20, 30)]
    pr = make_item(
        is_pr=True, labels=(state.AI_REVIEW,), comments=[run_comment("implementation", SOL, 5)], reviews=reviews
    )

    action = only(state.decide(pr, ctx))

    assert action.kind == state.SET_LABELS
    assert action.add_labels == (state.BLOCKED,)


def test_administrator_change_request_starts_a_new_ai_review_budget():
    ctx, _ = context()
    reviews = [ai_review(10), ai_review(20), ai_review(30), review(ADMIN, "CHANGES_REQUESTED", 40), ai_review(50)]
    pr = make_item(
        is_pr=True, labels=(state.AI_REVIEW,), comments=[run_comment("implementation", SOL, 5)], reviews=reviews
    )

    action = only(state.decide(pr, ctx))

    assert (action.kind, action.stage, action.model) == (state.RUN_STAGE, "review", SONNET)
    assert action.reason == "AI review round 2"
    assert state.run_markers(pr, ctx.authorizer)[-1] == ("review", SONNET)  # markers in bot reviews count


def test_review_and_feedback_actions_carry_the_linked_issue():
    ctx, _ = context()
    issue = make_item(number=77, labels=(state.IMPLEMENTING,))
    pr = replace(make_item(number=88, is_pr=True, labels=(state.CHANGES_REQUESTED,)), head_ref="agent/issue-77-x")

    actions = state.plan([issue, pr], ctx)

    feedback = next(action for action in actions if action.item.number == 88)
    assert (feedback.stage, feedback.related) == ("feedback", issue)


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


def test_needs_info_requests_count_toward_the_reanalysis_limit():
    ctx, _ = context()
    asked = [comment(f"q{n}", BOT, f"questions\n{state.run_marker('analysis', OPUS)}", 10 * n) for n in (1, 2, 3)]
    reply = comment("r", "reporter", "answers", 40)

    actions = state.decide(make_item(labels=(state.NEEDS_INFO,), comments=[*asked, reply]), ctx)

    assert only(actions).kind == state.SKIP and "limit" in only(actions).reason


def test_reply_must_follow_the_latest_needs_info_request():
    ctx, _ = context()
    early_reply = comment("r", "reporter", "answers", 5)
    asked = comment("q", BOT, f"questions\n{state.run_marker('analysis', OPUS)}", 10)

    actions = state.decide(make_item(labels=(state.NEEDS_INFO,), comments=[early_reply, asked]), ctx)

    assert only(actions).reason == "waiting for the reporter's reply"


def test_quota_waits_are_flagged_for_the_waiting_label():
    def claude_exhausted(engine, long_stage):
        return (engine != "claude", "claude exhausted")

    ctx, _ = context(usable=claude_exhausted)

    action = only(state.decide(make_item(), ctx))

    assert action.kind == state.WAIT and action.quota_wait


def awaiting(*admin_comments, rev=1):
    return make_item(
        labels=(state.AWAITING_APPROVAL,),
        comments=[analysis_comment(TITLE, BODY, rev=rev), *admin_comments],
    )


def test_plain_admin_comment_is_acknowledged_then_revised_after_the_wait():
    ctx, _ = context()
    chat = comment("c1", ADMIN, "Please also check Windows", 20)
    early = replace(ctx, now=at(22))
    late = replace(ctx, now=at(26))

    soon = state.decide(awaiting(chat), early)
    later = state.decide(awaiting(chat), late)

    assert [a.kind for a in soon] == [state.REACT, state.SKIP] and soon[0].comment_ids == ("c1",)
    assert "batching" in soon[1].reason
    revise = only(later, state.RUN_STAGE)
    assert (revise.stage, revise.model) == ("analysis", OPUS)
    assert revise.notes == "Please also check Windows" and revise.add_labels == (state.ANALYZING,)
    assert only(later, state.REACT).priority == 0


def test_revision_limit_escalates_to_blocked():
    ctx, _ = context()
    config = replace(ctx.config, policy=replace(ctx.config.policy, max_revisions_per_issue=2))
    ctx = replace(ctx, config=config, now=at(200))

    actions = state.decide(awaiting(comment("c1", ADMIN, "more changes", 20), rev=3), ctx)

    assert [a.kind for a in actions] == [state.REACT, state.SET_LABELS]
    assert actions[1].add_labels == (state.BLOCKED,) and "2 revisions" in actions[1].reason


def test_approval_is_acknowledged_and_starts_implementation():
    ctx, _ = context()

    actions = state.decide(awaiting(comment("c1", ADMIN, "/approve", 20)), ctx)

    assert [a.kind for a in actions] == [state.REACT, state.RUN_STAGE]
    assert actions[1].stage == "implementation"


# --- Phase 3: implementation tracking, CI checking, and concurrency ------------------------------------------------


def impl_pr(number=88, issue=77, labels=(state.IMPLEMENTING,)):
    pr = make_item(number=number, is_pr=True, labels=labels)
    return replace(pr, head_ref=f"agent/issue-{issue}-add-feature", head_sha="abc")


def approved_issue_item(number, labels=(state.AWAITING_APPROVAL,)):
    return make_item(
        number=number,
        labels=labels,
        comments=[analysis_comment(TITLE, BODY), comment(f"ok{number}", ADMIN, "/approve", 20)],
    )


def test_implementing_pull_request_is_routed_to_the_ci_check_with_its_issue():
    ctx, _ = context()
    issue = make_item(number=77, labels=(state.IMPLEMENTING,))

    actions = state.plan([issue, impl_pr()], ctx)

    check = only(actions, state.CHECK_CI)
    assert check.item.number == 88 and check.related.number == 77 and check.priority == state.PRIORITY["ci_fix"]
    assert only([a for a in actions if a.item.number == 77]).reason == "implementation is tracked by PR #88"


def test_issue_without_a_pull_request_continues_its_implementation():
    ctx, _ = context()

    actions = state.plan([make_item(number=77, labels=(state.IMPLEMENTING,))], ctx)

    action = only(actions, state.RUN_STAGE)
    assert (action.stage, action.model) == ("implementation", SOL)


def test_only_one_implementation_runs_at_a_time():
    ctx, _ = context()
    busy = make_item(number=70, labels=(state.IMPLEMENTING,))
    second = approved_issue_item(71)

    waiting = state.plan([busy, second], ctx)
    after_review = state.plan(
        [make_item(number=70, labels=(state.IMPLEMENTING,)), impl_pr(88, 70, (state.AI_REVIEW,)), second], ctx
    )

    skipped = [a for a in waiting if a.item.number == 71 and a.kind == state.SKIP]
    assert skipped and "waiting for the implementation of #70" in skipped[0].reason
    assert not [a for a in waiting if a.kind == state.RUN_STAGE and a.item.number == 71]
    started = [a for a in after_review if a.item.number == 71 and a.kind == state.RUN_STAGE]
    assert started and started[0].stage == "implementation"


def test_a_pull_request_still_in_ci_keeps_the_implementation_slot_busy():
    ctx, _ = context()
    items = [make_item(number=70, labels=(state.IMPLEMENTING,)), impl_pr(88, 70), approved_issue_item(71)]

    actions = state.plan(items, ctx)

    assert not [a for a in actions if a.item.number == 71 and a.kind == state.RUN_STAGE]


def test_a_blocked_implementation_does_not_hold_the_slot():
    ctx, _ = context()
    blocked_issue = make_item(number=70, labels=(state.IMPLEMENTING, state.BLOCKED))
    blocked_pr_issue = make_item(number=72, labels=(state.IMPLEMENTING,))
    blocked_pr = impl_pr(88, 72, (state.IMPLEMENTING, state.BLOCKED))

    for items in ([blocked_issue, approved_issue_item(71)], [blocked_pr_issue, blocked_pr, approved_issue_item(71)]):
        actions = state.plan(items, ctx)

        started = [a for a in actions if a.item.number == 71 and a.kind == state.RUN_STAGE]
        assert started and started[0].stage == "implementation"


def test_a_higher_limit_allows_parallel_implementations():
    ctx, _ = context()
    config = replace(ctx.config, policy=replace(ctx.config.policy, max_concurrent_implementations=2))
    ctx = replace(ctx, config=config)

    actions = state.plan([make_item(number=70, labels=(state.IMPLEMENTING,)), approved_issue_item(71)], ctx)

    assert [a for a in actions if a.item.number == 71 and a.kind == state.RUN_STAGE]
