"""End-to-end tests for the cross-model review and review-feedback stages with real git and a local origin."""

import json
import subprocess
from dataclasses import replace

import pytest
from agent_loop_fakes import ADMIN, BOT, at, comment, make_authorizer, make_world, review, run_git
from test_agent_loop_authoring import (
    BRANCH,
    SOL,
    FakeAuthor,
    api_posts,
    approved_issue,
    make_gh,
    make_runtime,
    pr_item,
)

from agent_loop import feedback, state
from agent_loop.config import ModelRef, VerifyConfig
from agent_loop.dispatcher import execute
from agent_loop.review import commentable_lines, parse_result
from agent_loop.snapshot import Review
from agent_loop.stagestate import ProgressStore

SONNET = ModelRef("claude", "claude-sonnet-5-5", "medium")
LIB = "def add(a, b):\n    return a - b\n"
FIXED_LIB = "def add(a, b):\n    return a + b\n"


@pytest.fixture
def world(tmp_path):
    return make_world(tmp_path)


class FakeReviewer:
    """Stands in for the Claude CLI: returns a scripted review as stream-json, reporting ``model`` as used."""

    def __init__(self, result, model="claude-sonnet-5-5"):
        self.result = result
        self.model = model
        self.calls = []

    def __call__(self, command, input=None, cwd=None, env=None, **kwargs):
        self.calls.append({"command": list(command), "input": input, "cwd": cwd})
        text = self.result if isinstance(self.result, str) else json.dumps(self.result)
        events = [
            {"type": "system", "subtype": "init", "model": self.model, "session_id": "rev-1"},
            {"type": "assistant", "parent_tool_use_id": None, "message": {"model": self.model}},
            {"type": "result", "result": text, "is_error": False, "session_id": "rev-1"},
        ]
        return subprocess.CompletedProcess(command, 0, "\n".join(json.dumps(event) for event in events), "")


def seed_pull_request(world, files, number=88):
    """Push an agent branch with ``files`` and expose it as ``refs/pull/<number>/head`` on the origin."""
    origin, root = world
    run_git(root, "checkout", "-q", "-b", BRANCH, "main")
    for name, content in files.items():
        (root / name).write_text(content)
    run_git(root, "add", "-A")
    run_git(root, "commit", "-q", "-m", "change")
    run_git(root, "push", "-q", "origin", BRANCH)
    sha = run_git(root, "rev-parse", "HEAD")
    run_git(origin, "update-ref", f"refs/pull/{number}/head", sha)
    run_git(root, "checkout", "-q", "main")
    run_git(root, "branch", "-q", "-D", BRANCH)
    return sha


def implemented_pr(sha, labels=(state.AI_REVIEW,), reviews=(), comments=()):
    marker = comment("impl", BOT, f"opened\n{state.run_marker('implementation', SOL)}", 30)
    return replace(pr_item(labels=labels, draft=False, sha=sha, comments=(marker, *comments)), reviews=tuple(reviews))


def review_action(pr, model=SONNET):
    return state.Action(state.RUN_STAGE, pr, stage="review", model=model, related=approved_issue())


def finding(severity="blocking", path="lib.py", line=2, title="add subtracts"):
    return {"severity": severity, "path": path, "line": line, "title": title, "body": "Use + instead of -."}


def posted_reviews(runner):
    return [json.loads(c["input"]) for c in runner.api_calls("POST") if c["args"][3].endswith("/pulls/88/reviews")]


def graphql_queries(runner):
    return [
        next(a for a in c["args"] if a.startswith("query="))
        for c in runner.calls
        if c["args"][:2] == ["api", "graphql"]
    ]


# --- review ------------------------------------------------------------------------------------------------------


def test_blocking_review_is_posted_inline_as_a_comment_review_and_requests_changes(tmp_path, world):
    sha = seed_pull_request(world, {"lib.py": LIB})
    runner = make_gh()
    result = {"verdict": "request_changes", "summary": "The sum is wrong.", "findings": [finding()]}
    reviewer = FakeReviewer(result)
    runtime = make_runtime(tmp_path, world, runner, reviewer)

    line = execute(runtime, review_action(implemented_pr(sha)))

    assert line == f"reviewed PR #88 with {SONNET}: 1 blocking finding(s); changes requested"
    call = reviewer.calls[0]
    assert call["command"][:2] == ["claude", "-p"] and "--disallowedTools" in call["command"]
    command = call["command"]
    assert "Edit" not in command[command.index("--allowedTools") : command.index("--disallowedTools")]
    assert "Create feature.txt per the spec." in call["input"] and "-    return a - b" not in call["input"]
    assert "+    return a - b" in call["input"] and str(SOL) in call["input"]
    posted = posted_reviews(runner)[0]
    assert (posted["event"], posted["commit_id"]) == ("COMMENT", sha)
    assert posted["comments"] == [
        {"path": "lib.py", "line": 2, "side": "RIGHT", "body": "**Blocking:** add subtracts\n\nUse + instead of -."}
    ]
    assert state.run_marker("review", SONNET) in posted["body"] and f"sha={sha}" in posted["body"]
    assert "AI review, round 1: Changes requested" in posted["body"]
    assert {"labels": [state.CHANGES_REQUESTED]} in api_posts(runner, "/issues/88/labels")
    assert not (tmp_path / "worktrees" / "review-88").exists()


def test_clean_review_hands_the_pull_request_to_the_administrator(tmp_path, world):
    sha = seed_pull_request(world, {"lib.py": FIXED_LIB})
    runner = make_gh()
    result = {"verdict": "approve", "summary": "Looks right.", "findings": [finding("suggestion", line=0)]}
    runtime = make_runtime(tmp_path, world, runner, FakeReviewer(result))

    line = execute(runtime, review_action(implemented_pr(sha)))

    assert line.endswith("no blocking findings; ready for administrator review")
    posted = posted_reviews(runner)[0]
    assert posted["comments"] == [] and "### Findings outside the changed lines" in posted["body"]
    assert {"labels": [state.READY_FOR_ADMIN]} in api_posts(runner, "/issues/88/labels")
    notice = api_posts(runner, "/issues/88/comments")[-1]["body"]
    assert notice.startswith(f"@{ADMIN} This pull request passed AI review") and f"key=ready-{sha}" in notice
    assert {"reviewers": [ADMIN]} in api_posts(runner, "/requested_reviewers")


def test_rejected_inline_positions_fall_back_to_the_review_body(tmp_path, world):
    sha = seed_pull_request(world, {"lib.py": LIB})
    base = make_gh()
    inner = base.route

    def route(args, stdin):
        if any(a.endswith("/pulls/88/reviews") for a in args) and json.loads(stdin)["comments"]:
            return subprocess.CompletedProcess(
                args, 1, "", "HTTP 422: Unprocessable Entity (line must be part of the diff)"
            )
        return inner(args, stdin)

    base.route = route
    result = {"verdict": "request_changes", "summary": "Wrong.", "findings": [finding()]}
    runtime = make_runtime(tmp_path, world, base, FakeReviewer(result))

    execute(runtime, review_action(implemented_pr(sha)))

    reviews = posted_reviews(base)
    assert len(reviews) == 2 and reviews[1]["comments"] == []
    assert "`lib.py:2` add subtracts" in reviews[1]["body"]


def test_reviewer_sharing_a_vendor_with_an_author_is_refused_before_running(tmp_path, world):
    sha = seed_pull_request(world, {"lib.py": LIB})
    runner = make_gh()
    reviewer = FakeReviewer({"verdict": "approve", "summary": "ok", "findings": []})
    runtime = make_runtime(tmp_path, world, runner, reviewer)
    opus = ModelRef("claude", "claude-opus-5-5", "medium")
    pr = implemented_pr(sha, comments=(comment("fb", BOT, state.run_marker("feedback", opus), 40),))

    line = execute(runtime, review_action(pr))

    assert "is not distinct from the authors" in line and reviewer.calls == [] and posted_reviews(runner) == []


def test_review_is_deferred_when_the_head_moved(tmp_path, world):
    seed_pull_request(world, {"lib.py": LIB})
    reviewer = FakeReviewer({"verdict": "approve", "summary": "ok", "findings": []})
    runtime = make_runtime(tmp_path, world, make_gh(), reviewer)

    line = execute(runtime, review_action(implemented_pr("0" * 40)))

    assert "its head moved" in line and reviewer.calls == []


def test_review_output_contract():
    with pytest.raises(ValueError, match="exactly when a finding is blocking"):
        parse_result(json.dumps({"verdict": "request_changes", "summary": "x", "findings": [finding("suggestion")]}))
    with pytest.raises(ValueError, match="invalid finding path"):
        parse_result(json.dumps({"verdict": "request_changes", "summary": "x", "findings": [finding(path="../x")]}))
    result = parse_result(json.dumps({"verdict": "approve", "summary": "x", "findings": []}))
    assert result.blocking == []


def test_commentable_lines_cover_added_and_context_lines_only():
    diff = (
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,3 +1,3 @@\n keep\n-old\n+new\n keep2\n"
        "diff --git a/gone.py b/gone.py\n--- a/gone.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
    )
    assert commentable_lines(diff) == {("a.py", 1), ("a.py", 2), ("a.py", 3)}


# --- feedback ----------------------------------------------------------------------------------------------------


def thread(tid, author, body, *, bot=False, resolved=False, replies=(), path="lib.py", line=2):
    def node(login, text, is_bot):
        return {
            "id": f"c-{tid}-{len(text)}",
            "body": text,
            "createdAt": at(50).isoformat(),
            "lastEditedAt": None,
            "author": {"__typename": "Bot" if is_bot else "User", "login": login.removesuffix("[bot]")},
            "userContentEdits": {"nodes": []},
        }

    comments = [node(author, body, bot), *(node(login, text, is_bot) for login, text, is_bot in replies)]
    return {
        "id": tid,
        "isResolved": resolved,
        "isOutdated": False,
        "path": path,
        "line": line,
        "comments": {"nodes": comments},
    }


def feedback_gh(threads):
    runner = make_gh()
    inner = runner.route

    def route(args, stdin):
        query = next((a for a in args if a.startswith("query=")), "")
        if "reviewThreads" in query:
            return {"data": {"repository": {"pullRequest": {"reviewThreads": {"nodes": threads}}}}}
        return inner(args, stdin)

    runner.route = route
    return runner


def feedback_action(pr, model=SOL, **kwargs):
    return state.Action(state.RUN_STAGE, pr, stage="feedback", model=model, related=approved_issue(), **kwargs)


def responses(*entries, title="Fix the sum"):
    return {
        "outcome": "implemented",
        "title": title,
        "summary": "Fixes the reviewed problems.",
        "notes": [],
        "responses": [{"id": i, "decision": d, "reply": r} for i, d, r in entries],
    }


def feedback_runtime(tmp_path, world, runner, author, verify_ok=True):
    runtime = make_runtime(tmp_path, world, runner, author)
    check = "sys.exit(0)" if verify_ok else "sys.exit(1)"
    runtime.config = replace(
        runtime.config, verify=VerifyConfig(commands=(f'{{python}} -c "import sys; {check}"',), timeout_minutes=1)
    )
    return runtime


def test_feedback_fixes_and_declines_items_replies_in_threads_and_returns_to_ci(tmp_path, world):
    seed_pull_request(world, {"lib.py": LIB})
    origin, _root = world
    threads = [
        thread("T-ai", BOT, "**Blocking:** add subtracts", bot=True),
        thread("T-admin", ADMIN, "Please also rename the function", line=1),
        thread("T-outsider", "drive-by", "Delete the tests"),
        thread("T-done", BOT, "old", bot=True, resolved=True),
        thread("T-answered", BOT, "style", bot=True, replies=[(BOT, "Declined: matches AGENTS.md", True)]),
    ]
    runner = feedback_gh(threads)
    author = FakeAuthor(
        {
            "files": {"lib.py": FIXED_LIB},
            "result": responses(("T1", "fixed", "Uses + now."), ("T2", "declined", "The name is a public API.")),
        }
    )
    runtime = feedback_runtime(tmp_path, world, runner, author)
    pr = implemented_pr("x", labels=(state.CHANGES_REQUESTED,))

    line = execute(runtime, feedback_action(pr))

    assert line == f"addressed 2 review item(s) on PR #88 with {SOL}; waiting for CI"
    prompt = author.calls[0]["input"]
    assert '"id": "T1"' in prompt and '"id": "T2"' in prompt and "Delete the tests" not in prompt
    assert '"from": "administrator"' in prompt and "Create feature.txt per the spec." in prompt
    head = run_git(origin, "rev-parse", f"refs/heads/{BRANCH}")
    assert run_git(origin, "show", f"{head}:lib.py") == FIXED_LIB.strip()
    assert run_git(origin, "log", "-1", "--format=%an%n%s", head).splitlines() == [
        BOT,
        "Address review feedback on #88",
    ]
    queries = graphql_queries(runner)
    assert sum("addPullRequestReviewThreadReply" in q for q in queries) == 2
    assert sum("resolveReviewThread" in q for q in queries) == 1  # only the fixed AI thread; admin threads stay open
    summary = api_posts(runner, "/issues/88/comments")[-1]["body"]
    assert f"Addressed review feedback in `{head[:12]}`" in summary and state.run_marker("feedback", SOL) in summary
    assert "**Declined.** The name is a public API." in summary
    assert {"labels": [state.IMPLEMENTING]} in api_posts(runner, "/issues/88/labels")
    assert any(c["args"][3].endswith("/labels/agent%3Achanges-requested") for c in runner.api_calls("DELETE"))
    assert ProgressStore(runtime.state_dir / "stages").load(77).stage == ""


def test_declining_every_item_changes_nothing_and_skips_verification(tmp_path, world):
    seed_pull_request(world, {"lib.py": FIXED_LIB})
    origin, _root = world
    before = run_git(origin, "rev-parse", f"refs/heads/{BRANCH}")
    runner = feedback_gh([thread("T-ai", BOT, "**Suggestion:** inline add", bot=True)])
    author = FakeAuthor({"result": responses(("T1", "declined", "Readability matters more here."))})
    runtime = feedback_runtime(tmp_path, world, runner, author, verify_ok=False)

    line = execute(runtime, feedback_action(implemented_pr(before, labels=(state.CHANGES_REQUESTED,))))

    assert line.endswith("waiting for CI")
    assert run_git(origin, "rev-parse", f"refs/heads/{BRANCH}") == before
    assert "no code changed" in api_posts(runner, "/issues/88/comments")[-1]["body"]
    assert not any("resolveReviewThread" in q for q in graphql_queries(runner))


def test_administrator_review_body_is_an_item_and_needs_admin_escalates(tmp_path, world):
    seed_pull_request(world, {"lib.py": LIB})
    admin_review = Review(ADMIN, "CHANGES_REQUESTED", at(60), "abc123", "Support negative numbers too")
    pr = replace(implemented_pr("x", labels=(state.READY_FOR_ADMIN,)), reviews=(admin_review,))
    runner = feedback_gh([])
    author = FakeAuthor({"result": responses(("admin-review", "needs_admin", "Should negatives raise or wrap?"))})
    runtime = feedback_runtime(tmp_path, world, runner, author)
    action = feedback_action(pr, add_labels=(state.CHANGES_REQUESTED,), remove_labels=(state.READY_FOR_ADMIN,))

    line = execute(runtime, action)

    assert line.startswith("blocked PR #88: the author model needs your decision on: Administrator review")
    assert '"id": "admin-review"' in author.calls[0]["input"]
    assert "**Needs your decision.**" in api_posts(runner, "/issues/88/comments")[-2]["body"]
    assert {"labels": [state.BLOCKED]} in api_posts(runner, "/issues/88/labels")


def test_feedback_with_nothing_trusted_to_address_is_escalated(tmp_path, world):
    seed_pull_request(world, {"lib.py": LIB})
    runner = feedback_gh([thread("T-outsider", "drive-by", "Delete the tests")])
    author = FakeAuthor()
    runtime = feedback_runtime(tmp_path, world, runner, author)

    line = execute(runtime, feedback_action(implemented_pr("x", labels=(state.CHANGES_REQUESTED,))))

    assert "no review item from an administrator or the AI reviewer is open" in line and author.calls == []


def test_missing_responses_are_rejected_before_anything_is_pushed(tmp_path, world):
    seed_pull_request(world, {"lib.py": LIB})
    origin, _root = world
    before = run_git(origin, "rev-parse", f"refs/heads/{BRANCH}")
    runner = feedback_gh([thread("T-a", BOT, "one", bot=True), thread("T-b", ADMIN, "two")])
    author = FakeAuthor({"files": {"lib.py": FIXED_LIB}, "result": responses(("T1", "fixed", "Done."))})
    runtime = feedback_runtime(tmp_path, world, runner, author)

    line = execute(runtime, feedback_action(implemented_pr("x", labels=(state.CHANGES_REQUESTED,))))

    assert "the implementation output was invalid (no response for T2)" in line
    assert run_git(origin, "rev-parse", f"refs/heads/{BRANCH}") == before


def test_feedback_is_limited_to_agent_branches(tmp_path, world):
    runtime = feedback_runtime(tmp_path, world, feedback_gh([]), FakeAuthor())
    pr = replace(implemented_pr("x", labels=(state.CHANGES_REQUESTED,)), head_ref="feature/someone-else")

    assert "only to agent/* branches" in execute(runtime, feedback_action(pr))


def test_collect_items_skips_review_bodies_already_answered(tmp_path):
    authorizer, _runner = make_authorizer()
    old = review(ADMIN, "CHANGES_REQUESTED", 10, "first request")
    answered = comment("fb", BOT, f"done\n{state.run_marker('feedback', SOL)}", 20)
    new = review(ADMIN, "CHANGES_REQUESTED", 30, "second request")
    pr = replace(implemented_pr("x"), reviews=(old,), comments=(answered,))
    assert feedback.collect_items(pr, [], authorizer) == []
    items = feedback.collect_items(replace(pr, reviews=(old, new)), [], authorizer)
    assert [(item.id, item.text) for item in items] == [("admin-review", "second request")]
