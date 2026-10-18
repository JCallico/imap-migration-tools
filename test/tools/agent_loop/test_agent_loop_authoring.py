"""End-to-end tests for the implementation and CI-repair stages with real git, verification, and a local origin."""

import json
import logging
import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from agent_loop_fakes import (
    ADMIN,
    BOT,
    REPO,
    FakeGhRunner,
    analysis_comment,
    comment,
    make_item,
    make_world,
    permission_route,
    run_git,
)

from agent_loop import state
from agent_loop.config import ModelRef, VerifyConfig, load_config
from agent_loop.dispatcher import Runtime, cleanup_worktrees, execute
from agent_loop.gh import Gh
from agent_loop.quota import SUCCESS, Classification, QuotaLedger
from agent_loop.snapshot import Item
from agent_loop.stagestate import PR_OPEN, ProgressStore

SOL = ModelRef("codex", "gpt-6.1-sol", "medium")
TITLE, BODY = "Add feature", "Please add it. ISSUE_BODY_MARKER"
BRANCH = "agent/issue-77-add-feature"
GOOD = {
    "outcome": "implemented",
    "title": "Add feature file",
    "summary": "Adds the feature.",
    "notes": ["Used the default"],
}
# Passes only when feature.txt exists, so the scripted model must create it.
VERIFY = VerifyConfig(
    commands=("{python} -c \"import pathlib, sys; sys.exit(0 if pathlib.Path('feature.txt').exists() else 1)\"",),
    timeout_minutes=1,
)


class FakeAuthor:
    """Stands in for the Codex CLI: each call applies a scripted edit to the worktree and returns its final message."""

    def __init__(self, *steps):
        self.steps = list(steps)
        self.calls = []

    def __call__(self, command, input=None, cwd=None, env=None, **kwargs):
        step = self.steps.pop(0)
        self.calls.append({"command": list(command), "input": input, "cwd": Path(cwd), "env": dict(env or {})})
        for name, content in step.get("files", {}).items():
            target = Path(cwd) / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        events = [{"type": "thread.started", "thread_id": step.get("session", "sess-1")}]
        if "result" in step:
            text = step["result"] if isinstance(step["result"], str) else json.dumps(step["result"])
            events.append({"type": "item.completed", "item": {"id": "i", "type": "agent_message", "text": text}})
        stdout = "\n".join(json.dumps(event) for event in events)
        return subprocess.CompletedProcess(command, step.get("code", 0), stdout, step.get("stderr", ""))


@pytest.fixture
def world(tmp_path):
    return make_world(tmp_path)


def make_gh(ci_runs=None, rules=None, logs="FAILED test_x: assert 1 == 2", pull_state="open"):
    def extra(args, stdin):
        path = next((arg for arg in args if arg.startswith(("repos/", "users/"))), "")
        if path.startswith("users/"):
            return {"id": 342463850}
        if path.endswith("/pulls") and "POST" in args:
            return {"number": 88, "node_id": "PR_node"}
        if path.endswith("/pulls"):
            return []
        if "/pulls/" in path:
            return {"state": pull_state, "merged_at": None}
        if path.endswith("/rules/branches/main"):
            return (
                rules
                if rules is not None
                else [
                    {
                        "type": "required_status_checks",
                        "parameters": {"required_status_checks": [{"context": "Lint"}, {"context": "Test"}]},
                    }
                ]
            )
        if path.endswith("/check-runs"):
            return {"check_runs": ci_runs or []}
        if path.endswith("/status"):
            return {"statuses": []}
        if "/actions/jobs/" in path:
            return logs
        return {}

    return FakeGhRunner(permission_route({ADMIN}, extra))


def make_runtime(tmp_path, world, runner, author, **policy):
    origin, root = world
    config = load_config(environ={"AGENT_LOOP_REPO": REPO})
    config = replace(
        config,
        notify=replace(config.notify, mention=(ADMIN,)),
        worktree_dir=tmp_path / "worktrees",
        verify=VERIFY,
        policy=replace(config.policy, **policy),
    )
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    return Runtime(
        config,
        Gh(REPO, token_provider=lambda: "ghs_app_token", runner=runner, base_env={}),
        None,
        BOT,
        state_dir,
        QuotaLedger(state_dir / "quota.json"),
        repo_root=root,
        environ={"PATH": os.environ["PATH"], "HOME": str(tmp_path), "GH_TOKEN": "user-token", "OPENAI_API_KEY": "sk-x"},
        engine_runner=author,
        remote_url=str(origin),
    )


def approved_issue(**kwargs):
    return make_item(
        number=77,
        title=TITLE,
        body=BODY,
        labels=(state.AWAITING_APPROVAL,),
        comments=[
            analysis_comment(TITLE, BODY, text="## Problem\nCreate feature.txt per the spec."),
            comment("c-note", ADMIN, "Keep it small please", 15),
            comment("c-ok", ADMIN, "/approve", 20),
        ],
        **kwargs,
    )


def implement(item, model=SOL):
    return state.Action(
        state.RUN_STAGE,
        item,
        stage="implementation",
        model=model,
        add_labels=(state.IMPLEMENTING,),
        remove_labels=(state.AWAITING_APPROVAL,),
    )


def api_posts(runner, suffix):
    return [json.loads(c["input"]) for c in runner.api_calls("POST") if c["args"][3].endswith(suffix)]


def pr_item(labels=(state.IMPLEMENTING,), draft=True, head_ref=BRANCH, number=88, comments=(), sha="deadbeef"):
    item = make_item(number=number, is_pr=True, title="Add feature file", labels=labels, comments=comments)
    return replace(item, head_ref=head_ref, head_sha=sha, is_draft=draft, node_id="PR_node")


# --- implementation ----------------------------------------------------------------------------------------------


def test_implements_an_approved_issue_and_opens_a_draft_pull_request(tmp_path, world):
    origin, _root = world
    runner = make_gh()
    author = FakeAuthor({"files": {"feature.txt": "done\n"}, "result": GOOD})
    runtime = make_runtime(tmp_path, world, runner, author)

    line = execute(runtime, implement(approved_issue()))

    assert line == f"implemented issue #77 with {SOL}: opened draft PR #88"
    call = author.calls[0]
    assert call["command"][:2] == ["codex", "exec"] and "workspace-write" in call["command"]
    assert call["cwd"].name == "impl-77" and call["cwd"].parent == tmp_path / "worktrees"
    assert "Create feature.txt per the spec." in call["input"] and "Keep it small please" in call["input"]
    assert "ISSUE_BODY_MARKER" not in call["input"], "the original issue text must not reach the implementer"
    assert not {"GH_TOKEN", "OPENAI_API_KEY", "GITHUB_TOKEN"} & set(call["env"])
    # The branch is on origin with a bot-authored commit; nothing from .agent-loop leaked in.
    assert run_git(origin, "rev-parse", f"refs/heads/{BRANCH}") == run_git(call["cwd"], "rev-parse", "HEAD")
    show = run_git(origin, "show", "--name-only", "--format=%an <%ae>%n%s", f"refs/heads/{BRANCH}").splitlines()
    assert show[0] == f"{BOT} <342463850+{BOT}@users.noreply.github.com>" and show[1] == "Add feature file"
    assert show[-1] == "feature.txt"
    # The draft PR is created by the App with the issue linked and the work verified.
    pull = api_posts(runner, "/pulls")[0]
    assert (pull["head"], pull["base"], pull["draft"], pull["title"]) == (BRANCH, "main", True, "Add feature file")
    assert (
        "Closes #77" in pull["body"]
        and "approved by @admin-user" in pull["body"]
        and "Used the default" in pull["body"]
    )
    assert {"labels": [state.IMPLEMENTING]} in api_posts(runner, "/issues/88/labels")
    comments = [post["body"] for post in api_posts(runner, "/issues/88/comments")]
    assert state.run_marker("implementation", SOL) in comments[0]
    assert any("draft pull request #88" in post["body"] for post in api_posts(runner, "/issues/77/comments"))
    progress = ProgressStore(runtime.state_dir / "stages").load(77)
    assert (progress.status, progress.pr_number, progress.branch) == (PR_OPEN, 88, BRANCH)


def test_verbose_log_traces_each_implementation_step_without_prompts_or_tokens(tmp_path, world, caplog):
    caplog.set_level(logging.DEBUG, logger="agent_loop")
    runner = make_gh()
    author = FakeAuthor({"files": {"feature.txt": "done\n"}, "result": GOOD})
    runtime = make_runtime(tmp_path, world, runner, author)

    execute(runtime, implement(approved_issue()))

    messages = [record.getMessage() for record in caplog.records]
    expected = [
        "approval by admin-user of analysis revision 1 is still valid",
        "created worktree",
        f"running {SOL} in",
        "codex finished in",
        "verifying outside the sandbox",
        "verify: ",
        "verification passed",
        "committed ",
        "diff policy: passed",
        f"pushing {BRANCH} to",
        "opening a draft pull request",
    ]
    positions = [next(i for i, text in enumerate(messages) if step in text) for step in expected]
    assert positions == sorted(positions), messages
    assert any(text.startswith("gh api --method POST repos/") for text in messages)
    log_text = "\n".join(messages)
    for secret in ("ghs_app_token", "user-token", "sk-x", "Create feature.txt per the spec.", "Adds the feature."):
        assert secret not in log_text


def test_failing_verification_is_repaired_by_resuming_the_same_session_with_the_failure_output(tmp_path, world):
    runner = make_gh()
    author = FakeAuthor(
        {"files": {"notes.txt": "wrong file\n"}, "result": GOOD, "session": "sess-9"},
        {"files": {"feature.txt": "done\n"}, "result": GOOD, "session": "sess-9"},
    )
    runtime = make_runtime(tmp_path, world, runner, author)
    runtime.config = replace(
        runtime.config,
        verify=VerifyConfig(
            commands=(
                "{python} -c \"import pathlib, sys; print('MISSING feature.txt'); sys.exit(0 if pathlib.Path('feature.txt').exists() else 1)\"",
            ),
            timeout_minutes=1,
        ),
    )

    line = execute(runtime, implement(approved_issue()))

    assert line.endswith("opened draft PR #88")
    repair = author.calls[1]
    assert repair["command"][:3] == ["codex", "exec", "resume"] and "sess-9" in repair["command"]
    assert 'sandbox_mode="workspace-write"' in repair["command"]
    assert "<verification_failures>" in repair["input"] and "MISSING feature.txt" in repair["input"]
    assert "Continue from where the previous run stopped" not in repair["input"]


def test_resumed_runs_that_cannot_resume_fall_back_to_a_fresh_session(tmp_path, world):
    runner = make_gh()
    author = FakeAuthor(
        {"code": 1, "stderr": "Error: no rollout found for session sess-old"},
        {"files": {"feature.txt": "done\n"}, "result": GOOD, "session": "sess-new"},
    )
    runtime = make_runtime(tmp_path, world, runner, author)
    store = ProgressStore(runtime.state_dir / "stages")
    store.save(replace(store.load(77), session_id="sess-old", engine="codex", branch=BRANCH))

    line = execute(runtime, implement(approved_issue()))

    assert line.endswith("opened draft PR #88")
    assert author.calls[0]["command"][:3] == ["codex", "exec", "resume"]
    assert (
        author.calls[1]["command"][:3] != ["codex", "exec", "resume"]
        and "<approved_specification>" in author.calls[1]["input"]
    )
    assert "A previous run of this stage was interrupted" in author.calls[1]["input"]
    assert store.load(77).session_id == "sess-new"


def test_persistent_verification_failure_blocks_after_the_round_limit(tmp_path, world):
    origin, _root = world
    runner = make_gh()
    author = FakeAuthor({"result": GOOD}, {"result": GOOD})
    runtime = make_runtime(tmp_path, world, runner, author, max_verify_rounds=1)

    line = execute(runtime, implement(approved_issue()))

    assert "the checks still fail after 1 repair rounds" in line and len(author.calls) == 2
    assert {"labels": [state.BLOCKED]} in api_posts(runner, "/issues/77/labels")
    assert api_posts(runner, "/pulls") == []
    assert (
        subprocess.run(
            ["git", "-C", str(origin), "rev-parse", "--verify", f"refs/heads/{BRANCH}"], capture_output=True
        ).returncode
        != 0
    )


@pytest.mark.parametrize(
    "files, rule",
    [
        ({".github/workflows/ci.yml": "name: x\n"}, "protected path"),
        ({"src/k.py": 'K = """-----BEGIN RSA PRIVATE KEY-----\nMIIE"""\n'}, "possible secret"),
    ],
)
def test_diff_policy_violations_block_before_anything_is_pushed(tmp_path, world, files, rule):
    origin, _root = world
    runner = make_gh()
    author = FakeAuthor({"files": {"feature.txt": "done\n", **files}, "result": GOOD})
    runtime = make_runtime(tmp_path, world, runner, author)

    line = execute(runtime, implement(approved_issue()))

    assert rule in line and "MIIE" not in line
    assert api_posts(runner, "/pulls") == []
    assert (
        subprocess.run(
            ["git", "-C", str(origin), "rev-parse", "--verify", f"refs/heads/{BRANCH}"], capture_output=True
        ).returncode
        != 0
    )
    assert {"labels": [state.BLOCKED]} in api_posts(runner, "/issues/77/labels")


def test_model_that_changes_nothing_is_blocked(tmp_path, world):
    runtime = make_runtime(tmp_path, world, make_gh(), FakeAuthor({"result": GOOD}))
    runtime.config = replace(runtime.config, verify=VerifyConfig(commands=("{python} -c pass",), timeout_minutes=1))

    assert "the model made no changes" in execute(runtime, implement(approved_issue()))


def test_model_reports_blocked_with_neutralized_explanation(tmp_path, world):
    runner = make_gh()
    author = FakeAuthor({"result": {"outcome": "blocked", "blocker": "Cannot do this, ask @eve about it"}})
    runtime = make_runtime(tmp_path, world, runner, author)

    line = execute(runtime, implement(approved_issue()))

    notice = api_posts(runner, "/issues/77/comments")[0]["body"]
    assert (
        "the model reports it cannot implement this" in line
        and "@<!-- -->eve" in notice
        and "@eve" not in notice.replace("@<!-- -->eve", "")
    )


def test_secret_in_the_models_summary_is_never_published(tmp_path, world):
    leaked = dict(GOOD, summary="token ghs_" + "a" * 36)
    runner = make_gh()
    runtime = make_runtime(tmp_path, world, runner, FakeAuthor({"files": {"feature.txt": "x\n"}, "result": leaked}))

    line = execute(runtime, implement(approved_issue()))

    assert "possible credential" in line and api_posts(runner, "/pulls") == []


def test_implementation_requires_a_still_valid_approval(tmp_path, world):
    runner = make_gh()
    author = FakeAuthor()
    runtime = make_runtime(tmp_path, world, runner, author)
    edited = replace(approved_issue(), body="The issue changed after approval")

    line = execute(runtime, implement(edited))

    assert "the approval is no longer valid (stale)" in line and author.calls == []


def test_quota_exhaustion_keeps_the_worktree_and_resumes_the_session_later(tmp_path, world):
    runner = make_gh()
    author = FakeAuthor(
        {
            "files": {"partial.txt": "half done\n"},
            "code": 1,
            "stderr": "You've hit your usage limit. Try again in 3 hours.",
            "session": "sess-q",
        },
        {"files": {"feature.txt": "done\n"}, "result": GOOD, "session": "sess-q"},
    )
    runtime = make_runtime(tmp_path, world, runner, author)

    paused = execute(runtime, implement(approved_issue()))

    assert paused.startswith("paused issue #77: codex exhausted")
    assert {"labels": [state.WAITING_QUOTA]} in api_posts(runner, "/issues/77/labels")
    progress = ProgressStore(runtime.state_dir / "stages").load(77)
    assert progress.session_id == "sess-q" and (tmp_path / "worktrees" / "impl-77" / "partial.txt").exists()
    assert api_posts(runner, "/pulls") == []

    runtime.ledger.record_classification("codex", Classification(SUCCESS))  # the limit window reset
    resumed = execute(
        runtime, implement(replace(approved_issue(), labels=frozenset({state.IMPLEMENTING, state.WAITING_QUOTA})))
    )

    assert resumed.endswith("opened draft PR #88")
    assert author.calls[1]["command"][:3] == ["codex", "exec", "resume"] and "sess-q" in author.calls[1]["command"]
    assert "Continue from where the previous run stopped" in author.calls[1]["input"]


def test_a_pull_request_closed_without_merging_stops_reimplementation(tmp_path, world):
    runner = make_gh(pull_state="closed")
    author = FakeAuthor()
    runtime = make_runtime(tmp_path, world, runner, author)
    ProgressStore(runtime.state_dir / "stages").save(
        replace(ProgressStore(runtime.state_dir / "stages").load(77), pr_number=88, branch=BRANCH)
    )

    line = execute(runtime, implement(approved_issue()))

    assert "pull request #88 was closed without merging" in line and author.calls == []


# --- the CI loop -------------------------------------------------------------------------------------------------


def green_runs():
    return [(1, "Lint", "completed", "success"), (2, "Test", "completed", "success")]


def ci_runs(*entries):
    return [{"id": i, "name": n, "status": s, "conclusion": c} for i, n, s, c in entries]


def ci_action(pr, issue=None):
    return state.Action(state.CHECK_CI, pr, related=issue, priority=2)


def test_pending_ci_waits(tmp_path, world):
    runner = make_gh(ci_runs=ci_runs((1, "Lint", "completed", "success"), (2, "Test", "in_progress", None)))
    runtime = make_runtime(tmp_path, world, runner, FakeAuthor())

    assert execute(runtime, ci_action(pr_item())) == "waiting for CI on PR #88: 1/2 required checks passed"


def test_green_ci_marks_the_pull_request_ready_for_ai_review(tmp_path, world):
    _origin, root = world
    runner = make_gh(ci_runs=ci_runs((1, "Lint", "completed", "success"), (2, "Test", "completed", "success")))
    runtime = make_runtime(tmp_path, world, runner, FakeAuthor())

    line = execute(runtime, ci_action(pr_item()))

    assert line == "PR #88 is green and ready for AI review"
    ready = [c["args"] for c in runner.calls if c["args"][:2] == ["api", "graphql"]]
    assert any("markPullRequestReadyForReview" in next(a for a in args if a.startswith("query=")) for args in ready)
    assert {"labels": [state.AI_REVIEW]} in api_posts(runner, "/issues/88/labels")
    assert any(c["args"][3].endswith("/labels/agent%3Aimplementing") for c in runner.api_calls("DELETE"))
    assert "ready for AI review" in api_posts(runner, "/issues/88/comments")[0]["body"]
    assert not (tmp_path / "worktrees" / "impl-77").exists()


def seed_pr_branch(world, tmp_path, files):
    origin, root = world
    run_git(root, "checkout", "-q", "-b", BRANCH, "main")
    for name, content in files.items():
        (root / name).write_text(content)
    run_git(root, "add", "-A")
    run_git(root, "commit", "-q", "-m", "wip")
    run_git(root, "push", "-q", "origin", BRANCH)
    run_git(root, "checkout", "-q", "main")
    run_git(root, "branch", "-q", "-D", BRANCH)
    return origin


def test_failing_ci_is_repaired_verified_pushed_and_recorded(tmp_path, world):
    origin = seed_pr_branch(world, tmp_path, {"lib.py": "x = 1\n"})
    runner = make_gh(ci_runs=ci_runs((1, "Lint", "completed", "failure"), (2, "Test", "completed", "success")))
    fix = {"outcome": "implemented", "title": "Fix lint error", "summary": "Removes the unused variable.", "notes": []}
    author = FakeAuthor({"files": {"feature.txt": "fixed\n"}, "result": fix})
    runtime = make_runtime(tmp_path, world, runner, author)
    issue = approved_issue()

    line = execute(runtime, ci_action(pr_item(), issue))

    assert line == f"repaired CI on PR #88 with {SOL} (attempt 1); waiting for new checks"
    prompt = author.calls[0]["input"]
    assert (
        '<failed_check name="Lint">' in prompt
        and "FAILED test_x" in prompt
        and "Create feature.txt per the spec." in prompt
    )
    assert "feature.txt" in run_git(origin, "show", "--name-only", "--format=", f"refs/heads/{BRANCH}")
    comment_body = api_posts(runner, "/issues/88/comments")[0]["body"]
    assert "CI repair attempt 1/3 for Lint" in comment_body and state.run_marker("ci_fix", SOL) in comment_body
    assert run_git(origin, "log", "--format=%an", f"refs/heads/{BRANCH}").splitlines()[0] == BOT


def test_ci_repair_attempts_are_limited(tmp_path, world):
    runner = make_gh(ci_runs=ci_runs((1, "Lint", "completed", "failure"), (2, "Test", "completed", "success")))
    author = FakeAuthor()
    runtime = make_runtime(tmp_path, world, runner, author)
    attempts = [comment(f"r{n}", BOT, f"fix\n{state.run_marker('ci_fix', SOL)}", n) for n in range(3)]

    line = execute(runtime, ci_action(pr_item(comments=attempts), approved_issue()))

    assert "CI is still failing after 3 repair attempts (Lint)" in line and author.calls == []
    assert {"labels": [state.BLOCKED]} in api_posts(runner, "/issues/88/labels")


def test_ci_repair_is_deferred_when_the_tick_budget_is_spent(tmp_path, world):
    runner = make_gh(ci_runs=ci_runs((1, "Lint", "completed", "failure"), (2, "Test", "completed", "success")))
    author = FakeAuthor()
    runtime = make_runtime(tmp_path, world, runner, author)
    runtime.budget = 0

    line = execute(runtime, ci_action(pr_item(), approved_issue()))

    assert line.startswith("deferred to the next tick: repair CI failures on PR #88") and author.calls == []


def test_ci_repair_waits_for_quota_instead_of_switching_models(tmp_path, world):
    runner = make_gh(ci_runs=ci_runs((1, "Lint", "completed", "failure"), (2, "Test", "completed", "success")))
    author = FakeAuthor()
    runtime = make_runtime(tmp_path, world, runner, author)
    runtime.ledger.record_classification("codex", Classification("quota_exhausted", 4_000_000_000.0, "limit"))

    line = execute(runtime, ci_action(pr_item(), approved_issue()))

    assert line.startswith("waiting: CI repair for PR #88") and author.calls == []
    assert {"labels": [state.WAITING_QUOTA]} in api_posts(runner, "/issues/88/labels")


def test_unmanaged_branch_with_failing_ci_is_escalated(tmp_path, world):
    runner = make_gh(ci_runs=ci_runs((1, "Lint", "completed", "failure"), (2, "Test", "completed", "success")))
    runtime = make_runtime(tmp_path, world, runner, FakeAuthor())

    line = execute(runtime, ci_action(pr_item(head_ref="someone/else")))

    assert "a branch the agent loop does not manage" in line


# --- housekeeping ------------------------------------------------------------------------------------------------


def test_finished_worktrees_are_removed_and_active_ones_kept(tmp_path, world):
    _origin, root = world
    runtime = make_runtime(tmp_path, world, make_gh(), FakeAuthor())
    for number in (77, 78):
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "worktree",
                "add",
                "-q",
                "-b",
                f"agent/issue-{number}-x",
                str(tmp_path / "worktrees" / f"impl-{number}"),
                "main",
            ],
            check=True,
        )
    store = ProgressStore(runtime.state_dir / "stages")
    store.save(replace(store.load(78), branch="agent/issue-78-x"))
    active = make_item(number=77, labels=(state.IMPLEMENTING,))

    removed = cleanup_worktrees(runtime, [active])

    assert removed == ["removed finished worktree impl-78"]
    assert (tmp_path / "worktrees" / "impl-77").exists() and not (tmp_path / "worktrees" / "impl-78").exists()
    assert (
        subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "agent/issue-78-x"], capture_output=True
        ).returncode
        != 0
    )


def test_item_snapshot_carries_node_id_and_branch():
    from agent_loop.snapshot import item_from_node

    node = {
        "id": "PR_1",
        "number": 5,
        "title": "t",
        "createdAt": "2026-10-07T12:00:00Z",
        "isDraft": True,
        "headRefOid": "abc",
        "headRefName": BRANCH,
    }

    item: Item = item_from_node(node, is_pr=True)

    assert (item.node_id, item.head_ref, item.is_draft, item.head_sha) == ("PR_1", BRANCH, True, "abc")
