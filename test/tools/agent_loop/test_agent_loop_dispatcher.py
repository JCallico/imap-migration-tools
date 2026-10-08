"""End-to-end dispatcher tests against a scripted gh CLI: GraphQL snapshots in, GitHub writes out."""

import json
from dataclasses import replace

import pytest
from agent_loop_fakes import ADMIN, REPO, FakeGhRunner, permission_route
from filelock import FileLock

from agent_loop import __main__ as cli
from agent_loop.config import load_config
from agent_loop.dispatcher import DispatcherError, Runtime, set_paused, status, tick
from agent_loop.gh import Gh
from agent_loop.quota import QuotaLedger

BOT_SLUG = "imap-agent"


def actor(login, bot=False):
    return {"__typename": "Bot" if bot else "User", "login": login}


def issue_node(number, labels=(), comments=(), events=(), created="2026-10-07T12:00:00Z"):
    return {
        "number": number,
        "title": f"Issue {number}",
        "body": "Body",
        "url": f"https://github.com/{REPO}/issues/{number}",
        "state": "OPEN",
        "createdAt": created,
        "author": actor("reporter"),
        "labels": {"nodes": [{"name": label} for label in labels]},
        "comments": {"totalCount": len(comments), "nodes": list(comments)},
        "timelineItems": {"totalCount": len(events), "nodes": list(events)},
    }


def comment_node(cid, login, body, created, bot=False):
    return {
        "id": cid,
        "body": body,
        "createdAt": created,
        "lastEditedAt": None,
        "author": actor(login, bot),
        "userContentEdits": {"nodes": []},
    }


def labeled(label, login, created, bot=False):
    return {"__typename": "LabeledEvent", "createdAt": created, "actor": actor(login, bot), "label": {"name": label}}


def github(issues, pulls=()):
    def extra(args, stdin):
        if args[:2] == ["api", "graphql"]:
            query = next(arg for arg in args if arg.startswith("query="))
            key = "pullRequests" if "pullRequests(" in query else "issues"
            nodes = list(pulls) if key == "pullRequests" else list(issues)
            return {
                "data": {"repository": {key: {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": nodes}}}
            }
        return {}

    return FakeGhRunner(permission_route({ADMIN}, extra))


def runtime(tmp_path, runner, as_app=True, paused=False):
    config = load_config(environ={"AGENT_LOOP_REPO": REPO, "AGENT_LOOP_PAUSED": "true" if paused else "false"})
    config = replace(config, notify=replace(config.notify, mention=(ADMIN,)))
    gh = Gh(REPO, token_provider=(lambda: "ghs_app") if as_app else None, runner=runner, base_env={})
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    return Runtime(config, gh, None, f"{BOT_SLUG}[bot]", state_dir, QuotaLedger(state_dir / "quota.json"))


def test_dry_run_plans_without_writing(tmp_path):
    runner = github([issue_node(3)])

    lines = tick(runtime(tmp_path, runner), dry_run=True)

    assert lines == ["[dry-run] issue #3: run analysis with claude:claude-opus-5-5:medium — new issue"]
    assert runner.api_calls("POST") == [] and runner.api_calls("DELETE") == []
    log = [json.loads(line) for line in (tmp_path / "state" / "ticks.jsonl").read_text().splitlines()]
    assert log[0]["dry_run"] is True


def test_live_tick_reverts_forged_labels_and_answers_unauthorized_commands(tmp_path):
    forged = issue_node(
        4,
        labels=["agent:ai-review"],
        events=[labeled("agent:ai-review", "maintainer", "2026-10-07T12:05:00Z")],
    )
    command = issue_node(
        5,
        labels=["agent:awaiting-approval"],
        events=[labeled("agent:awaiting-approval", BOT_SLUG, "2026-10-07T12:01:00Z", bot=True)],
        comments=[
            comment_node(
                "analysis", BOT_SLUG, "Spec\n<!-- agent-loop:analysis rev=1 hash=x -->", "2026-10-07T12:01:00Z", True
            ),
            comment_node("c1", "maintainer", "/approve", "2026-10-07T12:02:00Z"),
        ],
    )
    runner = github([forged, command])

    lines = tick(runtime(tmp_path, runner), dry_run=False)

    deletes = [call["args"][3] for call in runner.api_calls("DELETE")]
    assert deletes == ["repos/owner/repo/issues/4/labels/agent%3Aai-review"]
    replies = [json.loads(call["input"])["body"] for call in runner.api_calls("POST")]
    assert any("only repository administrators" in body and "comment=c1" in body for body in replies)
    assert any(line.startswith("reverted:") for line in lines)
    # The stale analysis (hash mismatch) leads to a pending re-analysis, never to implementation.
    assert not any("implementation" in line for line in lines)


def test_live_tick_requires_app_identity(tmp_path):
    with pytest.raises(DispatcherError, match="GitHub App"):
        tick(runtime(tmp_path, github([]), as_app=False), dry_run=False)


def test_paused_loop_and_concurrent_ticks(tmp_path):
    rt = runtime(tmp_path, github([issue_node(3)]))
    set_paused(rt, True)
    assert tick(rt, dry_run=True) == ["agent loop is paused; no actions taken"]
    set_paused(rt, False)

    with FileLock(str(rt.state_dir / "tick.lock")):
        with pytest.raises(DispatcherError, match="already running"):
            tick(rt, dry_run=True)


def test_status_reports_stages_quota_and_labels(tmp_path):
    rt = runtime(tmp_path, github([issue_node(3, labels=["agent:analyzing"])]))

    text = "\n".join(status(rt))

    assert "review: claude:claude-sonnet-5-5:medium" in text
    assert "no usage recorded yet" in text
    assert "agent:analyzing: 1" in text


def test_cli_reports_configuration_errors(tmp_path, capsys):
    bad = tmp_path / "bad.toml"
    bad.write_text("[stages.review]\nengine = 'codex'\nmodel = 'gpt-6.1-sol'\n")

    assert cli.main(["--config", str(bad), "status"]) == 2
    assert "must differ" in capsys.readouterr().err


def test_review_round_limit_blocks_and_notifies_admin(tmp_path):
    runs = [
        comment_node(
            f"r{n}",
            BOT_SLUG,
            "<!-- agent-loop:run stage=review model=claude:claude-sonnet-5-5:medium -->",
            f"2026-10-07T12:0{n}:00Z",
            True,
        )
        for n in range(3)
    ]
    pr = issue_node(
        9,
        labels=["agent:ai-review"],
        comments=runs,
        events=[labeled("agent:ai-review", BOT_SLUG, "2026-10-07T12:00:00Z", bot=True)],
    )
    pr.update({"isDraft": False, "headRefOid": "abc", "reviews": {"nodes": []}})
    runner = github([], pulls=[pr])

    tick(runtime(tmp_path, runner), dry_run=False)

    posts = runner.api_calls("POST")
    assert json.loads(posts[0]["input"]) == {"labels": ["agent:blocked"]}
    assert runner.api_calls("DELETE")[0]["args"][3].endswith("/labels/agent%3Aai-review")
    notice = json.loads(posts[-1]["input"])["body"]
    assert notice.startswith(f"@{ADMIN} Needs your decision") and "key=blocked-9-abc" in notice
