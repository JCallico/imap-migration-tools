"""Tests for the gh wrapper, GitHub App authentication, notifications, and label bootstrap."""

import json
import subprocess
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from agent_loop_fakes import REPO, FakeGhRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from agent_loop.app_auth import (
    AppAuthError,
    AppTokenProvider,
    build_app_jwt,
    check_private_key_file,
    provider_from_config,
)
from agent_loop.config import GitHubConfig
from agent_loop.gh import Gh, GhError
from agent_loop.labels import LABELS, bootstrap_labels
from agent_loop.notify import GitHubNotifier, Notification, notification_marker


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def key_file(tmp_path, rsa_key):
    pem = rsa_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    path = tmp_path / "app.pem"
    path.write_bytes(pem)
    path.chmod(0o600)
    return path


def test_gh_environment_drops_inherited_tokens_and_injects_app_token():
    runner = FakeGhRunner(lambda args, stdin: [])
    gh = Gh(REPO, token_provider=lambda: "ghs_app", runner=runner, base_env={"GH_TOKEN": "user", "PATH": "/bin"})

    gh.api("repos/owner/repo/issues")

    env = runner.calls[0]["env"]
    assert env["GH_TOKEN"] == "ghs_app"
    assert env["PATH"] == "/bin" and env["GH_PROMPT_DISABLED"] == "1"


def test_gh_api_arguments_body_and_pagination():
    runner = FakeGhRunner(lambda args, stdin: [[{"n": 1}], [{"n": 2}]])
    gh = Gh(REPO, runner=runner, base_env={})

    items = gh.api("repos/x/y/issues", fields={"state": "open", "per_page": 100}, paginate=True)
    gh.api("repos/x/y/issues/1/labels", method="POST", body={"labels": ["agent:paused"]})

    assert items == [{"n": 1}, {"n": 2}]
    first, second = runner.calls
    assert first["args"][:4] == ["api", "--method", "GET", "repos/x/y/issues"]
    assert ["-f", "state=open"] == first["args"][4:6] and ["-F", "per_page=100"] == first["args"][6:8]
    assert first["args"][-2:] == ["--paginate", "--slurp"]
    assert json.loads(second["input"]) == {"labels": ["agent:paused"]}


def test_gh_errors_redact_authorization_headers():
    def fail(args, stdin):
        return subprocess.CompletedProcess(args, 1, "", "HTTP 401: Bad credentials")

    gh = Gh(REPO, runner=FakeGhRunner(fail), base_env={})

    with pytest.raises(GhError) as error:
        gh.api("/app", headers=["Authorization: Bearer secret.jwt"])
    assert "secret.jwt" not in str(error.value)


def test_graphql_errors_raise():
    gh = Gh(REPO, runner=FakeGhRunner(lambda args, stdin: {"errors": [{"message": "bad"}]}), base_env={})

    with pytest.raises(GhError, match="bad"):
        gh.graphql("query { viewer { login } }")


def test_app_jwt_is_short_lived_and_signed(rsa_key, key_file):
    token = build_app_jwt("123", key_file.read_text(), now=1_000_000)

    claims = jwt.decode(token, rsa_key.public_key(), algorithms=["RS256"], options={"verify_exp": False})
    assert claims == {"iss": "123", "iat": 1_000_000 - 60, "exp": 1_000_000 + 540}


def test_private_key_readable_by_others_is_refused(key_file):
    key_file.chmod(0o644)

    with pytest.raises(AppAuthError, match="chmod 600"):
        check_private_key_file(key_file)


def test_installation_token_is_minted_with_bearer_jwt_and_cached(key_file):
    now = [1_000_000.0]
    expires = datetime.fromtimestamp(now[0], timezone.utc) + timedelta(hours=1)

    def route(args, stdin):
        return {"token": f"ghs_{len(runner.calls)}", "expires_at": expires.isoformat().replace("+00:00", "Z")}

    runner = FakeGhRunner(route)
    gh = Gh(REPO, runner=runner, base_env={"GH_TOKEN": "user-token"})
    provider = AppTokenProvider("123", "456", key_file, gh, clock=lambda: now[0])

    first = provider()
    assert provider() == first
    now[0] += 56 * 60  # within the refresh margin
    assert provider() != first

    call = runner.calls[0]
    assert call["args"][:4] == ["api", "--method", "POST", "/app/installations/456/access_tokens"]
    assert any(arg.startswith("Authorization: Bearer ") for arg in call["args"])
    assert "GH_TOKEN" not in call["env"]


def test_incomplete_app_configuration_is_rejected(tmp_path):
    assert provider_from_config(GitHubConfig()) is None
    with pytest.raises(AppAuthError, match="incomplete"):
        provider_from_config(GitHubConfig(app_id="1"))


def test_notifier_requires_app_identity_and_deduplicates():
    marker = notification_marker("analysis-1")

    def route(args, stdin):
        if "--paginate" in args:
            return [[{"body": f"earlier\n{marker}"}]]
        return {}

    runner = FakeGhRunner(route)
    as_user = GitHubNotifier(Gh(REPO, runner=runner, base_env={}), ("admin-user",))
    as_app = GitHubNotifier(Gh(REPO, token_provider=lambda: "t", runner=runner, base_env={}), ("admin-user",))

    with pytest.raises(RuntimeError, match="GitHub App"):
        as_user.send(Notification(1, "analysis-2", "ready"))
    assert as_app.send(Notification(1, "analysis-1", "ready")).startswith("already notified")
    assert runner.api_calls("POST") == []


def test_notifier_mentions_assigns_and_requests_review():
    runner = FakeGhRunner(lambda args, stdin: [[]] if "--paginate" in args else {})
    notifier = GitHubNotifier(Gh(REPO, token_provider=lambda: "t", runner=runner, base_env={}), ("admin-user",))

    notifier.send(Notification(9, "ready-abc", "PR ready for review", is_pr=True, assign=True, request_review=True))

    posts = runner.api_calls("POST")
    paths = [call["args"][3] for call in posts]
    assert paths == [
        "repos/owner/repo/issues/9/comments",
        "repos/owner/repo/issues/9/assignees",
        "repos/owner/repo/pulls/9/requested_reviewers",
    ]
    body = json.loads(posts[0]["input"])["body"]
    assert body.startswith("@admin-user PR ready for review") and notification_marker("ready-abc") in body


def test_notifier_dry_run_makes_no_calls():
    runner = FakeGhRunner()
    notifier = GitHubNotifier(Gh(REPO, runner=runner, base_env={}), ("admin-user",), dry_run=True)

    assert "would notify admin-user" in notifier.send(Notification(1, "k", "hello"))
    assert runner.calls == []


def test_label_bootstrap_describes_by_default_and_applies_on_request():
    runner = FakeGhRunner(lambda args, stdin: "")
    gh = Gh(REPO, runner=runner, base_env={})

    described = bootstrap_labels(gh, apply=False)
    assert runner.calls == [] and len(described) == len(LABELS)

    bootstrap_labels(gh, apply=True)
    assert {call["args"][2] for call in runner.calls} == {spec.name for spec in LABELS}
    assert all("--force" in call["args"] for call in runner.calls)
