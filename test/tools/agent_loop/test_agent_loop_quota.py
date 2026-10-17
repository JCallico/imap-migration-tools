"""Tests for quota telemetry parsing, failure classification, and the persistent ledger."""

import json
import stat

from agent_loop_fakes import FIXTURES

from agent_loop.quota import (
    AUTH,
    AVAILABLE,
    BACKOFF_BASE_SECONDS,
    EXHAUSTED,
    LOW,
    QUOTA_EXHAUSTED,
    SUCCESS,
    TASK_FAILURE,
    TRANSIENT,
    UNCLASSIFIED,
    UNKNOWN,
    Classification,
    QuotaLedger,
    RateLimitSnapshot,
    RateWindow,
    classify_failure,
    claude_snapshot,
    codex_snapshot,
    parse_reset_hint,
)

NOW = 1_800_000_000.0


def fixture_events(name):
    return [json.loads(line) for line in (FIXTURES / name).read_text().splitlines() if line.strip()]


def test_codex_snapshot_from_recorded_rollout():
    token_count = next(e for e in fixture_events("codex_rollout_ok.jsonl") if e["payload"].get("type") == "token_count")

    snapshot = codex_snapshot(token_count["payload"]["rate_limits"])

    assert snapshot.engine == "codex"
    assert [window.name for window in snapshot.windows] == ["primary_300m", "secondary_10080m"]
    assert snapshot.used_percent == 10.0
    assert snapshot.limited is False
    assert snapshot.reset_at == 1791656600


def test_claude_snapshot_from_recorded_stream():
    event = next(e for e in fixture_events("claude_stream_ok.jsonl") if e["type"] == "rate_limit_event")

    snapshot = claude_snapshot(event["rate_limit_info"])

    assert snapshot.engine == "claude"
    assert snapshot.used_percent == 24.0
    assert snapshot.limited is False


def test_claude_rejected_status_is_a_limit_with_reset():
    snapshot = claude_snapshot(
        {
            "status": "rejected",
            "rateLimitType": "five_hour",
            "resetsAt": NOW + 3600,
            "unifiedWindows": {"five_hour": {"utilization": 1.0, "resetsAt": NOW + 3600}},
        }
    )

    assert snapshot.limited
    assert snapshot.reset_at == NOW + 3600
    assert classify_failure(1, [], snapshot, now=NOW) == Classification(
        QUOTA_EXHAUSTED, NOW + 3600, "engine reported limit"
    )


def test_codex_reached_limit_uses_limited_window_reset():
    snapshot = codex_snapshot(
        {
            "primary": {"used_percent": 100.0, "window_minutes": 300, "resets_at": NOW + 600},
            "secondary": {"used_percent": 40.0, "window_minutes": 10080, "resets_at": NOW + 86400},
            "rate_limit_reached_type": "primary",
        }
    )

    assert snapshot.limited
    assert snapshot.reset_at == NOW + 600


def test_success_is_not_a_failure():
    assert classify_failure(0, [], None, now=NOW).kind == SUCCESS


def test_only_error_channels_are_classified():
    # A task about IMAP rate limits finishing successfully must not look like a quota failure.
    assert classify_failure(0, [], None, now=NOW).kind == SUCCESS
    assert classify_failure(1, ["SyntaxError in generated file"], None, now=NOW).kind == UNCLASSIFIED


def test_quota_message_with_relative_reset():
    result = classify_failure(1, ["You've hit your usage limit. Try again in 3 hours."], None, now=NOW)

    assert result.kind == QUOTA_EXHAUSTED
    assert result.reset_at == NOW + 3 * 3600


def test_auth_transient_and_timeout_classification():
    assert classify_failure(1, ["Error: not logged in"], None, now=NOW).kind == AUTH
    transient = classify_failure(1, ["stream disconnected before completion"], None, now=NOW)
    assert transient.kind == TRANSIENT and transient.reset_at > NOW
    assert classify_failure(None, [], None, timed_out=True, now=NOW).kind == TASK_FAILURE


def test_reset_hint_units():
    assert parse_reset_hint("retry after 90 seconds", NOW) == NOW + 90
    assert parse_reset_hint("resets in 2 days", NOW) == NOW + 2 * 86400
    assert parse_reset_hint("no hint", NOW) is None


def ledger(tmp_path, **kwargs):
    return QuotaLedger(tmp_path / "state" / "quota.json", **kwargs)


def test_low_quota_blocks_long_stages_only(tmp_path):
    book = ledger(tmp_path, low_threshold_percent=80)
    book.record_snapshot(RateLimitSnapshot("codex", (RateWindow("primary", 85.0, NOW + 1000),)), now=NOW)

    assert book.get("codex").status == LOW
    assert book.usable("codex", long_stage=True, now=NOW)[0] is False
    assert book.usable("codex", long_stage=False, now=NOW)[0] is True
    assert book.usable("codex", long_stage=True, now=NOW + 1001)[0] is True


def test_exhausted_until_known_reset(tmp_path):
    book = ledger(tmp_path)
    book.record_classification("claude", Classification(QUOTA_EXHAUSTED, NOW + 7200, "limit"), now=NOW)

    ok, reason = book.usable("claude", long_stage=False, now=NOW + 60)
    assert not ok and "exhausted" in reason
    assert book.usable("claude", long_stage=False, now=NOW + 7201) == (True, "")
    assert not book.needs_probe("claude", now=NOW + 7201)


def test_unknown_reset_backs_off_exponentially_with_cap(tmp_path):
    book = ledger(tmp_path, unknown_backoff_max_hours=1.5)
    delays = []
    for _ in range(4):
        entry = book.record_classification("codex", Classification(UNCLASSIFIED, None, "boom"), now=NOW)
        delays.append(entry.resume_at - NOW)

    assert delays == [BACKOFF_BASE_SECONDS, 2 * BACKOFF_BASE_SECONDS, 1.5 * 3600, 1.5 * 3600]
    assert book.get("codex").status == UNKNOWN
    assert book.needs_probe("codex", now=NOW + 2 * 3600)


def test_success_clears_pause_and_backoff(tmp_path):
    book = ledger(tmp_path)
    book.record_classification("codex", Classification(QUOTA_EXHAUSTED, None, "limit"), now=NOW)
    book.record_classification("codex", Classification(SUCCESS), now=NOW + 4000)

    entry = book.get("codex")
    assert (entry.status, entry.backoff_level, entry.resume_at) == (AVAILABLE, 0, None)


def test_ledger_persists_with_private_permissions(tmp_path):
    book = ledger(tmp_path)
    book.record_classification("claude", Classification(QUOTA_EXHAUSTED, NOW + 60, "limit"), now=NOW)

    reopened = ledger(tmp_path)
    assert reopened.get("claude").status == EXHAUSTED
    assert stat.S_IMODE(book.path.stat().st_mode) == 0o600
    assert reopened.get("codex").status == AVAILABLE
