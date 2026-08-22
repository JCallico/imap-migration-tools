"""Tests for operation readiness and output parsing."""

import pytest

from cli.backup import parse_arguments as parse_backup_arguments
from cli.compare import parse_arguments as parse_compare_arguments
from cli.count import parse_arguments as parse_count_arguments
from tui.operations import (
    OPERATION_BY_NAME,
    ProgressState,
    RunOptions,
    build_command,
    parse_output,
    readiness,
    required_settings,
)


def account_values():
    return {
        "SRC_IMAP_HOST": "src.example.com",
        "SRC_IMAP_USERNAME": "source",
        "SRC_IMAP_PASSWORD": "secret",
        "DEST_IMAP_HOST": "dest.example.com",
        "DEST_IMAP_USERNAME": "destination",
        "DEST_IMAP_PASSWORD": "secret",
    }


def test_readiness_matrix(tmp_path):
    values = account_values()
    values["BACKUP_LOCAL_PATH"] = str(tmp_path)
    assert readiness("count", values).ready
    assert readiness("backup", values).ready
    assert readiness("restore", values).ready
    assert readiness("migrate", values).ready
    values["SRC_LOCAL_PATH"] = str(tmp_path)
    values["DEST_LOCAL_PATH"] = str(tmp_path)
    assert readiness("compare", values).ready


def test_backup_required_settings_identify_missing_path():
    required, missing = required_settings("backup", account_values())
    assert {
        "SRC_IMAP_HOST",
        "SRC_IMAP_USERNAME",
        "SRC_IMAP_PASSWORD",
        "SRC_OAUTH2_CLIENT_ID",
        "SRC_OAUTH2_CLIENT_SECRET",
        "SRC_ACCOUNT_TYPE",
        "BACKUP_LOCAL_PATH",
    } <= required
    assert missing == {"BACKUP_LOCAL_PATH"}


@pytest.mark.parametrize(
    ("operation", "prefixes"),
    (("backup", ("SRC",)), ("restore", ("DEST",)), ("migrate", ("SRC", "DEST")), ("compare", ("SRC", "DEST"))),
)
def test_account_operations_include_all_oauth_configuration(operation, prefixes):
    required, _missing = required_settings(operation, account_values())
    for prefix in prefixes:
        assert {
            f"{prefix}_IMAP_PASSWORD",
            f"{prefix}_OAUTH2_CLIENT_ID",
            f"{prefix}_OAUTH2_CLIENT_SECRET",
            f"{prefix}_ACCOUNT_TYPE",
        } <= required


def test_command_has_options_but_no_credentials():
    command = build_command(
        OPERATION_BY_NAME["migrate"],
        RunOptions("INBOX", 3, 20, "/tmp/cache", {"PRESERVE_FLAGS": True, "DEST_DELETE": False}),
    )
    assert command[:4][-2:] == ["-m", "imap_migrate"]
    assert "--preserve-flags" in command
    assert "--no-dest-delete" in command
    assert command[-1] == "INBOX"


def test_count_and_compare_modes_are_explicit_arguments(tmp_path):
    count = build_command(OPERATION_BY_NAME["count"], RunOptions(target="destination"))
    compare = build_command(
        OPERATION_BY_NAME["compare"],
        RunOptions(source_path=str(tmp_path / "source"), destination_path=str(tmp_path / "destination")),
    )
    assert count[-2:] == ["--target", "destination"]
    assert compare[-4:] == [
        "--src-path",
        str(tmp_path / "source"),
        "--dest-path",
        str(tmp_path / "destination"),
    ]


def test_count_targets_resolve_with_multiple_configured_sources(monkeypatch, tmp_path):
    for prefix, host in (("SRC", "src.example.com"), ("DEST", "dest.example.com")):
        monkeypatch.setenv(f"{prefix}_IMAP_HOST", host)
        monkeypatch.setenv(f"{prefix}_IMAP_USERNAME", prefix.lower())
        monkeypatch.setenv(f"{prefix}_IMAP_PASSWORD", "secret")
    monkeypatch.setenv("BACKUP_LOCAL_PATH", str(tmp_path))

    source_command = build_command(OPERATION_BY_NAME["count"], RunOptions(target="source"))
    destination_command = build_command(OPERATION_BY_NAME["count"], RunOptions(target="destination"))
    local_command = build_command(OPERATION_BY_NAME["count"], RunOptions(target="local"))

    source, source_is_local = parse_count_arguments(source_command[4:])
    destination, destination_is_local = parse_count_arguments(destination_command[4:])
    local, local_is_local = parse_count_arguments(local_command[4:])
    assert (source.host, source_is_local) == ("src.example.com", False)
    assert (destination.host, destination_is_local) == ("dest.example.com", False)
    assert (local.path, local_is_local) == (str(tmp_path), True)


def test_negative_boolean_and_compare_path_commands_match_shared_parsers(monkeypatch, tmp_path):
    monkeypatch.setenv("SRC_IMAP_HOST", "src.example.com")
    monkeypatch.setenv("SRC_IMAP_USERNAME", "source")
    monkeypatch.setenv("SRC_IMAP_PASSWORD", "secret")
    monkeypatch.setenv("DEST_IMAP_HOST", "dest.example.com")
    monkeypatch.setenv("DEST_IMAP_USERNAME", "destination")
    monkeypatch.setenv("DEST_IMAP_PASSWORD", "secret")
    monkeypatch.setenv("BACKUP_LOCAL_PATH", str(tmp_path))
    monkeypatch.setenv("GMAIL_MODE", "true")

    backup_command = build_command(
        OPERATION_BY_NAME["backup"],
        RunOptions(switches={"GMAIL_MODE": False}),
    )
    backup = parse_backup_arguments(backup_command[4:])
    assert "--no-gmail-mode" in backup_command
    assert backup.gmail_mode is False

    source_path = tmp_path / "source"
    source_path.mkdir()
    compare_command = build_command(
        OPERATION_BY_NAME["compare"],
        RunOptions(source_path=str(source_path)),
    )
    compare, source_is_local, destination_is_local = parse_compare_arguments(compare_command[4:])
    assert compare.src_path == str(source_path)
    assert source_is_local is True
    assert destination_is_local is False


def test_output_parser_is_best_effort():
    state = ProgressState()
    parse_output("Progress: 4/10 emails scanned", state)
    parse_output("[INBOX] SAVED | message.eml", state)
    parse_output("[INBOX] SKIP (exists)", state)
    parse_output("[INBOX] FAILED", state)
    parse_output("unfamiliar output remains harmless", state)
    assert (state.current, state.total) == (4, 10)
    assert (state.copied, state.skipped, state.failed) == (1, 1, 1)
