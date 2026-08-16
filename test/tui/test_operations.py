"""Tests for operation readiness and output parsing."""

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
    assert {"SRC_IMAP_HOST", "SRC_IMAP_USERNAME", "SRC_IMAP_PASSWORD", "BACKUP_LOCAL_PATH"} <= required
    assert missing == {"BACKUP_LOCAL_PATH"}


def test_command_has_options_but_no_credentials():
    command = build_command(
        OPERATION_BY_NAME["migrate"],
        RunOptions("INBOX", 3, 20, "/tmp/cache", {"PRESERVE_FLAGS": True, "DEST_DELETE": False}),
    )
    assert command[:4][-2:] == ["-m", "imap_migrate"]
    assert "--preserve-flags" in command
    assert "--dest-delete" not in command
    assert command[-1] == "INBOX"


def test_output_parser_is_best_effort():
    state = ProgressState()
    parse_output("Progress: 4/10 emails scanned", state)
    parse_output("[INBOX] SAVED | message.eml", state)
    parse_output("[INBOX] SKIP (exists)", state)
    parse_output("[INBOX] FAILED", state)
    parse_output("unfamiliar output remains harmless", state)
    assert (state.current, state.total) == (4, 10)
    assert (state.copied, state.skipped, state.failed) == (1, 1, 1)
