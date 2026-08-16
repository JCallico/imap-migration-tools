"""Tests for TUI configuration behavior."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from dotenv import dotenv_values

from tui.config import (
    FIELDS,
    discover_env,
    effective_values,
    read_env,
    render_new_env,
    save_form,
    save_raw,
    validate,
)


def test_rendered_schema_contains_every_supported_field():
    rendered = render_new_env({})
    parsed = dotenv_values(stream=__import__("io").StringIO(rendered))
    assert set(parsed) == {field.name for field in FIELDS}


def test_committed_example_matches_schema():
    parsed = dotenv_values(Path(__file__).resolve().parents[2] / ".env.example")
    assert set(parsed) == {field.name for field in FIELDS}


def test_schema_sections_match_env_example_order():
    sections = list(dict.fromkeys(field.group for field in FIELDS))
    assert sections == [
        "Source Account",
        "Destination Account",
        "OAuth2",
        "Local paths",
        "imap-count aliases",
        "Microsoft account type overrides",
        "Shared options",
        "Migration options",
        "Backup options",
        "Restore options",
        "Advanced OAuth2 endpoints",
    ]


def test_save_form_preserves_comments_and_unknown_keys(tmp_path):
    path = tmp_path / ".env"
    path.write_text("# custom comment\nUNKNOWN=value\nSRC_IMAP_HOST=old\n", encoding="utf-8")

    save_form(path, {"SRC_IMAP_HOST": "imap.example.com", "MAX_WORKERS": "3"})

    content = path.read_text(encoding="utf-8")
    assert "# custom comment" in content
    assert "UNKNOWN=value" in content
    assert read_env(path)["SRC_IMAP_HOST"] == "imap.example.com"
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_raw_save_is_atomic_and_owner_only(tmp_path):
    path = tmp_path / ".env"
    save_raw(path, 'SRC_IMAP_HOST="imap.example.com"\n')
    assert read_env(path) == {"SRC_IMAP_HOST": "imap.example.com"}
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_raw_save_rejects_invalid_syntax(tmp_path):
    path = tmp_path / ".env"
    path.write_text("GOOD=original\n", encoding="utf-8")
    try:
        save_raw(path, "not valid !!!\n")
    except ValueError as exc:
        assert "line 1" in str(exc)
    else:
        raise AssertionError("Invalid syntax was accepted")
    assert path.read_text(encoding="utf-8") == "GOOD=original\n"


def test_discover_env_walks_parents(tmp_path):
    expected = tmp_path / ".env"
    expected.write_text("A=B\n", encoding="utf-8")
    child = tmp_path / "one" / "two"
    child.mkdir(parents=True)
    assert discover_env(child) == expected


def test_effective_precedence(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text("MAX_WORKERS=2\n", encoding="utf-8")
    monkeypatch.setenv("MAX_WORKERS", "6")
    assert effective_values(path)["MAX_WORKERS"].value == "6"
    assert effective_values(path)["MAX_WORKERS"].source == "OS environment"
    assert effective_values(path, {"MAX_WORKERS": "8"})["MAX_WORKERS"].value == "8"


def test_validation_rejects_bad_types_and_placeholders():
    errors = validate({"MAX_WORKERS": "0", "GMAIL_MODE": "perhaps", "SRC_IMAP_PASSWORD": "your-app-password"})
    assert set(errors) == {"MAX_WORKERS", "GMAIL_MODE", "SRC_IMAP_PASSWORD"}
