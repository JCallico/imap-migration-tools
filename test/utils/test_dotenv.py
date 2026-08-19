"""Tests for optional dotenv loading and configuration provenance."""

import os

from conftest import temp_env
from utils.dotenv import load_dotenv


def test_load_dotenv_reports_only_added_keys(tmp_path, monkeypatch):
    """Existing OS keys remain authoritative and are not reported as dotenv values."""
    (tmp_path / ".env").write_text('FROM_DOTENV="dotenv"\nSHARED_VALUE="dotenv"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    with temp_env({"SHARED_VALUE": "os"}):
        result = load_dotenv()
        assert os.environ["FROM_DOTENV"] == "dotenv"
        assert os.environ["SHARED_VALUE"] == "os"

    assert result.dotenv_keys == frozenset({"FROM_DOTENV"})
