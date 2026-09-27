"""Tests for dotenv loading and configuration provenance."""

import builtins
import os
from pathlib import Path

import pytest

from conftest import temp_env
from utils.dotenv import load_dotenv


def test_source_checkout_without_installed_dependency_is_ignored(monkeypatch):
    """Direct source execution remains usable when runtime dependencies were not installed."""
    real_import = builtins.__import__

    def import_without_dotenv(name, *args, **kwargs):
        if name == "dotenv":
            raise ModuleNotFoundError("No module named 'dotenv'", name="dotenv")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_dotenv)

    assert load_dotenv().dotenv_keys == frozenset()


def test_every_test_starts_behind_dotenv_discovery_boundary():
    """The autouse fixture must move tests outside the repository and create a dotenv boundary."""
    repository_root = Path(__file__).resolve().parents[2]
    isolated_cwd = Path.cwd().resolve()

    assert isolated_cwd != repository_root
    assert repository_root not in isolated_cwd.parents
    assert (isolated_cwd / ".env").is_file()
    assert (isolated_cwd / ".env").stat().st_size == 0


def test_empty_boundary_blocks_parent_repository_dotenv(tmp_path, monkeypatch):
    """Dotenv discovery must not cross the empty boundary into a repository-level file."""
    simulated_repository = tmp_path / "repository"
    boundary = simulated_repository / "isolated-test"
    working_directory = boundary / "work"
    working_directory.mkdir(parents=True)
    (simulated_repository / ".env").write_text(
        'SRC_IMAP_HOST="real.example.com"\nSRC_IMAP_PASSWORD="real-password"\n', encoding="utf-8"
    )
    (boundary / ".env").touch()
    monkeypatch.chdir(working_directory)

    with temp_env({}):
        result = load_dotenv()
        assert "SRC_IMAP_HOST" not in os.environ
        assert "SRC_IMAP_PASSWORD" not in os.environ

    assert result.dotenv_keys == frozenset()


def test_load_dotenv_reports_only_added_keys(tmp_path, monkeypatch):
    """Existing OS keys remain authoritative and are not reported as dotenv values."""
    (tmp_path / ".env").write_text('FROM_DOTENV="dotenv"\nSHARED_VALUE="dotenv"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    with temp_env({"SHARED_VALUE": "os"}):
        result = load_dotenv()
        assert os.environ["FROM_DOTENV"] == "dotenv"
        assert os.environ["SHARED_VALUE"] == "os"

    assert result.dotenv_keys == frozenset({"FROM_DOTENV"})


def test_env_file_variable_loads_exactly_that_file(tmp_path, monkeypatch):
    """A project file replaces discovery, so a working-directory ``.env`` is never merged."""
    (tmp_path / ".env").write_text('FROM_LOCAL="local"\n', encoding="utf-8")
    project = tmp_path / "acme.env"
    project.write_text('FROM_PROJECT="project"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    with temp_env({"IMAP_TOOLS_ENV_FILE": str(project)}):
        result = load_dotenv()
        assert os.environ["FROM_PROJECT"] == "project"
        assert "FROM_LOCAL" not in os.environ

    assert result.dotenv_keys == frozenset({"FROM_PROJECT"})


def test_missing_env_file_variable_stops_instead_of_running_unconfigured(tmp_path):
    with temp_env({"IMAP_TOOLS_ENV_FILE": str(tmp_path / "deleted.env")}):
        with pytest.raises(SystemExit, match="Configuration file not found"):
            load_dotenv()
