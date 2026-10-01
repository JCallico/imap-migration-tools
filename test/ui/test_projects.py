"""Tests for the shared project store."""

import errno
import os
import stat
from pathlib import Path

import pytest

import ui.projects as projects_module
from ui.projects import (
    ProjectStore,
    _move_without_replacing,
    _resolve,
    default_projects_dir,
    explicit_env,
    local_env,
    run_environment,
    validate_name,
)


def test_projects_directory_defaults_to_home_and_honors_override(tmp_path, monkeypatch):
    monkeypatch.delenv("IMAP_TOOLS_PROJECTS_DIR")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert default_projects_dir() == tmp_path / ".imap-migration-tools"
    monkeypatch.setenv("IMAP_TOOLS_PROJECTS_DIR", str(tmp_path / "custom"))
    assert default_projects_dir() == tmp_path / "custom"


def test_default_project_always_listed_before_local_and_sorted_named_projects(tmp_path):
    local = tmp_path / "work" / ".env"
    local.parent.mkdir()
    local.touch()
    store = ProjectStore(tmp_path / "projects", local)
    store.create("zeta")
    store.create("Alpha")

    projects = store.projects()

    assert [(project.name, project.kind) for project in projects] == [
        ("default", "default"),
        ("local", "local"),
        ("Alpha", "named"),
        ("zeta", "named"),
    ]
    assert projects[0].path == tmp_path / "projects" / ".env"
    assert projects[2].path == tmp_path / "projects" / "Alpha.env"


def test_local_project_is_hidden_when_it_is_a_project_file(tmp_path):
    store = ProjectStore(tmp_path, tmp_path / ".env")
    assert store.local_project() is None
    named = store.create("acme")
    assert ProjectStore(tmp_path, named.path).local_project() is None


def test_create_writes_owner_only_template_and_never_replaces(tmp_path):
    store = ProjectStore(tmp_path / "projects")
    project = store.create("  acme  ")

    assert project.name == "acme"
    assert 'SRC_IMAP_HOST=""' in project.path.read_text(encoding="utf-8")
    if os.name != "nt":
        assert stat.S_IMODE(project.path.stat().st_mode) == 0o600
        assert stat.S_IMODE(store.root.stat().st_mode) == 0o700
    with pytest.raises(ValueError, match="already exists"):
        store.create("ACME")


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("", "required"),
        ("a" * 61, "60 characters"),
        ("a/b", "cannot contain"),
        ("line\nbreak", "cannot contain"),
        (".hidden", "period"),
        ("Default", "reserved"),
        ("LOCAL", "reserved"),
        ("con", "Windows"),
        ("com1.backup", "Windows"),
    ],
)
def test_invalid_project_names_are_rejected(name, message):
    with pytest.raises(ValueError, match=message):
        validate_name(name)


def test_rename_moves_the_single_file_and_follows_the_remembered_selection(tmp_path):
    store = ProjectStore(tmp_path)
    project = store.create("acme")
    project.path.write_text('SRC_IMAP_HOST="imap.example.com"\n', encoding="utf-8")
    store.remember(project)

    renamed = store.rename(project, "Acme Corp")

    assert not project.path.exists()
    assert renamed.path.read_text(encoding="utf-8") == 'SRC_IMAP_HOST="imap.example.com"\n'
    assert [item.name for item in store.named_projects()] == ["Acme Corp"]
    assert store.remembered() == "Acme Corp"


def test_rename_supports_case_only_change_and_refuses_existing_names(tmp_path):
    store = ProjectStore(tmp_path)
    project = store.create("acme")
    store.create("other")

    assert store.rename(project, "ACME").path.name == "ACME.env"
    with pytest.raises(ValueError, match="already exists"):
        store.rename(store.find("ACME"), "Other")
    assert {item.name for item in store.named_projects()} == {"ACME", "other"}


def test_rename_reports_a_file_removed_by_another_instance(tmp_path):
    store = ProjectStore(tmp_path)
    project = store.create("acme")
    project.path.unlink()
    with pytest.raises(ValueError, match="no longer exists"):
        store.rename(project, "renamed")


def test_default_and_local_projects_cannot_be_renamed_or_deleted(tmp_path):
    local = tmp_path / "work.env"
    local.touch()
    store = ProjectStore(tmp_path / "projects", local)
    for project in (store.default_project(), store.local_project()):
        with pytest.raises(ValueError, match="cannot be renamed"):
            store.rename(project, "other")
        with pytest.raises(ValueError, match="cannot be deleted"):
            store.delete(project)


def test_delete_removes_the_file_and_resets_the_remembered_selection(tmp_path):
    store = ProjectStore(tmp_path)
    project = store.create("acme")
    store.remember(project)

    store.delete(project)
    store.delete(project)

    assert not project.path.exists()
    assert store.remembered() == "default"


def test_initial_project_precedence(tmp_path):
    local = tmp_path / "work" / ".env"
    local.parent.mkdir()
    local.touch()
    store = ProjectStore(tmp_path / "projects", local)
    acme = store.create("acme")

    assert store.initial().name == "local"
    store.remember(acme)
    assert store.initial().name == "acme"
    assert store.initial(project_name="DEFAULT").name == "default"
    assert store.initial(env_path=acme.path) == acme
    assert store.initial(env_path=tmp_path / "other.env").path == tmp_path / "other.env"
    with pytest.raises(ValueError, match="Project not found"):
        store.initial(project_name="missing")

    acme.path.unlink()
    assert store.initial().name == "local"
    assert ProjectStore(tmp_path / "projects").initial().name == "default"


def test_local_and_explicit_env_resolution(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert local_env() is None
    (tmp_path / ".env").touch()
    assert local_env() == (tmp_path / ".env").resolve()
    assert local_env(tmp_path / "chosen.env") == tmp_path / "chosen.env"

    assert explicit_env() is None
    monkeypatch.setenv("IMAP_TOOLS_ENV_FILE", str(tmp_path / "variable.env"))
    assert explicit_env() == tmp_path / "variable.env"
    assert explicit_env(tmp_path / "argument.env") == tmp_path / "argument.env"


def test_run_environment_pins_the_resolved_project_file(tmp_path):
    project = ProjectStore(tmp_path).create("acme")
    assert run_environment(project) == {"IMAP_TOOLS_ENV_FILE": str(project.path.resolve())}


def test_rename_to_the_same_name_is_a_no_op(tmp_path):
    store = ProjectStore(tmp_path)
    project = store.create("acme")
    assert store.rename(project, " acme ") == project
    assert project.path.is_file()


def test_create_reports_a_file_created_concurrently_by_another_instance(tmp_path, monkeypatch):
    store = ProjectStore(tmp_path)
    store.create("acme")
    monkeypatch.setattr(store, "_check_available", lambda *args, **kwargs: None)
    with pytest.raises(ValueError, match="already exists"):
        store.create("acme")


def test_unreadable_or_unwritable_projects_directory_degrades_gracefully(tmp_path, monkeypatch):
    store = ProjectStore(tmp_path / "projects")
    monkeypatch.setattr(Path, "chmod", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("read-only")))
    store.ensure_root()
    assert store.root.is_dir()

    monkeypatch.setattr(Path, "glob", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("unreadable")))
    assert store.named_projects() == []

    blocked = ProjectStore(tmp_path / "file-not-directory")
    blocked.root.write_text("", encoding="utf-8")
    blocked.remember(blocked.default_project())
    assert blocked.remembered() == ""


def test_resolve_falls_back_to_an_absolute_path(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "resolve", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("loop")))
    assert _resolve(tmp_path / "project.env") == (tmp_path / "project.env").absolute()


def test_windows_move_refuses_to_replace_an_existing_project(tmp_path):
    source = tmp_path / "old.env"
    source.write_text("old", encoding="utf-8")
    existing = tmp_path / "taken.env"
    existing.write_text("taken", encoding="utf-8")

    with pytest.raises(ValueError, match="already exists"):
        _move_without_replacing(source, existing, case_only=False, windows=True)
    _move_without_replacing(source, tmp_path / "new.env", case_only=False, windows=True)

    assert existing.read_text(encoding="utf-8") == "taken"
    assert (tmp_path / "new.env").read_text(encoding="utf-8") == "old"


def test_move_falls_back_to_rename_where_hard_links_are_unsupported(tmp_path, monkeypatch):
    def unsupported(*args, **kwargs):
        raise OSError(errno.EPERM, "hard links unsupported")

    monkeypatch.setattr(projects_module.os, "link", unsupported)
    source = tmp_path / "old.env"
    source.write_text("old", encoding="utf-8")
    taken = tmp_path / "taken.env"
    taken.write_text("taken", encoding="utf-8")

    with pytest.raises(ValueError, match="already exists"):
        _move_without_replacing(source, taken, case_only=False, windows=False)
    _move_without_replacing(source, tmp_path / "new.env", case_only=False, windows=False)

    assert not source.exists()
    assert taken.read_text(encoding="utf-8") == "taken"
    assert (tmp_path / "new.env").read_text(encoding="utf-8") == "old"


def test_move_reports_link_races_and_unexpected_errors(tmp_path, monkeypatch):
    source = tmp_path / "old.env"
    source.write_text("old", encoding="utf-8")

    monkeypatch.setattr(projects_module.os, "link", lambda *args: (_ for _ in ()).throw(FileExistsError()))
    with pytest.raises(ValueError, match="already exists"):
        _move_without_replacing(source, tmp_path / "new.env", case_only=False, windows=False)

    monkeypatch.setattr(projects_module.os, "link", lambda *args: (_ for _ in ()).throw(OSError(errno.EIO, "io")))
    with pytest.raises(OSError, match="io"):
        _move_without_replacing(source, tmp_path / "new.env", case_only=False, windows=False)
    assert source.is_file()


def test_remembered_project_ignores_a_windows_byte_order_mark(tmp_path):
    store = ProjectStore(tmp_path)
    store.create("Acme Corp")
    (tmp_path / ".active-project").write_bytes("\ufeffAcme Corp\r\n".encode("utf-8"))

    assert store.remembered() == "Acme Corp"
    assert store.initial().name == "Acme Corp"
