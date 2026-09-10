"""Native widget interactions and real CLI/IMAP integration."""

import os
import time
from pathlib import Path

import pytest

wx = pytest.importorskip("wx")
if os.name != "nt" and __import__("sys").platform != "darwin" and not os.environ.get("DISPLAY"):
    pytest.skip("Native GUI tests require a display (use xvfb-run on Linux)", allow_module_level=True)

from ui.app import (  # noqa: E402
    DEFAULT_OPERATION_HEIGHT,
    AboutDialog,
    AppearanceDialog,
    HelpDialog,
    KeyboardReferenceDialog,
    Workspace,
)
from ui_core import history  # noqa: E402
from ui_core.appearance import load_appearance  # noqa: E402
from ui_core.config import FIELDS, read_env, save_form  # noqa: E402
from ui_core.operations import OPERATION_BY_NAME  # noqa: E402


@pytest.fixture(scope="module")
def native_app():
    app = wx.App.Get() or wx.App(False)
    yield app


@pytest.fixture
def workspace(native_app, tmp_path, monkeypatch):
    for field in FIELDS:
        monkeypatch.delenv(field.name, raising=False)
    monkeypatch.setenv("PYTHONPATH", str(Path(__file__).resolve().parents[2] / "src"))
    root = tmp_path / "history"
    root.mkdir()
    monkeypatch.setattr(history, "history_dir", lambda: root)
    frame = Workspace(tmp_path / ".env", tmp_path / "layout.json")
    frame.Show()
    wx.Yield()
    yield frame
    if frame.controller.active:
        frame.controller.cancel(force=True)
        wait_for(frame, lambda: not frame.controller.active)
    frame.autosave.Stop()
    frame.Close()
    wx.Yield()


def wait_for(frame, predicate, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        wx.Yield()
        frame.poll()
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError(f"Timed out: {frame.output.GetValue()} / {frame.GetStatusBar().GetStatusText()}")


def click(button):
    event = wx.CommandEvent(wx.EVT_BUTTON.typeId, button.GetId())
    event.SetEventObject(button)
    button.GetEventHandler().ProcessEvent(event)


def test_form_autosaves_and_external_edit_wins(workspace):
    frame = workspace
    frame.controls["MAX_WORKERS"].SetValue("7")
    wait_for(frame, lambda: read_env(frame.env_path).get("MAX_WORKERS") == "7")
    frame.controls["MAX_WORKERS"].SetValue("8")
    save_form(frame.env_path, {"MAX_WORKERS": "9"})
    frame.poll()
    assert frame.controls["MAX_WORKERS"].GetValue() == "9"
    assert not frame.autosave.IsRunning()
    frame.env_path.write_text('MAX_WORKERS="invalid"\n')
    frame.poll()
    assert frame.controls["MAX_WORKERS"].GetValue() == "9"
    assert "not loaded" in frame.GetStatusBar().GetStatusText()


def test_configuration_schema_and_native_password_controls(workspace):
    assert set(workspace.controls) == {field.name for field in FIELDS}
    assert workspace.controls["SRC_IMAP_PASSWORD"].GetWindowStyle() & wx.TE_PASSWORD
    workspace.controls["MAX_WORKERS"].SetValue("0")
    assert not workspace.save_configuration()
    assert "positive" in workspace.GetStatusBar().GetStatusText()


def test_tools_and_configuration_share_readiness_state(workspace):
    workspace.load_form({})
    workspace.select_operation("backup")
    assert "Missing" in workspace.tools.GetString(2)
    assert workspace.labels["SRC_IMAP_HOST"].GetFont().GetWeight() == wx.FONTWEIGHT_BOLD
    assert "required" in workspace.labels["SRC_IMAP_HOST"].GetLabel().lower()


def test_native_theme_has_visual_hierarchy(workspace):
    assert workspace.header.GetBackgroundColour() == workspace.colours["header"]
    assert workspace.output.GetFont().GetFamily() == wx.FONTFAMILY_TELETYPE
    assert workspace.readiness_panel.GetBackgroundColour() != workspace.GetBackgroundColour()
    assert (
        " ".join(workspace.operation_description.GetLabel().split())
        == OPERATION_BY_NAME[workspace.operation].description
    )


def test_native_theme_refreshes_custom_surfaces(workspace, monkeypatch):
    palette = dict(workspace.colours)
    palette.update(
        {
            "background": wx.Colour(20, 21, 22),
            "surface": wx.Colour(30, 31, 32),
            "surface_soft": wx.Colour(40, 41, 42),
            "accent": wx.Colour(80, 120, 200),
            "accent_text": wx.Colour(255, 255, 255),
            "header": wx.Colour(55, 65, 75),
            "header_text": wx.Colour(245, 245, 245),
        }
    )
    monkeypatch.setattr(workspace, "_system_colours", lambda: palette)
    workspace.apply_system_theme()
    assert workspace.GetBackgroundColour() == palette["background"]
    assert workspace.header.GetBackgroundColour() == palette["header"]
    assert workspace.output.GetBackgroundColour() == palette["surface"]
    assert workspace.operation_panel.GetBackgroundColour() == palette["surface_soft"]


def test_header_omits_configuration_filename_and_view_uses_submenus(workspace):
    header_labels = [child.GetLabel() for child in workspace.header.GetChildren() if isinstance(child, wx.StaticText)]
    assert workspace.env_path.name not in header_labels
    assert "Count, compare, backup, restore, and migrate mailboxes with confidence." in header_labels

    view = workspace.GetMenuBar().GetMenu(2)
    labels = [item.GetItemLabelText() for item in view.GetMenuItems() if not item.IsSeparator()]
    assert labels == ["Reset layout", "Zoom", "Transparency", "Appearance…"]
    zoom = next(item.GetSubMenu() for item in view.GetMenuItems() if item.GetItemLabelText() == "Zoom")
    assert [item.GetItemLabelText() for item in zoom.GetMenuItems()] == ["Zoom in", "Zoom out", "Reset zoom"]
    transparency = next(item.GetSubMenu() for item in view.GetMenuItems() if item.GetItemLabelText() == "Transparency")
    assert [item.GetItemLabelText() for item in transparency.GetMenuItems()] == [
        "Increase transparency",
        "Decrease transparency",
        "Reset transparency",
    ]


def test_help_menu_uses_structured_information_dialogs(workspace):
    help_menu = workspace.GetMenuBar().GetMenu(3)
    labels = [item.GetItemLabelText() for item in help_menu.GetMenuItems() if not item.IsSeparator()]
    assert labels == ["Help", "Keyboard Reference", "About"]

    dialogs = [HelpDialog(workspace), KeyboardReferenceDialog(workspace), AboutDialog(workspace)]
    try:
        assert dialogs[0].section_titles == [
            "Configure accounts",
            "Choose and run an operation",
            "Monitor and stop work",
            "Review history",
            "Adjust the workspace",
        ]
        assert ("Ctrl/Cmd+=", "Zoom in") in dialogs[1].shortcut_rows
        assert "Version" in dialogs[2].section_titles
        assert "License" in dialogs[2].section_titles
        assert "Project" not in dialogs[2].section_titles
    finally:
        for dialog in dialogs:
            dialog.Destroy()


def test_window_opacity_is_configurable_and_persistent(workspace, monkeypatch):
    applied = []
    monkeypatch.setattr(workspace, "transparency_supported", lambda: True)
    monkeypatch.setattr(workspace, "SetTransparent", lambda alpha: applied.append(alpha) or True)
    assert workspace.apply_opacity(84)
    assert workspace.opacity == 84
    assert applied == [214]

    from ui_core.appearance import save_appearance

    save_appearance(workspace.settings_path, workspace.opacity, workspace.zoom)
    assert load_appearance(workspace.settings_path) == {"opacity": 84, "zoom": 100}


def test_appearance_settings_screen_exposes_opacity_and_zoom(workspace):
    dialog = AppearanceDialog(workspace, 88, 120, True)
    try:
        assert (dialog.opacity.GetMin(), dialog.opacity.GetMax()) == (70, 100)
        assert (dialog.zoom.GetMin(), dialog.zoom.GetMax()) == (80, 150)
        assert dialog.selected_opacity() == 88
        assert dialog.selected_zoom() == 120
        assert dialog.zoom.GetName() == "Zoom"
        click(dialog.reset_opacity_button)
        click(dialog.reset_zoom_button)
        assert dialog.selected_opacity() == 96
        assert dialog.selected_zoom() == 100
        assert workspace.opacity == 96
        assert workspace.zoom == 100
        assert dialog.GetTitle() == "Appearance"
    finally:
        dialog.Destroy()


def test_zoom_scales_controls_and_can_be_reset(workspace):
    original = workspace.output.GetFont().GetPointSize()
    workspace.apply_zoom(130)
    assert workspace.output.GetFont().GetPointSize() > original
    workspace.reset_zoom()
    assert workspace.zoom == 100
    assert workspace.output.GetFont().GetPointSize() == original
    assert load_appearance(workspace.settings_path)["zoom"] == 100


def test_transparency_menu_commands_adjust_and_reset_opacity(workspace, monkeypatch):
    applied = []
    monkeypatch.setattr(workspace, "transparency_supported", lambda: True)
    monkeypatch.setattr(workspace, "SetTransparent", lambda alpha: applied.append(alpha) or True)
    workspace.apply_opacity(90)
    workspace.increase_transparency()
    assert workspace.opacity == 85
    workspace.decrease_transparency()
    assert workspace.opacity == 90
    workspace.reset_transparency()
    assert workspace.opacity == 96
    assert load_appearance(workspace.settings_path)["opacity"] == 96


def test_destructive_run_requires_confirmation(workspace, monkeypatch):
    workspace.load_form(
        {
            "SRC_IMAP_HOST": "source",
            "SRC_IMAP_USERNAME": "alice",
            "SRC_IMAP_PASSWORD": "secret",
            "DEST_IMAP_HOST": "dest",
            "DEST_IMAP_USERNAME": "bob",
            "DEST_IMAP_PASSWORD": "secret",
            "DELETE_FROM_SOURCE": "true",
        }
    )
    workspace.select_operation("migrate")
    confirmations = []
    monkeypatch.setattr(
        workspace, "confirm", lambda message, required=False: confirmations.append((message, required)) or False
    )
    click(workspace.run_button)
    assert not workspace.controller.active
    assert confirmations[0][1]
    assert "alice@source" in confirmations[0][0]


@pytest.mark.parametrize("operation", ["count", "compare", "backup", "restore", "migrate"])
def test_all_operations_through_native_widgets(workspace, mock_server_factory, monkeypatch, tmp_path, operation):
    source, destination, src_port, dest_port = mock_server_factory(
        {"INBOX": [b"Subject: Desktop test\r\nMessage-ID: <desktop@example.com>\r\n\r\nBody"]}, {"INBOX": []}
    )
    backup = tmp_path / "backup"
    (backup / "INBOX").mkdir(parents=True)
    if operation == "restore":
        (backup / "INBOX" / "one.eml").write_bytes(b"Subject: Restored\r\n\r\nBody")
    values = {
        "SRC_IMAP_HOST": f"imap://localhost:{src_port}",
        "SRC_IMAP_USERNAME": "user",
        "SRC_IMAP_PASSWORD": "pass",
        "DEST_IMAP_HOST": f"imap://localhost:{dest_port}",
        "DEST_IMAP_USERNAME": "user",
        "DEST_IMAP_PASSWORD": "pass",
        "BACKUP_LOCAL_PATH": str(backup),
    }
    workspace.load_form(values)
    assert workspace.save_configuration()
    workspace.select_operation(operation)
    monkeypatch.setattr(workspace, "confirm", lambda *args: True)
    click(workspace.run_button)
    assert workspace.controller.active
    wait_for(workspace, lambda: not workspace.controller.active)
    record = history.load_records()[0]
    assert record.status == "completed"
    assert record.operation == operation
    assert "INBOX" in workspace.output.GetValue()
    if operation in {"restore", "migrate"}:
        assert len(destination.folders["INBOX"]) == 1
    if operation == "backup":
        assert list(backup.rglob("*.eml"))
    workspace.output_filter.SetValue("INBOX")
    wx.Yield()
    assert all("inbox" in line.lower() for line in workspace.output.GetValue().splitlines())


def test_external_history_preserves_selection_and_deletion(workspace, monkeypatch):
    first = history.new_record("count")
    first.status = "completed"
    with_writer = history.HistoryWriter(first, history.Redactor([]))
    with_writer.write("first output")
    with_writer.close()
    workspace.refresh_history()
    assert workspace.selected_run_id == first.run_id
    second = history.new_record("backup")
    writer = history.HistoryWriter(second, history.Redactor([]))
    writer.write("unfinished")
    workspace.refresh_history()
    assert len(workspace.records) == 1
    second.status = "completed"
    writer.close()
    workspace.refresh_history()
    assert workspace.selected_run_id == first.run_id
    monkeypatch.setattr(workspace, "confirm", lambda *args: True)
    workspace.delete_history()
    assert workspace.selected_run_id == second.run_id
    assert "unfinished" in workspace.output.GetValue()


def test_native_layout_and_focus_actions(workspace, native_app):
    workspace.SetSize((900, 700))
    wx.Yield()
    assert workspace.outer.GetSplitMode() == wx.SPLIT_HORIZONTAL
    workspace.SetSize((1250, 850))
    wx.Yield()
    assert workspace.outer.GetSplitMode() == wx.SPLIT_VERTICAL
    workspace.output_filter.SetFocus()
    wx.Yield()
    assert workspace.output_filter.HasFocus() or workspace.output_filter.IsDescendant(wx.Window.FindFocus())
    workspace.upper.SetSashPosition(350)
    assert workspace.upper.GetSashPosition() == 350
    workspace.reset_layout()
    assert workspace.upper.GetSashPosition() == 430
    assert workspace.sidebar.GetSashPosition() == DEFAULT_OPERATION_HEIGHT
    workspace.select_operation("compare")
    wx.Yield()
    run_bottom = workspace.run_button.GetPosition().y + workspace.run_button.GetSize().height
    assert run_bottom <= workspace.operation_panel.GetClientSize().height


def test_export_writes_complete_log_even_when_filtered(workspace, monkeypatch, tmp_path):
    record = history.new_record("count")
    record.status = "completed"
    writer = history.HistoryWriter(record, history.Redactor(["test-secret"]))
    writer.write("INBOX test-secret")
    writer.write("Archive")
    writer.close()
    workspace.refresh_history()
    workspace.output_filter.SetValue("INBOX")
    target = tmp_path / "export.log"

    class ExportDialog:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ShowModal(self):
            return wx.ID_OK

        def GetPath(self):
            return str(target)

    monkeypatch.setattr(wx, "FileDialog", ExportDialog)
    workspace.export_history()
    assert target.read_text() == "INBOX [REDACTED]\nArchive\n"


def test_os_environment_wins_over_saved_form(workspace, monkeypatch):
    monkeypatch.setenv("MAX_WORKERS", "11")
    workspace.controls["MAX_WORKERS"].SetValue("7")
    assert workspace.save_configuration()
    assert read_env(workspace.env_path)["MAX_WORKERS"] == "7"
    assert workspace.values()["MAX_WORKERS"] == "11"
    assert "overrides" in workspace.GetStatusBar().GetStatusText()


def test_force_stop_and_quit_wait_for_cleanup(workspace, monkeypatch):
    calls = []
    workspace.controller.active = True
    monkeypatch.setattr(workspace.controller, "cancel", lambda force=False: calls.append(force))
    monkeypatch.setattr(workspace, "confirm", lambda *args: True)
    workspace.controller.events.put(("force_available", None))
    workspace.poll()
    assert workspace.force_button.IsEnabled()
    click(workspace.force_button)
    assert calls == [True]
    workspace.Close()
    assert workspace.closing
    assert calls == [True, False]
    assert workspace.poller.IsRunning()
    workspace.closing = False
    workspace.controller.active = False
