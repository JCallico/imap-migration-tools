"""Native widget interactions and real CLI/IMAP integration."""

import ctypes
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

if sys.platform.startswith("linux"):
    # GTK otherwise prefers the live Wayland session even when pytest-xvfb has
    # replaced DISPLAY, allowing native test windows to reach the desktop.
    os.environ["GDK_BACKEND"] = "x11"
    os.environ.pop("WAYLAND_DISPLAY", None)

wx = pytest.importorskip("wx")
if sys.platform.startswith("linux"):
    pytest_xvfb = pytest.importorskip(
        "pytest_xvfb",
        reason="Native GUI tests require pytest-xvfb on Linux so windows never use the desktop display",
    )
    if pytest_xvfb.xvfb_instance is None:
        pytest.skip(
            "Native GUI tests require Xvfb on Linux so windows never use the desktop display",
            allow_module_level=True,
        )

import gui.app as native_gui  # noqa: E402
from gui.app import (  # noqa: E402
    DEFAULT_OPERATION_HEIGHT,
    AboutDialog,
    AppearanceDialog,
    ConfirmationDialog,
    HelpDialog,
    KeyboardReferenceDialog,
    PaletteChoice,
    PaletteMenuRenderer,
    PaletteSplitter,
    Workspace,
    application_icon_path,
)
from ui import history  # noqa: E402
from ui.appearance import load_appearance  # noqa: E402
from ui.config import FIELDS, read_env, save_form  # noqa: E402
from ui.layout import load_window_size, save_layout  # noqa: E402
from ui.operations import OPERATION_BY_NAME  # noqa: E402
from ui.projects import ProjectStore  # noqa: E402


def test_linux_native_widgets_use_only_the_xvfb_display():
    if not sys.platform.startswith("linux"):
        pytest.skip("Xvfb isolation is Linux-specific")

    assert pytest_xvfb.xvfb_instance is not None
    assert os.environ["GDK_BACKEND"] == "x11"
    assert "WAYLAND_DISPLAY" not in os.environ
    assert os.environ["DISPLAY"] == f":{pytest_xvfb.xvfb_instance.display}"


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
    if wx.Platform != "__WXMAC__":
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


@pytest.mark.skipif(wx.Platform != "__WXMAC__", reason="Cocoa-only test presentation behavior")
def test_macos_workspace_remains_hidden_during_tests(workspace):
    assert not workspace.IsShown()


def test_form_autosaves_and_external_edit_wins(workspace):
    frame = workspace
    frame.controls["MAX_WORKERS"].SetValue("7")
    assert frame.autosave.IsRunning()
    assert frame.save_configuration()
    assert read_env(frame.env_path).get("MAX_WORKERS") == "7"
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


def test_workspace_uses_packaged_android_launcher_artwork(workspace):
    assert application_icon_path().is_file()
    assert workspace._application_icon.IsOk()
    if wx.Platform == "__WXMAC__":
        assert workspace.GetIcon().IsOk()


def test_tools_and_configuration_share_readiness_state(workspace):
    workspace.load_form({})
    workspace.select_operation("backup")
    assert "Missing" in workspace.tools.GetString(2)
    assert workspace.labels["SRC_IMAP_HOST"].GetFont().GetWeight() == wx.FONTWEIGHT_BOLD
    assert "required" in workspace.labels["SRC_IMAP_HOST"].GetLabel().lower()


def test_native_theme_has_visual_hierarchy(workspace):
    assert workspace.header.GetBackgroundColour() == workspace.colours["header"]
    assert workspace.output.GetFont().IsFixedWidth()
    if wx.Platform == "__WXMAC__":
        assert workspace.output.GetFont().GetPointSize() == workspace.output_filter.GetFont().GetPointSize()
    else:
        assert workspace.output.GetFont().GetPointSize() == 10
    assert workspace.readiness_panel.GetBackgroundColour() != workspace.GetBackgroundColour()
    assert all(isinstance(splitter, PaletteSplitter) for splitter in workspace._splitters)
    assert all(splitter._sash_colour == workspace.colours["separator"] for splitter in workspace._splitters)
    assert workspace.history_table.GetWindowStyle() & wx.LC_NO_HEADER
    assert workspace.history_header.GetBackgroundColour() == workspace.colours["accent_soft"]
    assert workspace.history_table.GetBackgroundColour() == workspace.colours["control"]
    assert (
        " ".join(workspace.operation_description.GetLabel().split())
        == OPERATION_BY_NAME[workspace.operation].description
    )


@pytest.mark.skipif(wx.Platform != "__WXMAC__", reason="Cocoa-only splitter metrics")
def test_macos_splitters_have_visible_draggable_sashes(workspace):
    assert all(splitter.GetWindowStyleFlag() & wx.SP_3DSASH for splitter in workspace._splitters)
    assert all(splitter.GetSashSize() > 1 for splitter in workspace._splitters)


def test_native_theme_uses_shared_terminal_dark_and_light_palettes(workspace):
    workspace.apply_theme("dark")
    assert workspace.colours["background"] == wx.Colour("#050505")
    assert workspace.colours["accent"] == wx.Colour("#44DD55")
    assert workspace.output.GetBackgroundColour() == wx.Colour("#0B0D0B")
    assert workspace.header_title.GetFont().IsFixedWidth()
    assert all(splitter.GetBackgroundColour() == workspace.colours["separator"] for splitter in workspace._splitters)

    workspace.apply_theme("light")
    assert workspace.colours["background"] == wx.Colour("#DDE4DA")
    assert workspace.colours["accent"] == wx.Colour("#146B25")
    assert workspace.output.GetForegroundColour() == wx.Colour("#182018")
    assert workspace.labels["SRC_IMAP_HOST"].GetFont().IsFixedWidth()
    assert all(splitter.GetBackgroundColour() == workspace.colours["separator"] for splitter in workspace._splitters)

    workspace.apply_theme("system")


@pytest.mark.skipif(wx.Platform != "__WXMAC__", reason="Cocoa-only native appearance integration")
def test_macos_native_controls_follow_selected_theme(workspace):
    try:
        workspace.apply_theme("dark")
        assert workspace._apply_native_frame_theme()
        assert wx.SystemSettings.GetAppearance().IsDark()

        workspace.apply_theme("light")
        assert workspace._apply_native_frame_theme()
        assert not wx.SystemSettings.GetAppearance().IsDark()
    finally:
        workspace.apply_theme("system")


@pytest.mark.skipif(wx.Platform != "__WXMAC__", reason="Cocoa-only native appearance integration")
def test_macos_open_dialog_follows_system_theme_after_explicit_theme(workspace):
    workspace.apply_theme("system")
    wx.Yield()
    system_theme = "dark" if workspace._system_is_dark() else "light"
    explicit_theme = "light" if system_theme == "dark" else "dark"
    dialog = AppearanceDialog(workspace, 100, 100, True, explicit_theme)
    try:
        workspace.apply_theme(explicit_theme)
        dialog.theme.SetStringSelection("System")
        dialog.preview_theme(workspace)
        for _ in range(4):
            wx.Yield()

        assert workspace.theme == "system"
        assert dialog.GetBackgroundColour() == workspace.colours["surface_soft"]
        assert all(
            child.GetForegroundColour() == workspace.colours["text"]
            for child in dialog.GetChildren()
            if isinstance(child, wx.StaticText)
        )
    finally:
        dialog.Destroy()
        workspace.apply_theme("system")


def test_first_run_defaults_to_system_theme(workspace):
    assert not workspace.settings_path.exists()
    assert workspace.theme == "system"


def test_unknown_native_theme_is_rejected(workspace):
    with pytest.raises(ValueError, match="theme must be one of"):
        workspace.apply_theme("sepia")


def test_system_light_detection_uses_portable_wx_api(workspace, monkeypatch):
    class Appearance:
        @staticmethod
        def IsDark():
            return False

    monkeypatch.setattr(wx.SystemSettings, "GetAppearance", lambda: Appearance())
    monkeypatch.setattr(wx.SystemSettings, "GetColour", lambda role: wx.Colour("#F4F6F2"))
    assert not workspace._system_is_dark()


def test_system_dark_detection_uses_portable_wx_api(workspace, monkeypatch):
    class Appearance:
        @staticmethod
        def IsDark():
            return True

    monkeypatch.setattr(native_gui, "_windows_dark_preference", lambda: None)
    monkeypatch.setattr(wx.SystemSettings, "GetAppearance", lambda: Appearance())
    workspace.apply_theme("system")
    assert workspace._system_is_dark()
    assert workspace.theme == "system"
    assert workspace.colours["background"] == wx.Colour("#050505")


def test_windows_theme_preference_takes_precedence_over_stale_native_colours(workspace, monkeypatch):
    class Appearance:
        @staticmethod
        def IsDark():
            return False

    monkeypatch.setattr(native_gui, "_windows_dark_preference", lambda: True)
    monkeypatch.setattr(wx.SystemSettings, "GetAppearance", lambda: Appearance())
    monkeypatch.setattr(wx.SystemSettings, "GetColour", lambda role: wx.Colour("#FFFFFF"))

    workspace.apply_theme("system")
    assert workspace._system_is_dark()
    assert workspace.colours["background"] == wx.Colour("#050505")


def test_windows_inputs_drop_the_bright_native_client_edge(monkeypatch):
    monkeypatch.setattr(native_gui.os, "name", "nt")
    assert native_gui._input_style(wx.TE_PASSWORD) == wx.TE_PASSWORD | wx.BORDER_NONE
    assert native_gui._choice_type() is PaletteChoice


def test_windows_theme_preference_reads_registry_and_handles_failures(monkeypatch):
    class RegistryKey:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    values = iter((0, 1))
    registry = SimpleNamespace(
        HKEY_CURRENT_USER=object(),
        OpenKey=lambda *args: RegistryKey(),
        QueryValueEx=lambda *args: (next(values), None),
    )
    monkeypatch.setattr(native_gui.os, "name", "nt")
    monkeypatch.setitem(sys.modules, "winreg", registry)

    assert native_gui._windows_dark_preference()
    assert not native_gui._windows_dark_preference()
    registry.OpenKey = lambda *args: (_ for _ in ()).throw(OSError("unavailable"))
    assert native_gui._windows_dark_preference() is None


def test_windows_native_theme_helpers_cover_supported_and_failure_paths(monkeypatch):
    class NativeSetter:
        def __init__(self):
            self.calls = []
            self.result = 0

        def __call__(self, *args):
            self.calls.append(args)
            return self.result

    frame_setter = NativeSetter()
    control_setter = NativeSetter()
    messages = NativeSetter()
    monkeypatch.setattr(native_gui.os, "name", "nt")
    monkeypatch.setattr(sys, "getwindowsversion", lambda: SimpleNamespace(build=22631), raising=False)
    monkeypatch.setattr(
        ctypes,
        "windll",
        SimpleNamespace(
            dwmapi=SimpleNamespace(DwmSetWindowAttribute=frame_setter),
            uxtheme=SimpleNamespace(SetWindowTheme=control_setter),
            user32=SimpleNamespace(SendMessageW=messages),
        ),
        raising=False,
    )

    colours = {
        "frame_border": wx.Colour("#010203"),
        "header": wx.Colour("#040506"),
        "header_text": wx.Colour("#070809"),
    }
    assert native_gui._colourref(wx.Colour("#010203")) == 0x030201
    assert native_gui._set_windows_frame_theme(42, True, colours)
    assert len(frame_setter.calls) == 4
    assert native_gui._set_windows_control_theme(42, True)
    assert control_setter.calls[-1][1] == "DarkMode_Explorer"
    assert messages.calls

    control_setter.result = 1
    assert not native_gui._set_windows_control_theme(42, False)
    assert control_setter.calls[-1][1] == "Explorer"
    frame_setter.result = 1
    assert not native_gui._set_windows_frame_theme(42, False, colours)

    monkeypatch.delattr(ctypes, "windll")
    assert not native_gui._set_windows_frame_theme(42, True, colours)
    assert not native_gui._set_windows_control_theme(42, True)


def test_macos_native_theme_helper_covers_supported_and_failure_paths(monkeypatch):
    calls = []

    class Appearance:
        System = "system"
        Light = "light"
        Dark = "dark"

    class AppearanceResult:
        Ok = "ok"

    app = SimpleNamespace(SetAppearance=lambda appearance: calls.append(appearance) or AppearanceResult.Ok)

    class App:
        @staticmethod
        def Get():
            return app

    App.Appearance = Appearance
    App.AppearanceResult = AppearanceResult
    monkeypatch.setattr(native_gui.wx, "Platform", "__WXMAC__")
    monkeypatch.setattr(native_gui.wx, "App", App)

    assert all(native_gui._set_macos_app_appearance(theme) for theme in ("system", "light", "dark"))
    assert calls == [Appearance.System, Appearance.Light, Appearance.Dark]

    app.SetAppearance = lambda appearance: (_ for _ in ()).throw(RuntimeError("unavailable"))
    assert not native_gui._set_macos_app_appearance("dark")
    monkeypatch.setattr(App, "Get", staticmethod(lambda: SimpleNamespace()))
    assert not native_gui._set_macos_app_appearance("dark")
    monkeypatch.setattr(native_gui.wx, "Platform", "__WXGTK__")
    assert not native_gui._set_macos_app_appearance("dark")


def test_macos_workspace_style_paths_are_platform_selectable(workspace, monkeypatch):
    applied = []
    styled = []
    owned_dialog = wx.Dialog(workspace)
    unrelated_dialog = wx.Dialog(None)
    splitters = []
    try:
        monkeypatch.setattr(native_gui.wx, "Platform", "__WXMAC__")
        monkeypatch.setattr(
            native_gui,
            "_set_macos_app_appearance",
            lambda theme: applied.append(theme) or True,
        )
        monkeypatch.setattr(native_gui.wx, "GetTopLevelWindows", lambda: [owned_dialog, unrelated_dialog])
        monkeypatch.setattr(workspace, "style_dialog", lambda dialog: styled.append(dialog))

        assert workspace._apply_native_frame_theme()
        workspace._style_open_macos_dialogs()
        macos_splitter = workspace._splitter(workspace.shell)
        splitters.append(macos_splitter)

        assert applied == [workspace.theme]
        assert styled == [owned_dialog]
        assert macos_splitter.GetWindowStyleFlag() & wx.SP_3DSASH

        monkeypatch.setattr(native_gui.wx, "Platform", "__WXMSW__")
        monkeypatch.setattr(native_gui.os, "name", "nt")
        windows_splitter = workspace._splitter(workspace.shell)
        splitters.append(windows_splitter)
        assert windows_splitter.GetWindowStyleFlag() & wx.SP_NO_XP_THEME
    finally:
        for splitter in splitters:
            workspace._splitters.remove(splitter)
            splitter.Destroy()
        owned_dialog.Destroy()
        unrelated_dialog.Destroy()


def test_palette_choice_owns_selection_and_theme(workspace):
    choice = PaletteChoice(workspace, choices=["first", "second"])
    workspace.apply_theme("dark")
    choice.apply_palette(workspace.colours)

    assert choice.SetStringSelection("second")
    assert choice.GetSelection() == 1
    assert choice.GetStringSelection() == "second"
    assert choice.GetBackgroundColour() == wx.Colour("#101210")

    choice.SetString(1, "updated")
    assert choice.GetString(1) == "updated"
    assert choice.GetStringSelection() == "updated"

    selected = []
    choice.Bind(native_gui.EVT_PALETTE_CHOICE, lambda event: selected.append(choice.GetSelection()))
    choice._on_key_down(SimpleNamespace(GetKeyCode=lambda: wx.WXK_DOWN, Skip=lambda: None))
    assert selected == [0]

    choice._show_popup()
    assert choice._popup.IsShown()
    assert choice._popup.GetChildren()[0].GetSizer().GetItemCount() == 2
    choice._show_popup()
    second_row = choice._popup.GetChildren()[0].GetChildren()[1]
    second_row.GetEventHandler().ProcessEvent(wx.MouseEvent(wx.EVT_LEFT_DOWN.typeId))
    assert selected == [0, 1]
    choice._popup.Dismiss()
    choice._popup.Destroy()
    choice._popup = None
    choice._on_key_down(SimpleNamespace(GetKeyCode=lambda: wx.WXK_SPACE, Skip=lambda: None))
    assert choice._popup.IsShown()
    choice._popup.Dismiss()
    choice._popup.Destroy()
    choice._popup = None
    assert not choice.SetStringSelection("missing")
    choice._on_key_down(SimpleNamespace(GetKeyCode=lambda: ord("A"), Skip=lambda: selected.append("skipped")))
    assert selected[-1] == "skipped"
    choice.Enable(False)
    choice._show_popup()
    assert choice._popup is None
    choice.Destroy()


def test_all_platforms_use_palette_owned_choices(workspace):
    assert native_gui._choice_type() is PaletteChoice
    assert isinstance(workspace.tools, PaletteChoice)
    assert isinstance(workspace.count_mode, PaletteChoice)


def test_palette_menu_renderer_scopes_terminal_font_and_colours(native_app, monkeypatch):
    renderer = PaletteMenuRenderer()
    font = wx.Font(wx.FontInfo(11).Family(wx.FONTFAMILY_TELETYPE))
    text_colour = wx.Colour("#E8EEE8")
    highlight_colour = wx.Colour("#44DD55")
    separator_colour = wx.Colour("#202520")
    renderer.apply_text_palette(font, text_colour, highlight_colour, separator_colour)
    original_get_font = wx.SystemSettings.GetFont
    original_best_label_colour = native_gui.FM.colourutils.BestLabelColour
    observed = {}

    def inspect_palette(base_renderer, menubar, dc):
        observed["font"] = wx.SystemSettings.GetFont(wx.SYS_DEFAULT_GUI_FONT)
        observed["fallback_font"] = wx.SystemSettings.GetFont(wx.SYS_ANSI_FIXED_FONT)
        observed["text"] = native_gui.FM.colourutils.BestLabelColour(base_renderer.menuBarFaceColour)
        observed["highlight"] = native_gui.FM.colourutils.BestLabelColour(base_renderer.menuBarFocusFaceColour)

    monkeypatch.setattr(native_gui.FM.FMRenderer, "DrawMenuBar", inspect_palette)
    renderer.DrawMenuBar(None, None)

    assert observed["font"].GetNativeFontInfoDesc() == font.GetNativeFontInfoDesc()
    assert observed["font"].GetPointSize() == 11
    assert observed["fallback_font"].IsOk()
    assert observed["text"] == text_colour
    assert observed["highlight"] == highlight_colour
    assert renderer.separator_colour == separator_colour
    restored_font = wx.SystemSettings.GetFont(wx.SYS_DEFAULT_GUI_FONT)
    expected_font = original_get_font(wx.SYS_DEFAULT_GUI_FONT)
    assert restored_font.GetNativeFontInfoDesc() == expected_font.GetNativeFontInfoDesc()
    assert native_gui.FM.colourutils.BestLabelColour is original_best_label_colour


def test_palette_menu_renderer_draws_themed_separator(monkeypatch):
    renderer = PaletteMenuRenderer()
    renderer.separator_colour = wx.Colour("#202520")
    operations = []

    class DrawingContext:
        def SetPen(self, pen):
            operations.append(("pen", pen.GetColour()))

        def DrawLine(self, *coordinates):
            operations.append(("line", coordinates))

    monkeypatch.setattr(native_gui.FM, "DCSaver", lambda dc: object())
    renderer.DrawSeparator(DrawingContext(), 4, 10, 6, 100)

    assert operations[0] == ("pen", renderer.separator_colour)
    assert operations[1][0] == "line"


def test_app_menu_applies_palette_to_top_level_and_nested_items(workspace):
    class MenuItem:
        def __init__(self, submenu=None):
            self.submenu = submenu
            self.font = None
            self.colour = None

        def SetFont(self, font):
            self.font = font

        def SetTextColour(self, colour):
            self.colour = colour

        def GetSubMenu(self):
            return self.submenu

    class Menu:
        def __init__(self, items):
            self.items = items

        def GetMenuItems(self):
            return self.items

    nested_item = MenuItem()
    top_item = MenuItem(Menu([nested_item]))
    menu = Menu([top_item])

    class MenuBar:
        def __init__(self):
            self.background = None
            self.refreshed = False

        def GetFont(self):
            return workspace.GetFont()

        def GetMenuCount(self):
            return 1

        def GetMenu(self, index):
            assert index == 0
            return menu

        def SetBackgroundColour(self, colour):
            self.background = colour

        def Refresh(self):
            self.refreshed = True

    original_bar = workspace.app_menu_bar
    original_renderer = getattr(workspace, "_flat_menu_renderer", None)
    try:
        workspace.app_menu_bar = MenuBar()
        workspace._flat_menu_renderer = PaletteMenuRenderer()
        workspace._style_app_menu()
        assert top_item.colour == workspace.colours["text"]
        assert nested_item.colour == workspace.colours["text"]
        assert workspace.app_menu_bar.background == workspace.colours["header"]
        assert workspace.app_menu_bar.refreshed
    finally:
        workspace.app_menu_bar = original_bar
        if original_renderer is None:
            del workspace._flat_menu_renderer
        else:
            workspace._flat_menu_renderer = original_renderer


def test_windows_frame_theme_is_applied_with_current_palette(workspace, monkeypatch):
    applied = []
    monkeypatch.setattr(native_gui.wx, "Platform", "__WXMSW__")
    monkeypatch.setattr(
        native_gui,
        "_set_windows_frame_theme",
        lambda handle, dark, colours: applied.append((handle, dark, colours["border"])) or True,
    )

    workspace.apply_theme("dark")
    workspace.apply_theme("light")

    assert applied[-2][1:] == (True, wx.Colour("#5E655E"))
    assert applied[-1][1:] == (False, wx.Colour("#4D7154"))


def test_output_status_reflows_when_label_changes(workspace):
    workspace.set_progress_label("completed")
    wx.Yield()

    assert workspace.progress.GetLabel() == "completed"
    assert workspace.progress.GetSize().width >= workspace.progress.GetBestSize().width


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


def test_light_theme_restyles_existing_output_text_background(workspace):
    workspace.lines.extend(["Command: count", "TOTAL 42"])
    workspace.current_run_id = workspace.selected_run_id = "active"
    workspace.apply_theme("dark")
    workspace.apply_theme("light")

    style = wx.TextAttr()
    assert workspace.output.GetStyle(0, style)
    assert style.GetTextColour() == workspace.colours["text"]
    assert style.GetBackgroundColour() == workspace.colours["surface"]


def test_header_omits_configuration_filename_and_view_uses_submenus(workspace):
    header_labels = [child.GetLabel() for child in workspace.header.GetChildren() if isinstance(child, wx.StaticText)]
    assert workspace.env_path.name not in header_labels
    assert "$ count | compare | backup | restore | migrate" in header_labels

    menu_bar = workspace.app_menu_bar or workspace.GetMenuBar()
    view = menu_bar.GetMenu(menu_bar.FindMenu("View"))
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
    menu_bar = workspace.app_menu_bar or workspace.GetMenuBar()
    help_menu = menu_bar.GetMenu(menu_bar.FindMenu("Help"))
    labels = [item.GetItemLabelText() for item in help_menu.GetMenuItems() if not item.IsSeparator()]
    assert labels == ["Help", "Keyboard Reference", "About"]

    dialogs = [HelpDialog(workspace), KeyboardReferenceDialog(workspace), AboutDialog(workspace)]
    try:
        assert dialogs[0].section_titles == [
            "Choose a project",
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


def test_confirmation_dialogs_follow_the_selected_theme(workspace):
    workspace.apply_theme("light")
    dialogs = [
        ConfirmationDialog(workspace, "Continue with this operation?"),
        ConfirmationDialog(workspace, "Delete the selected item?", True),
    ]
    try:
        for dialog in dialogs:
            assert dialog.GetBackgroundColour() == workspace.colours["surface_soft"]
            assert dialog.heading.GetForegroundColour() == workspace.colours["accent_label"]
            assert dialog.message.GetForegroundColour() == workspace.colours["text"]
        assert dialogs[1].entry.GetBackgroundColour() == workspace.colours["control"]
        assert dialogs[1].GetValue() == ""
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

    from ui.appearance import save_appearance

    save_appearance(workspace.settings_path, workspace.opacity, workspace.zoom)
    assert load_appearance(workspace.settings_path) == {"opacity": 84, "zoom": 100, "theme": "system"}


def test_fully_opaque_window_avoids_native_transparency_until_needed(workspace, monkeypatch):
    applied = []
    monkeypatch.setattr(workspace, "transparency_supported", lambda: True)
    monkeypatch.setattr(workspace, "SetTransparent", lambda alpha: applied.append(alpha) or True)

    assert workspace.apply_opacity(100)
    assert applied == []

    workspace.apply_opacity(80)
    workspace.apply_opacity(100)
    assert applied == [204, 255]


def test_appearance_settings_screen_exposes_theme_opacity_and_zoom(workspace):
    dialog = AppearanceDialog(workspace, 88, 120, True, "dark")
    try:
        assert dialog.selected_theme() == "dark"
        assert (dialog.opacity.GetMin(), dialog.opacity.GetMax()) == (70, 100)
        assert (dialog.zoom.GetMin(), dialog.zoom.GetMax()) == (80, 150)
        assert dialog.selected_opacity() == 88
        assert dialog.selected_zoom() == 120
        assert dialog.zoom.GetName() == "Zoom"
        assert dialog.theme.GetName() == "Theme"
        dialog.theme.SetStringSelection("Light")
        dialog.preview_theme(workspace)
        assert workspace.theme == "light"
        click(dialog.reset_opacity_button)
        click(dialog.reset_zoom_button)
        assert dialog.selected_opacity() == 100
        assert dialog.selected_zoom() == 100
        assert workspace.opacity == 100
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
    assert workspace.opacity == 100
    assert load_appearance(workspace.settings_path)["opacity"] == 100


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
    assert all(
        label.GetForegroundColour() == workspace.colours["accent_label"]
        for label in workspace.history_header.GetChildren()
    )
    assert workspace.history_table.GetItemTextColour(0) == workspace.colours["text"]
    assert workspace.history_table.GetItemBackgroundColour(0) == workspace.colours["surface"]
    assert not workspace.history_table.GetItemState(0, wx.LIST_STATE_SELECTED)
    workspace.apply_theme("dark")
    assert workspace.history_table.GetItemBackgroundColour(0) == workspace.colours["surface"]
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
    workspace.apply_responsive_layout(900, 700)
    assert workspace.outer.GetSplitMode() == wx.SPLIT_HORIZONTAL
    workspace.apply_responsive_layout(1250, 850)
    assert workspace.outer.GetSplitMode() == wx.SPLIT_VERTICAL
    assert workspace.output_filter.AcceptsFocus()
    workspace.upper.SetSashPosition(350)
    assert workspace.upper.GetSashPosition() == 350
    workspace.reset_layout()
    assert workspace.upper.GetSashPosition() == 430
    assert abs(workspace.sidebar.GetSashPosition() - DEFAULT_OPERATION_HEIGHT) <= 32
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


def test_unsupported_appearance_and_information_actions(workspace, monkeypatch):
    dialog = AppearanceDialog(workspace, 90, 110, False)
    try:
        assert not dialog.opacity.IsEnabled()
        assert not dialog.reset_opacity_button.IsEnabled()
        assert "unavailable" in " ".join(
            child.GetLabel().lower() for child in dialog.GetChildren() if isinstance(child, wx.StaticText)
        )
    finally:
        dialog.Destroy()

    shown = []

    class Information:
        def __init__(self, parent):
            assert parent is workspace

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def ShowModal(self):
            shown.append(True)

    workspace._show_information(Information)
    actions = []
    monkeypatch.setattr(workspace, "_show_information", lambda dialog_type: actions.append(dialog_type))
    workspace.show_help()
    workspace.show_keyboard_reference()
    workspace.show_about()
    assert shown == [True]
    assert actions == [HelpDialog, KeyboardReferenceDialog, AboutDialog]


def test_appearance_commands_and_dialog_outcomes(workspace, monkeypatch):
    saved = []
    monkeypatch.setattr(
        workspace, "save_appearance_settings", lambda: saved.append((workspace.opacity, workspace.zoom)) or True
    )
    workspace.zoom_in()
    workspace.zoom_out()
    assert workspace.zoom == 100
    assert len(saved) == 2

    def cannot_save(*args):
        raise OSError("read only")

    monkeypatch.setattr(native_gui, "save_appearance", cannot_save)
    assert not native_gui.Workspace.save_appearance_settings(workspace)
    assert "Unable to save appearance" in workspace.GetStatusBar().GetStatusText()

    class AppearanceResult:
        result = wx.ID_CANCEL

        def __init__(self, *args):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def ShowModal(self):
            return self.result

        def selected_opacity(self):
            return 82

        def selected_zoom(self):
            return 120

        def selected_theme(self):
            return "dark"

    monkeypatch.setattr(native_gui, "AppearanceDialog", AppearanceResult)
    original = (workspace.opacity, workspace.zoom, workspace.theme)
    workspace.show_appearance_settings()
    assert (workspace.opacity, workspace.zoom, workspace.theme) == original

    AppearanceResult.result = wx.ID_OK
    monkeypatch.setattr(workspace, "save_appearance_settings", lambda: False)
    workspace.show_appearance_settings()
    assert (workspace.opacity, workspace.zoom, workspace.theme) == original


def test_dialog_and_configuration_error_paths(workspace, monkeypatch):
    class Dialog:
        result = wx.ID_OK
        value = "DELETE"
        path = "/chosen"

        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def ShowModal(self):
            return self.result

        def GetValue(self):
            return self.value

        def GetPath(self):
            return self.path

    monkeypatch.setattr(native_gui, "ConfirmationDialog", Dialog)
    assert workspace.confirm("Delete?", True)
    Dialog.value = "wrong"
    assert not workspace.confirm("Delete?", True)
    Dialog.value = "DELETE"
    Dialog.result = wx.ID_YES
    assert workspace.confirm("Continue?")

    monkeypatch.setattr(wx, "DirDialog", Dialog)
    Dialog.result = wx.ID_OK
    workspace.browse("BACKUP_LOCAL_PATH")
    assert workspace.controls["BACKUP_LOCAL_PATH"].GetValue() == "/chosen"

    workspace.env_path.write_text('MAX_WORKERS="8"\n')
    assert not workspace.save_configuration()
    assert workspace.controls["MAX_WORKERS"].GetValue() == "8"

    monkeypatch.setattr(native_gui, "save_form", lambda *args: (_ for _ in ()).throw(OSError("disk full")))
    assert not workspace.save_configuration()
    assert "disk full" in workspace.GetStatusBar().GetStatusText()


def test_prepare_poll_and_history_error_paths(workspace, monkeypatch):
    workspace.controller.active = True
    workspace.prepare_run()
    workspace.controller.active = False
    monkeypatch.setattr(workspace, "save_configuration", lambda: True)
    monkeypatch.setattr(
        workspace,
        "operation_readiness",
        lambda: SimpleNamespace(ready=False, detail="Not ready"),
    )
    workspace.prepare_run()
    assert workspace.GetStatusBar().GetStatusText() == "Not ready"

    monkeypatch.setattr(
        workspace,
        "operation_readiness",
        lambda: SimpleNamespace(ready=True, detail="Ready"),
    )
    monkeypatch.setattr(native_gui, "make_options", lambda *args: (_ for _ in ()).throw(ValueError("bad workers")))
    workspace.prepare_run()
    assert "positive integers" in workspace.GetStatusBar().GetStatusText()

    workspace.controller.events.put(("warning", "warning detail"))
    monkeypatch.setattr(
        native_gui, "directory_fingerprint", lambda *args: (_ for _ in ()).throw(OSError("history disk"))
    )
    workspace.poll()
    assert "history disk" in workspace.GetStatusBar().GetStatusText()

    monkeypatch.setattr(history, "load_records", lambda: (_ for _ in ()).throw(OSError("unreadable")))
    workspace.records = []
    workspace.refresh_history()
    assert "unreadable" in workspace.GetStatusBar().GetStatusText()

    workspace.selected_run_id = "missing"
    monkeypatch.setattr(history, "read_log", lambda *args: (_ for _ in ()).throw(OSError("missing log")))
    workspace.render_output()
    assert "missing log" in workspace.GetStatusBar().GetStatusText()


def test_history_guard_cancel_and_failure_paths(workspace, monkeypatch, tmp_path):
    workspace.selected_run_id = None
    workspace.export_history()
    workspace.delete_history()

    record = history.new_record("count")
    record.status = "completed"
    workspace.records = [record]
    workspace.selected_run_id = record.run_id
    workspace.current_run_id = record.run_id
    workspace.controller.active = True
    workspace.delete_history()
    assert "active run" in workspace.GetStatusBar().GetStatusText()
    workspace.controller.active = False

    class CancelDialog:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def ShowModal(self):
            return wx.ID_CANCEL

    monkeypatch.setattr(wx, "FileDialog", CancelDialog)
    workspace.export_history()

    class FailingDialog(CancelDialog):
        def ShowModal(self):
            return wx.ID_OK

        def GetPath(self):
            return str(tmp_path / "missing" / "export.log")

    monkeypatch.setattr(wx, "FileDialog", FailingDialog)
    monkeypatch.setattr(history, "read_log", lambda *args: "content")
    workspace.export_history()
    assert "Unable to export" in workspace.GetStatusBar().GetStatusText()

    monkeypatch.setattr(workspace, "confirm", lambda *args: True)
    monkeypatch.setattr(history, "delete_record", lambda *args: (_ for _ in ()).throw(OSError("delete failed")))
    workspace.delete_history()
    assert "delete failed" in workspace.GetStatusBar().GetStatusText()


def test_window_events_and_main_launch(workspace, monkeypatch, tmp_path):
    skipped = []

    class Event:
        def Skip(self):
            skipped.append(True)

        def IsShown(self):
            return True

        def GetSize(self):
            return wx.Size(900, 700)

    applied = []
    monkeypatch.setattr(workspace, "apply_opacity", lambda value: applied.append(value))
    workspace.on_show(Event())
    assert applied == [workspace.opacity]
    responsive = []
    monkeypatch.setattr(workspace, "apply_responsive_layout", lambda: responsive.append(True))
    workspace.on_resize(Event())
    assert responsive == [True]
    assert workspace._last_window_size == (900, 700)
    monkeypatch.setattr(wx, "CallAfter", lambda callback: callback())
    themed = []
    monkeypatch.setattr(workspace, "apply_system_theme", lambda: themed.append(True))
    workspace.on_system_colour_changed(Event())
    assert themed == [True]

    launched = []

    class App:
        def __init__(self, redirect):
            assert not redirect

        def MainLoop(self):
            launched.append("loop")

    class Frame:
        def __init__(self, path, **_kwargs):
            launched.append(path)

        def Show(self):
            launched.append("show")

    monkeypatch.setattr(native_gui.wx, "App", App)
    monkeypatch.setattr(native_gui, "Workspace", Frame)
    native_gui.main(["--env", str(tmp_path / ".env")])
    assert launched == [tmp_path / ".env", "show", "loop"]


def test_window_size_is_saved_and_restored(native_app, tmp_path):
    layout_path = tmp_path / "layout.json"
    save_layout(layout_path, {}, (800, 600))
    frame = Workspace(tmp_path / ".env", layout_path)
    assert tuple(frame.GetSize()) == (800, 600)

    if wx.Platform != "__WXMAC__":
        frame.Show()
    frame.SetSize((840, 640))
    wx.Yield()
    frame.Close()
    wx.Yield()

    assert load_window_size(layout_path) == (840, 640)


@pytest.fixture
def project_workspace(native_app, tmp_path, monkeypatch):
    for field in FIELDS:
        monkeypatch.delenv(field.name, raising=False)
    root = tmp_path / "history"
    root.mkdir()
    monkeypatch.setattr(history, "history_dir", lambda: root)
    store = ProjectStore(tmp_path / "projects")
    store.ensure_root()
    store.default_path.write_text(
        'SRC_IMAP_HOST="default.example.com"\nSRC_IMAP_PASSWORD="default-secret"\nGMAIL_MODE="true"\n',
        encoding="utf-8",
    )
    acme = store.create("acme")
    acme.path.write_text('SRC_IMAP_HOST="acme.example.com"\n', encoding="utf-8")
    frame = Workspace(layout_path=tmp_path / "layout.json", projects=store)
    frame.Show()
    wx.Yield()
    yield frame, store, acme
    frame.autosave.Stop()
    frame.Close()
    wx.Yield()


def test_switching_projects_reloads_the_complete_form_without_merging(project_workspace, monkeypatch):
    frame, store, acme = project_workspace
    assert frame.project.name == "default"
    assert frame.project_choice.GetItems() == ["default", "acme"]
    assert frame.controls["SRC_IMAP_PASSWORD"].HasFlag(wx.TE_PASSWORD)
    assert not frame.project_buttons["rename"].IsEnabled()
    assert frame.project_buttons["rename"].GetForegroundColour() == frame.colours["muted"]
    assert not frame.delete_project_item.IsEnabled()

    frame.project_choice.SetStringSelection("acme")
    frame.on_project_choice()

    assert frame.env_path == acme.path.resolve()
    assert frame.controls["SRC_IMAP_HOST"].GetValue() == "acme.example.com"
    assert frame.controls["SRC_IMAP_PASSWORD"].GetValue() == ""
    assert frame.controls["GMAIL_MODE"].GetValue() is False
    assert frame.GetTitle() == "IMAP Migration Tools — acme"
    assert frame.project_buttons["delete"].IsEnabled()
    assert frame.project_buttons["delete"].GetForegroundColour() == frame.colours["text"]
    assert store.remembered() == "acme"

    started = []
    monkeypatch.setattr(frame.controller, "start", lambda operation, values, request: started.append(request))
    monkeypatch.setattr(frame, "confirm", lambda *args: True)
    frame.controls["SRC_IMAP_USERNAME"].ChangeValue("user")
    frame.controls["SRC_IMAP_PASSWORD"].ChangeValue("acme-secret")
    frame.prepare_run()
    assert started[0].environment["IMAP_TOOLS_ENV_FILE"] == str(acme.path.resolve())
    assert "default-secret" not in acme.path.read_text(encoding="utf-8")


def test_pending_edit_is_saved_to_the_previous_project_and_invalid_edits_block_switching(project_workspace):
    frame, store, acme = project_workspace
    frame.controls["SRC_IMAP_HOST"].SetValue("pending.example.com")
    assert frame.autosave.IsRunning()

    assert frame.switch_project(acme)
    assert read_env(store.default_path)["SRC_IMAP_HOST"] == "pending.example.com"
    assert read_env(acme.path)["SRC_IMAP_HOST"] == "acme.example.com"

    frame.controls["MAX_WORKERS"].SetValue("0")
    assert not frame.switch_project(store.default_project())
    assert frame.project == acme
    assert frame.project_choice.GetStringSelection() == "acme"
    assert "before changing projects" in frame.GetStatusBar().GetStatusText()


def test_create_rename_and_delete_projects(project_workspace, monkeypatch):
    frame, store, _acme = project_workspace
    names = iter(["default", "Client", "Client Renamed"])
    monkeypatch.setattr(frame, "ask_project_name", lambda *args: next(names))

    frame.request_project_name("new")
    assert frame.project.name == "default"
    assert frame.GetStatusBar().GetStatusText() == '"default" is reserved'

    frame.request_project_name("new")
    assert frame.project.name == "Client"
    assert (store.root / "Client.env").is_file()
    frame.controls["SRC_IMAP_HOST"].ChangeValue("client.example.com")
    assert frame.save_configuration()

    frame.request_project_name("rename")
    assert frame.project.name == "Client Renamed"
    assert not (store.root / "Client.env").exists()
    assert frame.controls["SRC_IMAP_HOST"].GetValue() == "client.example.com"

    prompts = []
    monkeypatch.setattr(frame, "confirm", lambda message, require_delete=False: prompts.append(message) or False)
    frame.request_project_deletion()
    assert frame.project.name == "Client Renamed"
    monkeypatch.setattr(frame, "confirm", lambda message, require_delete=False: prompts.append(message) or True)
    frame.request_project_deletion()

    assert "Client Renamed.env" in prompts[0]
    assert frame.project.name == "default"
    assert [project.name for project in store.named_projects()] == ["acme"]


def test_other_instance_changes_refresh_projects_and_protect_a_deleted_active_project(project_workspace):
    frame, store, acme = project_workspace
    frame.switch_project(acme)
    ProjectStore(store.root).create("beta")
    frame.poll()
    assert frame.project_choice.GetItems() == ["default", "acme", "beta"]

    acme.path.unlink()
    frame.poll()
    assert frame.project_choice.GetItems() == ["default", "beta", "acme"]
    assert frame.project_location.GetLabel().endswith("(missing)")
    frame.controls["SRC_IMAP_HOST"].ChangeValue("after-delete.example.com")
    assert not frame.save_configuration()
    assert not acme.path.exists()


def test_main_opens_named_projects_and_rejects_unknown_ones(monkeypatch, tmp_path):
    launched = []

    class App:
        def __init__(self, redirect):
            pass

        def MainLoop(self):
            pass

    class Frame:
        def __init__(self, path, *, projects, project_name):
            launched.append(projects.initial(path, project_name).name)

        def Show(self):
            pass

    ProjectStore().create("acme")
    monkeypatch.setattr(native_gui.wx, "App", App)
    monkeypatch.setattr(native_gui, "Workspace", Frame)
    native_gui.main(["--project", "acme"])
    assert launched == ["acme"]
    with pytest.raises(SystemExit):
        native_gui.main(["--project", "missing"])
    with pytest.raises(SystemExit):
        native_gui.main(["--project", "acme", "--env", str(tmp_path / "other.env")])

    monkeypatch.setenv("IMAP_TOOLS_ENV_FILE", str(tmp_path / "not-created-yet.env"))
    native_gui.main([])
    assert launched == ["acme", "local"]


def test_project_guards_and_name_prompt(project_workspace, monkeypatch):
    frame, store, acme = project_workspace
    frame.request_project_name("rename")
    frame.request_project_deletion()
    assert frame.project.name == "default"

    frame.on_project_choice()
    assert frame.project.name == "default"
    monkeypatch.setattr(frame.project_choice, "GetStringSelection", lambda: "vanished")
    frame.on_project_choice()
    assert frame.GetStatusBar().GetStatusText() == "Project not found: vanished"
    monkeypatch.undo()

    frame.controller.active = True
    assert not frame.switch_project(acme)
    assert "Wait for the current operation" in frame.GetStatusBar().GetStatusText()
    frame.controller.active = False

    assert frame.project_name_entered("new", None) is None
    frame.switch_project(acme)
    monkeypatch.setattr(frame, "confirm", lambda *args: True)
    monkeypatch.setattr(store, "delete", lambda project: (_ for _ in ()).throw(OSError("busy")))
    frame.request_project_deletion()
    assert frame.GetStatusBar().GetStatusText() == "Unable to delete project: busy"
    assert frame.project == acme

    prompts = []

    class Dialog:
        def __init__(self, parent, title, value=""):
            prompts.append((title, value))

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def ShowModal(self):
            return wx.ID_CANCEL if len(prompts) > 1 else wx.ID_OK

        def GetValue(self):
            return "typed"

    monkeypatch.setattr(native_gui, "ProjectNameDialog", Dialog)
    assert frame.ask_project_name("New project") == "typed"
    assert frame.ask_project_name("Rename acme", "acme") is None
    assert prompts == [("New project", ""), ("Rename acme", "acme")]


def test_project_name_dialog_uses_the_application_theme(project_workspace):
    frame, _store, _acme = project_workspace
    dialog = native_gui.ProjectNameDialog(frame, "Rename acme", "acme")
    try:
        assert dialog.GetTitle() == "Rename acme"
        assert dialog.GetValue() == "acme"
        assert dialog.entry.GetName() == "Project name"
        assert dialog.heading.GetForegroundColour() == frame.colours["accent_label"]
        assert dialog.GetBackgroundColour() == frame.colours["surface_soft"]
    finally:
        dialog.Destroy()
