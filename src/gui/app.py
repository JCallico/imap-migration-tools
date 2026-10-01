"""Native desktop workspace for the five IMAP operations."""

from __future__ import annotations

import argparse
import os
import queue
import sys
from collections import deque
from pathlib import Path

import wx
import wx.lib.agw.flatmenu as FM
import wx.lib.scrolledpanel
from platformdirs import user_config_path

from gui.controller import RunController
from ui import history
from ui.appearance import (
    DEFAULT_OPACITY,
    DEFAULT_THEME,
    DEFAULT_ZOOM,
    MAXIMUM_ZOOM,
    MINIMUM_OPACITY,
    MINIMUM_ZOOM,
    THEMES,
    load_appearance,
    save_appearance,
)
from ui.config import FIELDS, discover_env, effective_values, read_env, save_form, validate
from ui.layout import load_layout, load_window_size, save_layout
from ui.operations import OPERATION_BY_NAME, OPERATIONS, account_ready, build_command, readiness
from ui.runner import RunRequest
from ui.workspace import make_options, run_confirmation, validated_form
from utils.dotenv import load_dotenv
from utils.filesystem_watch import directory_fingerprint, file_content_fingerprint
from utils.imap_common import get_version

COMMAND_KEY = "Ctrl"
APPEARANCE_SHORTCUT = f"{COMMAND_KEY}+,"
TRANSPARENCY_STEP = 5
DEFAULT_OPERATION_HEIGHT = 470
DEFAULT_WINDOW_SIZE = (1250, 850)
MINIMUM_WINDOW_SIZE = (720, 520)
APPLICATION_ICON = Path(__file__).with_name("assets") / "imap-tools.png"


def application_icon_path():
    """Return the packaged desktop icon shared with the Android launcher."""
    return APPLICATION_ICON


def _windows_dark_preference():
    """Return the Windows app theme preference, or None off Windows/on failure."""
    if os.name != "nt":
        return None
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        ) as key:
            apps_use_light_theme, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        return not bool(apps_use_light_theme)
    except (ImportError, OSError, ValueError):
        return None


def _input_style(style=0):
    """Remove the bright native client edge from Windows input controls."""
    return style | wx.BORDER_NONE if os.name == "nt" else style


PALETTE_CHOICE_EVENT = wx.NewEventType()
EVT_PALETTE_CHOICE = wx.PyEventBinder(PALETTE_CHOICE_EVENT, 1)


class PaletteChoice(wx.Panel):
    """A read-only selector fully painted with the application palette."""

    def __init__(self, parent, choices=(), style=0, **kwargs):
        super().__init__(parent, style=wx.BORDER_NONE | wx.WANTS_CHARS, **kwargs)
        self._choices = list(choices)
        self._selection = wx.NOT_FOUND
        self._palette = None
        self._popup = None
        self._value = wx.StaticText(self, label="")
        self._arrow = wx.StaticText(self, label="⌄")
        row = wx.BoxSizer(wx.HORIZONTAL)
        row.Add(self._value, 1, wx.ALIGN_CENTER_VERTICAL | wx.LEFT, 6)
        row.Add(self._arrow, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT | wx.RIGHT, 6)
        self.SetSizer(row)
        self.SetMinSize((-1, 24))
        for widget in (self, self._value, self._arrow):
            widget.Bind(wx.EVT_LEFT_DOWN, self._show_popup)
        self.Bind(wx.EVT_KEY_DOWN, self._on_key_down)

    def apply_palette(self, colours):
        """Refresh the selector and its dropdown with semantic colours."""
        self._palette = colours
        self.SetBackgroundColour(colours["control"])
        self.SetForegroundColour(colours["text"])
        self._value.SetBackgroundColour(colours["control"])
        self._value.SetForegroundColour(colours["text"])
        self._arrow.SetBackgroundColour(colours["control"])
        self._arrow.SetForegroundColour(colours["muted"])
        self.Refresh()

    def _show_popup(self, event=None):
        if not self.IsEnabled() or not self._choices:
            return
        if self._popup:
            self._popup.Destroy()
        popup = wx.PopupTransientWindow(wx.GetTopLevelParent(self), wx.BORDER_SIMPLE)
        self._popup = popup
        content = wx.Panel(popup, style=wx.BORDER_NONE)
        rows = wx.BoxSizer(wx.VERTICAL)
        if self._palette:
            popup.SetBackgroundColour(self._palette["input_border"])
            content.SetBackgroundColour(self._palette["input_border"])
        width = max(self.GetSize().width, self.GetBestSize().width)
        item_height = max(24, self.GetCharHeight() + 8)
        height = min(item_height * len(self._choices) + 4, 240)
        popup.SetSize((width, height))
        content.SetSize((width - 2, height - 2))

        def select(index):
            self.SetSelection(index)
            popup.Dismiss()
            self._emit_selection()

        for index, value in enumerate(self._choices):
            row = wx.Panel(content, style=wx.BORDER_NONE)
            label = wx.StaticText(row, label=value)
            row_sizer = wx.BoxSizer(wx.HORIZONTAL)
            row_sizer.Add(label, 1, wx.ALIGN_CENTER_VERTICAL | wx.LEFT | wx.RIGHT, 6)
            row.SetSizer(row_sizer)
            row.SetMinSize((-1, item_height))
            if self._palette:
                background = self._palette["accent_soft"] if index == self._selection else self._palette["control"]
                row.SetBackgroundColour(background)
                label.SetBackgroundColour(background)
                label.SetForegroundColour(
                    self._palette["accent"] if index == self._selection else self._palette["text"]
                )
            row.Bind(wx.EVT_LEFT_DOWN, lambda event, selected=index: select(selected))
            label.Bind(wx.EVT_LEFT_DOWN, lambda event, selected=index: select(selected))
            rows.Add(row, 0, wx.EXPAND)
        content.SetSizer(rows)
        content.Layout()
        popup.Position(self.ClientToScreen((0, self.GetSize().height)), (0, 0))
        popup.Popup()

    def _on_key_down(self, event):
        key = event.GetKeyCode()
        if key in (wx.WXK_SPACE, wx.WXK_RETURN, wx.WXK_NUMPAD_ENTER):
            self._show_popup()
            return
        if key in (wx.WXK_UP, wx.WXK_DOWN) and self._choices:
            offset = -1 if key == wx.WXK_UP else 1
            current = self._selection if self._selection != wx.NOT_FOUND else (0 if offset < 0 else -1)
            self.SetSelection((current + offset) % len(self._choices))
            self._emit_selection()
            return
        event.Skip()

    def _emit_selection(self):
        event = wx.CommandEvent(PALETTE_CHOICE_EVENT, self.GetId())
        event.SetEventObject(self)
        self.ProcessWindowEvent(event)

    def SetSelection(self, selection):
        self._selection = selection if 0 <= selection < len(self._choices) else wx.NOT_FOUND
        self._value.SetLabel(self.GetStringSelection())
        self.Layout()

    def GetSelection(self):
        return self._selection

    def SetStringSelection(self, value):
        try:
            self.SetSelection(self._choices.index(value))
            return True
        except ValueError:
            return False

    def GetStringSelection(self):
        return self._choices[self._selection] if self._selection != wx.NOT_FOUND else ""

    def GetString(self, index):
        return self._choices[index]

    def SetString(self, index, value):
        self._choices[index] = value
        if index == self._selection:
            self._value.SetLabel(value)
            self.Layout()


class PaletteMenuRenderer(FM.FMRenderer):
    """Let FlatMenu's otherwise hard-coded menu-bar text follow our palette."""

    def __init__(self):
        super().__init__()
        self.menu_bar_font = wx.SystemSettings.GetFont(wx.SYS_DEFAULT_GUI_FONT)
        self.menu_bar_text_colour = wx.SystemSettings.GetColour(wx.SYS_COLOUR_MENUTEXT)
        self.menu_bar_highlight_text_colour = self.menu_bar_text_colour
        self.separator_colour = wx.SystemSettings.GetColour(wx.SYS_COLOUR_BTNSHADOW)

    def apply_text_palette(self, font, text_colour, highlight_text_colour, separator_colour):
        """Set the font and semantic colors used for top-level menu titles."""
        self.menu_bar_font = font
        self.menu_bar_text_colour = text_colour
        self.menu_bar_highlight_text_colour = highlight_text_colour
        self.separator_colour = separator_colour

    def DrawSeparator(self, dc, x_coord, y_coord, text_x, separator_width):  # noqa: N802
        """Draw popup-menu separators with the shared muted theme color."""
        dc_saver = FM.DCSaver(dc)
        dc.SetPen(wx.Pen(self.separator_colour))
        y = y_coord + self.separatorHeight // 2
        dc.DrawLine(x_coord + text_x, y, x_coord + text_x + separator_width, y)
        del dc_saver

    def DrawMenuBar(self, menubar, dc):  # noqa: N802 - wxPython renderer API
        """Draw the stock FlatMenu bar with application-owned text styling."""
        original_get_font = wx.SystemSettings.GetFont
        original_best_label_colour = FM.colourutils.BestLabelColour

        def themed_font(role):
            if role == wx.SYS_DEFAULT_GUI_FONT:
                return wx.Font(self.menu_bar_font)
            return original_get_font(role)

        def themed_label_colour(colour, bw=True):
            if colour == self.menuBarFocusFaceColour:
                return self.menu_bar_highlight_text_colour
            return self.menu_bar_text_colour

        wx.SystemSettings.GetFont = themed_font
        FM.colourutils.BestLabelColour = themed_label_colour
        try:
            super().DrawMenuBar(menubar, dc)
        finally:
            wx.SystemSettings.GetFont = original_get_font
            FM.colourutils.BestLabelColour = original_best_label_colour


class PaletteSplitter(wx.SplitterWindow):
    """Native splitter with the application separator palette."""

    def __init__(self, parent, style=0):
        super().__init__(parent, style=style)
        self._sash_colour = None

    def apply_palette(self, colour):
        self._sash_colour = colour
        self.SetBackgroundColour(colour)
        self.Refresh()


def _choice_type():
    """Keep selectors aligned with the selected app theme on every platform."""
    return PaletteChoice


def _bind_choice(control, callback):
    """Bind the selection event emitted by the selected control implementation."""
    control.Bind(EVT_PALETTE_CHOICE if isinstance(control, PaletteChoice) else wx.EVT_CHOICE, callback)


def _is_choice(control):
    return isinstance(control, (wx.Choice, PaletteChoice))


def _colourref(colour):
    """Convert a wx colour to the BGR COLORREF layout used by Win32."""
    return colour.Red() | (colour.Green() << 8) | (colour.Blue() << 16)


def _set_windows_frame_theme(window_handle, dark, colours):
    """Apply supported Windows DWM caption and border colours."""
    if os.name != "nt" or not window_handle:
        return False
    try:
        import ctypes

        setter = ctypes.windll.dwmapi.DwmSetWindowAttribute
        setter.argtypes = (ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint)
        setter.restype = ctypes.c_long
        handle = ctypes.c_void_p(int(window_handle))
        enabled = ctypes.c_int(bool(dark))
        if setter(handle, 20, ctypes.byref(enabled), ctypes.sizeof(enabled)) != 0:
            return False

        if sys.getwindowsversion().build >= 22000:
            for attribute, colour_name in ((34, "frame_border"), (35, "header"), (36, "header_text")):
                colour = ctypes.c_uint(_colourref(colours[colour_name]))
                setter(handle, attribute, ctypes.byref(colour), ctypes.sizeof(colour))
        return True
    except (AttributeError, OSError):
        return False


def _set_windows_control_theme(window_handle, dark):
    """Ask Windows common controls to draw scrollbars for the active theme."""
    if os.name != "nt" or not window_handle:
        return False
    try:
        import ctypes

        setter = ctypes.windll.uxtheme.SetWindowTheme
        setter.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p)
        setter.restype = ctypes.c_long
        handle = ctypes.c_void_p(int(window_handle))
        result = setter(handle, "DarkMode_Explorer" if dark else "Explorer", None)
        ctypes.windll.user32.SendMessageW(handle, 0x031A, 0, 0)  # WM_THEMECHANGED
        return result == 0
    except (AttributeError, OSError):
        return False


HELP_SECTIONS = (
    (
        "Configure accounts",
        "Enter source and destination connection details, authentication, local paths, and operation options. Valid "
        "changes save automatically to the selected .env file; existing operating-system values take precedence.",
    ),
    (
        "Choose and run an operation",
        "Select Count, Compare, Backup, Restore, or Migrate. Review the readiness message, then choose Run. "
        "Destructive operations identify their targets and require typing DELETE before they begin.",
    ),
    (
        "Monitor and stop work",
        "Output streams into the workspace while an operation runs. Cancel requests graceful cleanup; Force stop "
        "becomes available when cleanup takes too long.",
    ),
    (
        "Review history",
        "History is shared with the terminal interface. Select a completed run to view, filter, export, or delete its "
        "redacted log.",
    ),
    (
        "Adjust the workspace",
        "Drag panel dividers to resize them or double-click a divider to reset the layout. View provides layout, "
        "zoom, transparency, and appearance controls.",
    ),
)

KEYBOARD_SECTIONS = (
    ("Operations", (("Alt+1 … Alt+5", "Select Count, Compare, Backup, Restore, or Migrate"), ("F5", "Run"))),
    (
        "Workspace",
        (
            ("Tab / Shift+Tab", "Move focus forward or backward"),
            ("Enter / Space", "Activate the focused control"),
            ("Alt+0", "Reset the panel layout"),
        ),
    ),
    (
        "Appearance",
        (
            ("Ctrl/Cmd+=", "Zoom in"),
            ("Ctrl/Cmd+-", "Zoom out"),
            ("Ctrl/Cmd+0", "Reset zoom"),
            ("Ctrl/Cmd+,", "Open Appearance"),
        ),
    ),
    (
        "Help and window",
        (
            ("F1", "Open Help"),
            ("F2", "Open Keyboard Reference"),
            ("Escape", "Close a dialog"),
            ("F10 / Ctrl+Q", "Quit"),
        ),
    ),
)


def _mix(first, second, weight=0.5):
    """Blend two system colours without assuming a light or dark theme."""
    return wx.Colour(
        round(first.Red() * weight + second.Red() * (1 - weight)),
        round(first.Green() * weight + second.Green() * (1 - weight)),
        round(first.Blue() * weight + second.Blue() * (1 - weight)),
    )


class InformationDialog(wx.Dialog):
    """Scrollable native information window with structured sections."""

    def __init__(self, parent, title, introduction, sections):
        super().__init__(parent, title=title, style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER)
        self.section_titles = []
        self.shortcut_rows = []
        panel = wx.lib.scrolledpanel.ScrolledPanel(self)
        panel.SetBackgroundColour(parent.colours["surface_soft"])
        content = wx.BoxSizer(wx.VERTICAL)
        heading = wx.StaticText(panel, label=title)
        self.heading = heading
        heading.SetFont(wx.Font(wx.FontInfo(round(18 * parent.zoom / 100)).Bold()))
        heading.SetForegroundColour(parent.colours["text"])
        content.Add(heading, 0, wx.BOTTOM, 6)
        introduction_text = wx.StaticText(panel, label=introduction)
        introduction_text.SetForegroundColour(parent.colours["muted"])
        introduction_text.Wrap(560)
        content.Add(introduction_text, 0, wx.EXPAND | wx.BOTTOM, 18)
        for section_title, body in sections:
            self.section_titles.append(section_title)
            label = wx.StaticText(panel, label=section_title)
            label.SetFont(label.GetFont().Bold())
            label.SetForegroundColour(parent.colours["accent_label"])
            content.Add(label, 0, wx.TOP | wx.BOTTOM, 6)
            if isinstance(body, str):
                paragraph = wx.StaticText(panel, label=body)
                paragraph.SetForegroundColour(parent.colours["text"])
                paragraph.Wrap(560)
                content.Add(paragraph, 0, wx.EXPAND | wx.BOTTOM, 8)
            else:
                shortcuts = wx.FlexGridSizer(cols=2, vgap=7, hgap=18)
                shortcuts.AddGrowableCol(1)
                for key, description in body:
                    self.shortcut_rows.append((key, description))
                    key_label = wx.StaticText(panel, label=key)
                    key_label.SetFont(key_label.GetFont().Bold())
                    description_label = wx.StaticText(panel, label=description)
                    shortcuts.Add(key_label, 0, wx.ALIGN_TOP)
                    shortcuts.Add(description_label, 1, wx.EXPAND)
                content.Add(shortcuts, 0, wx.EXPAND | wx.BOTTOM, 10)
        wrapper = wx.BoxSizer(wx.VERTICAL)
        wrapper.Add(content, 1, wx.EXPAND | wx.ALL, 20)
        panel.SetSizer(wrapper)
        panel.SetupScrolling(scroll_x=False)
        dialog_sizer = wx.BoxSizer(wx.VERTICAL)
        dialog_sizer.Add(panel, 1, wx.EXPAND)
        dialog_sizer.Add(self.CreateStdDialogButtonSizer(wx.OK), 0, wx.EXPAND | wx.ALL, 12)
        self.SetSizer(dialog_sizer)
        self.SetSize((640, 560))
        self.SetMinSize((480, 380))
        parent.style_dialog(self)
        panel.SetBackgroundColour(parent.colours["surface_soft"])
        self.heading.SetForegroundColour(parent.colours["accent_label"])
        for label in parent._walk_windows(self):
            if isinstance(label, wx.StaticText) and label.GetLabel() in self.section_titles:
                label.SetForegroundColour(parent.colours["accent_label"])
        self.CentreOnParent()


class HelpDialog(InformationDialog):
    """Task-oriented application help."""

    def __init__(self, parent):
        super().__init__(
            parent,
            "Help",
            "Use one workspace to configure, run, and review every IMAP mailbox operation.",
            HELP_SECTIONS,
        )


class KeyboardReferenceDialog(InformationDialog):
    """Aligned reference for desktop keyboard commands."""

    def __init__(self, parent):
        super().__init__(
            parent,
            "Keyboard Reference",
            "Use these shortcuts from anywhere in the main workspace.",
            KEYBOARD_SECTIONS,
        )


class AboutDialog(InformationDialog):
    """Application identity and project information."""

    def __init__(self, parent):
        super().__init__(
            parent,
            "About IMAP Migration Tools",
            "A native desktop workspace for reliable IMAP mailbox operations.",
            (
                ("Version", get_version()),
                ("Operations", "Count, Compare, Backup, Restore, and Migrate share one tested operation core."),
                (
                    "Privacy and safety",
                    "Credentials stay in the configured environment, sensitive output is redacted, and destructive "
                    "operations require explicit confirmation.",
                ),
                ("License", "Open source under the MIT License."),
            ),
        )


class ConfirmationDialog(wx.Dialog):
    """Compact confirmation surface fully owned by the application theme."""

    def __init__(self, parent, message, require_delete=False):
        title = "Confirm deletion" if require_delete else "Confirm"
        super().__init__(parent, title=title, style=wx.DEFAULT_DIALOG_STYLE)
        self.entry = None
        content = wx.BoxSizer(wx.VERTICAL)
        self.heading = wx.StaticText(self, label=title)
        self.heading.SetFont(wx.Font(wx.FontInfo(14).Family(wx.FONTFAMILY_TELETYPE).Bold()))
        content.Add(self.heading, 0, wx.BOTTOM, 10)
        self.message = wx.StaticText(self, label=message)
        self.message.Wrap(440)
        content.Add(self.message, 0, wx.EXPAND | wx.BOTTOM, 14)
        if require_delete:
            instruction = wx.StaticText(self, label="Type DELETE to continue.")
            instruction.SetFont(instruction.GetFont().Bold())
            content.Add(instruction, 0, wx.BOTTOM, 6)
            self.entry, entry_box = parent._input_box(
                self,
                wx.TextCtrl,
                style=_input_style(),
                track_border=False,
            )
            self.entry.SetName("Deletion confirmation")
            if entry_box is not self.entry:
                entry_box.SetBackgroundColour(parent.colours["input_border"])
            content.Add(entry_box, 0, wx.EXPAND | wx.BOTTOM, 14)
        buttons = wx.BoxSizer(wx.HORIZONTAL)
        buttons.AddStretchSpacer()
        cancel = wx.Button(self, wx.ID_CANCEL, "Cancel")
        affirmative_id = wx.ID_OK if require_delete else wx.ID_YES
        affirmative = wx.Button(self, affirmative_id, "Delete" if require_delete else "Continue")
        cancel.SetDefault()
        cancel.Bind(wx.EVT_BUTTON, lambda event: self.EndModal(wx.ID_CANCEL))
        affirmative.Bind(wx.EVT_BUTTON, lambda event: self.EndModal(affirmative_id))
        buttons.Add(cancel)
        buttons.Add(affirmative, 0, wx.LEFT, 8)
        content.Add(buttons, 0, wx.EXPAND)
        wrapper = wx.BoxSizer(wx.VERTICAL)
        wrapper.Add(content, 1, wx.EXPAND | wx.ALL, 20)
        self.SetSizerAndFit(wrapper)
        self.SetMinSize((480, self.GetSize().height))
        parent.style_dialog(self)
        self.heading.SetForegroundColour(parent.colours["accent_label"])
        if self.entry:
            self.entry.SetFocus()
        self.CentreOnParent()

    def GetValue(self):  # noqa: N802 - mirrors wx.TextEntryDialog
        return self.entry.GetValue() if self.entry else ""


class AppearanceDialog(wx.Dialog):
    """Native appearance dialog with live transparency and zoom previews."""

    def __init__(self, parent, opacity, zoom, supported, theme=DEFAULT_THEME):
        super().__init__(parent, title="Appearance", style=wx.DEFAULT_DIALOG_STYLE)
        self.original_opacity = opacity
        self.original_zoom = zoom
        self.original_theme = theme
        content = wx.BoxSizer(wx.VERTICAL)
        title = wx.StaticText(self, label="Appearance")
        title.SetFont(wx.Font(wx.FontInfo(14).Bold()))
        content.Add(title, 0, wx.BOTTOM, 5)
        detail = wx.StaticText(
            self,
            label="Choose a terminal-inspired theme, transparency, and zoom.",
        )
        content.Add(detail, 0, wx.BOTTOM, 16)
        theme_label = wx.StaticText(self, label="Theme")
        theme_label.SetFont(theme_label.GetFont().Bold())
        content.Add(theme_label, 0, wx.BOTTOM, 6)
        self.theme, self.theme_box = parent._input_box(
            self,
            _choice_type(),
            choices=[name.title() for name in THEMES],
            style=_input_style(),
            track_border=False,
        )
        self.theme.SetStringSelection(theme.title())
        self.theme.SetName("Theme")
        self.theme.SetToolTip("Follow the operating system or select a light or dark application theme")
        _bind_choice(self.theme, lambda event: self.preview_theme(parent))
        content.Add(self.theme_box, 0, wx.EXPAND | wx.BOTTOM, 16)
        label = wx.StaticText(self, label="Window opacity")
        label.SetFont(label.GetFont().Bold())
        content.Add(label, 0, wx.BOTTOM, 6)
        self.opacity = wx.Slider(
            self,
            value=opacity,
            minValue=MINIMUM_OPACITY,
            maxValue=100,
            style=wx.SL_HORIZONTAL | wx.SL_LABELS,
        )
        self.opacity.SetName("Window opacity")
        self.opacity.SetToolTip("70% is most transparent; 100% is fully opaque")
        self.opacity.Enable(supported)
        self.opacity.Bind(wx.EVT_SLIDER, lambda event: parent.apply_opacity(self.opacity.GetValue()))
        content.Add(self.opacity, 0, wx.EXPAND | wx.BOTTOM, 6)
        self.reset_opacity_button = wx.Button(self, label=f"Reset opacity to {DEFAULT_OPACITY}%")
        self.reset_opacity_button.Enable(supported)
        self.reset_opacity_button.Bind(wx.EVT_BUTTON, lambda event: self.reset_opacity(parent))
        content.Add(self.reset_opacity_button, 0, wx.ALIGN_RIGHT | wx.BOTTOM, 10)
        if not supported:
            unsupported = wx.StaticText(
                self,
                label="Window transparency is unavailable with the current desktop compositor.",
            )
            unsupported.SetForegroundColour(parent.colours["warning"])
            content.Add(unsupported, 0, wx.BOTTOM, 8)
        zoom_label = wx.StaticText(self, label="Zoom")
        zoom_label.SetFont(zoom_label.GetFont().Bold())
        content.Add(zoom_label, 0, wx.TOP | wx.BOTTOM, 6)
        self.zoom = wx.Slider(
            self,
            value=zoom,
            minValue=MINIMUM_ZOOM,
            maxValue=MAXIMUM_ZOOM,
            style=wx.SL_HORIZONTAL | wx.SL_LABELS,
        )
        self.zoom.SetName("Zoom")
        self.zoom.SetToolTip("Scale text and native controls from 80% to 150%")
        self.zoom.Bind(wx.EVT_SLIDER, lambda event: parent.apply_zoom(self.zoom.GetValue()))
        content.Add(self.zoom, 0, wx.EXPAND | wx.BOTTOM, 6)
        self.reset_zoom_button = wx.Button(self, label=f"Reset zoom to {DEFAULT_ZOOM}%")
        self.reset_zoom_button.Bind(wx.EVT_BUTTON, lambda event: self.reset_zoom(parent))
        content.Add(self.reset_zoom_button, 0, wx.ALIGN_RIGHT | wx.BOTTOM, 10)
        buttons = self.CreateStdDialogButtonSizer(wx.OK | wx.CANCEL)
        content.Add(buttons, 0, wx.EXPAND | wx.TOP, 10)
        wrapper = wx.BoxSizer(wx.VERTICAL)
        wrapper.Add(content, 1, wx.EXPAND | wx.ALL, 20)
        self.SetSizerAndFit(wrapper)
        self.SetMinSize((440, self.GetSize().height))
        parent.style_dialog(self)
        self._style_input_border(parent)

    def _style_input_border(self, parent):
        """Keep the appearance selector outline on the shared input token."""
        if self.theme_box is not self.theme:
            self.theme_box.SetBackgroundColour(parent.colours["input_border"])

    def selected_theme(self):
        """Return the application theme currently selected in the dialog."""
        return self.theme.GetStringSelection().lower()

    def selected_opacity(self):
        """Return the opacity currently selected in the dialog."""
        return self.opacity.GetValue()

    def selected_zoom(self):
        """Return the zoom currently selected in the dialog."""
        return self.zoom.GetValue()

    def preview_theme(self, parent):
        """Preview the selected theme in the workspace and this dialog."""
        parent.apply_theme(self.selected_theme())
        parent.style_dialog(self)
        self._style_input_border(parent)

    def reset_opacity(self, parent):
        """Restore and preview the default window opacity."""
        self.opacity.SetValue(DEFAULT_OPACITY)
        parent.apply_opacity(DEFAULT_OPACITY)

    def reset_zoom(self, parent):
        """Restore and preview the default zoom."""
        self.zoom.SetValue(DEFAULT_ZOOM)
        parent.apply_zoom(DEFAULT_ZOOM)


class Workspace(wx.Frame):
    """Native widgets bound to shared configuration and operation behavior."""

    def __init__(self, env_path=None, layout_path=None, controller=None, settings_path=None):
        layout_path = Path(layout_path or user_config_path("imap-migration-tools", "CallicoCode") / "gui-layout.json")
        saved_size = load_window_size(layout_path)
        window_size = (
            tuple(max(saved, minimum) for saved, minimum in zip(saved_size, MINIMUM_WINDOW_SIZE))
            if saved_size
            else DEFAULT_WINDOW_SIZE
        )
        super().__init__(None, title="IMAP Migration Tools", size=window_size)
        icon_path = application_icon_path()
        if icon_path.is_file():
            icon = wx.Icon()
            icon.CopyFromBitmap(wx.Bitmap(str(icon_path), wx.BITMAP_TYPE_PNG))
            if icon.IsOk():
                self._application_icon = icon
                self.SetIcon(icon)
        self.env_path = Path(env_path or discover_env()).resolve()
        self.working_directory = self.env_path.parent
        self.layout_path = layout_path
        self.settings_path = Path(settings_path or Path(self.layout_path).with_name("gui-settings.json"))
        appearance = load_appearance(self.settings_path)
        self.opacity = appearance.get("opacity", DEFAULT_OPACITY)
        self._transparency_applied = False
        self.zoom = appearance.get("zoom", DEFAULT_ZOOM)
        self.theme = appearance.get("theme", DEFAULT_THEME)
        self._base_font_sizes = {}
        self._theme_text = []
        self._theme_muted = []
        self._theme_accent_labels = []
        self._theme_rules = []
        self._theme_input_borders = []
        self.history_header = None
        self._splitters = []
        self.controller = controller or RunController()
        self.operation = "count"
        self.controls = {}
        self.labels = {}
        self.label_colours = {}
        self.lines = deque(maxlen=5000)
        self.current_run_id = None
        self.selected_run_id = None
        self.records = []
        self.closing = False
        self.compact = False
        self.loading = True
        self._last_window_size = window_size
        self.digest = file_content_fingerprint(self.env_path)
        self.rejected_digest = None
        self.history_digest = None
        self.colours = self._system_colours()
        self.SetBackgroundColour(self.colours["background"])
        self.CreateStatusBar()
        self._build_menu()
        self._build_workspace()
        self.apply_system_theme()
        self._capture_base_fonts()
        self.load_form(read_env(self.env_path))
        self.loading = False
        self.autosave = wx.Timer(self)
        self.poller = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self.save_configuration, self.autosave)
        self.Bind(wx.EVT_TIMER, self.poll, self.poller)
        self.Bind(wx.EVT_CLOSE, self.on_close)
        self.Bind(wx.EVT_SIZE, self.on_resize)
        self.Bind(wx.EVT_SHOW, self.on_show)
        self.Bind(wx.EVT_SYS_COLOUR_CHANGED, self.on_system_colour_changed)
        self.poller.Start(100)
        self.restore_layout()
        self.apply_opacity(self.opacity)
        self.apply_zoom(self.zoom)
        self.select_operation("count")
        self.refresh_history()
        self.SetMinSize(MINIMUM_WINDOW_SIZE)
        self.SetStatusText(f"Configuration: {self.env_path}")

    def _build_menu(self):
        self._menu_accelerators = []
        flat = os.name == "nt"
        menu_type = FM.FlatMenu if flat else wx.Menu
        bar = FM.FlatMenuBar(self, options=FM.FM_OPT_IS_LCD) if flat else wx.MenuBar()
        file_menu = menu_type()
        self._menu_action(file_menu, "Export selected log…", self.export_history)
        file_menu.AppendSeparator()
        self._menu_action(file_menu, "Quit\tCtrl+Q", self.Close, wx.ID_EXIT)
        bar.Append(file_menu, "&File")
        tools = menu_type()
        for index, operation in enumerate(OPERATIONS, 1):
            self._menu_action(
                tools, f"{operation.title}\tAlt+{index}", lambda name=operation.name: self.select_operation(name)
            )
        self._menu_action(tools, "Run\tF5", self.prepare_run)
        bar.Append(tools, "&Operations")
        view = menu_type()
        self._menu_action(view, "Reset layout\tAlt+0", self.reset_layout)
        view.AppendSeparator()
        zoom = menu_type()
        self._menu_action(zoom, f"Zoom in\t{COMMAND_KEY}+=", self.zoom_in)
        self._menu_action(zoom, f"Zoom out\t{COMMAND_KEY}+-", self.zoom_out)
        self._menu_action(zoom, f"Reset zoom\t{COMMAND_KEY}+0", self.reset_zoom)
        view.AppendSubMenu(zoom, "Zoom")
        transparency = menu_type()
        self._menu_action(transparency, "Increase transparency", self.increase_transparency)
        self._menu_action(transparency, "Decrease transparency", self.decrease_transparency)
        self._menu_action(transparency, "Reset transparency", self.reset_transparency)
        view.AppendSubMenu(transparency, "Transparency")
        view.AppendSeparator()
        self._menu_action(
            view,
            f"Appearance…\t{APPEARANCE_SHORTCUT}",
            self.show_appearance_settings,
        )
        bar.Append(view, "&View")
        help_menu = menu_type()
        self._menu_action(help_menu, "Help\tF1", self.show_help, wx.ID_HELP)
        self._menu_action(help_menu, "Keyboard Reference\tF2", self.show_keyboard_reference)
        help_menu.AppendSeparator()
        self._menu_action(help_menu, "About", self.show_about)
        bar.Append(help_menu, "&Help")
        if flat:
            self.app_menu_bar = bar
            self._flat_menu_renderer = PaletteMenuRenderer()
            self._flat_menu_theme = FM.FMRendererMgr().AddRenderer(self._flat_menu_renderer)
            FM.FMRendererMgr().SetTheme(self._flat_menu_theme)
        else:
            self.app_menu_bar = None
            self.SetMenuBar(bar)
        quit_id = wx.NewIdRef()
        self.Bind(wx.EVT_MENU, lambda event: self.Close(), id=int(quit_id))
        self._menu_accelerators.append((wx.ACCEL_NORMAL, wx.WXK_F10, int(quit_id)))
        self.SetAcceleratorTable(wx.AcceleratorTable(self._menu_accelerators))

    def _menu_action(self, menu, label, action, item_id=wx.ID_ANY):
        item = menu.Append(item_id, label)
        self.Bind(wx.EVT_MENU, lambda event: action(), id=item.GetId())
        if "\t" in label:
            entry = wx.AcceleratorEntry()
            if entry.FromString(label):
                self._menu_accelerators.append((entry.GetFlags(), entry.GetKeyCode(), item.GetId()))
        return item

    def _show_information(self, dialog_type):
        with dialog_type(self) as dialog:
            dialog.ShowModal()

    def show_help(self):
        self._show_information(HelpDialog)

    def show_keyboard_reference(self):
        self._show_information(KeyboardReferenceDialog)

    def show_about(self):
        self._show_information(AboutDialog)

    def transparency_supported(self):
        """Return whether the current window manager supports native opacity."""
        return bool(self.CanSetTransparent())

    def _walk_windows(self, parent):
        """Yield every descendant window so interface zoom remains consistent."""
        for child in parent.GetChildren():
            yield child
            yield from self._walk_windows(child)

    def _capture_base_fonts(self):
        """Remember native font sizes before applying a user scale."""
        for window in (self, *self._walk_windows(self)):
            size = window.GetFont().GetPointSize()
            if size > 0:
                self._base_font_sizes[window] = size

    def apply_zoom(self, zoom):
        """Scale native control fonts and reflow panels."""
        self.zoom = max(MINIMUM_ZOOM, min(MAXIMUM_ZOOM, int(zoom)))
        for window, base_size in tuple(self._base_font_sizes.items()):
            if window and not window.IsBeingDeleted():
                font = window.GetFont()
                font.SetPointSize(max(7, round(base_size * self.zoom / 100)))
                window.SetFont(font)
                window.InvalidateBestSize()
        if hasattr(self, "operation_description"):
            self.operation_description.SetLabel(OPERATION_BY_NAME[self.operation].description)
            self.operation_description.Wrap(max(180, self.operation_panel.GetClientSize().width - 32))
            self.refresh_readiness()
            self.config_panel.FitInside()
            self.operation_panel.FitInside()
            self._style_app_menu()
            self.Layout()

    def change_zoom(self, amount):
        """Move to the next ten-percent zoom step and save it."""
        target = max(MINIMUM_ZOOM, min(MAXIMUM_ZOOM, round((self.zoom + amount) / 10) * 10))
        self.apply_zoom(target)
        self.save_appearance_settings()

    def zoom_in(self):
        self.change_zoom(10)

    def zoom_out(self):
        self.change_zoom(-10)

    def reset_zoom(self):
        self.apply_zoom(DEFAULT_ZOOM)
        self.save_appearance_settings()

    def change_transparency(self, amount):
        """Adjust transparency by a percentage-point step and persist it."""
        self.apply_opacity(self.opacity - amount)
        self.save_appearance_settings()

    def increase_transparency(self):
        self.change_transparency(TRANSPARENCY_STEP)

    def decrease_transparency(self):
        self.change_transparency(-TRANSPARENCY_STEP)

    def reset_transparency(self):
        self.apply_opacity(DEFAULT_OPACITY)
        self.save_appearance_settings()

    def apply_opacity(self, opacity):
        """Apply an opacity percentage when supported by the desktop."""
        self.opacity = max(MINIMUM_OPACITY, min(100, int(opacity)))
        if self.transparency_supported():
            # On Windows, enabling the layered-window path can remain visibly
            # translucent under RDP even when wx is given an alpha of 255.
            # Leave a fresh, fully opaque window on the native default path.
            if self.opacity < 100:
                self.SetTransparent(round(255 * self.opacity / 100))
                self._transparency_applied = True
            elif self._transparency_applied:
                self.SetTransparent(255)
                self._transparency_applied = False
            return True
        return False

    def save_appearance_settings(self):
        """Persist the current appearance without interrupting the workspace."""
        try:
            save_appearance(self.settings_path, self.opacity, self.zoom, self.theme)
            self.SetStatusText(
                f"Appearance saved: {self.theme.title()} theme, {self.opacity}% opacity, {self.zoom}% zoom"
            )
            return True
        except (OSError, ValueError) as exc:
            self.SetStatusText(f"Unable to save appearance settings: {exc}")
            return False

    def show_appearance_settings(self):
        """Preview and persist native desktop appearance settings."""
        original = self.opacity
        original_zoom = self.zoom
        original_theme = self.theme
        with AppearanceDialog(self, original, original_zoom, self.transparency_supported(), original_theme) as dialog:
            if dialog.ShowModal() != wx.ID_OK:
                self.apply_opacity(original)
                self.apply_zoom(original_zoom)
                self.apply_theme(original_theme)
                return
            selected = dialog.selected_opacity()
            selected_zoom = dialog.selected_zoom()
            selected_theme = dialog.selected_theme()
            self.apply_opacity(selected)
            self.apply_zoom(selected_zoom)
            self.apply_theme(selected_theme)
            if not self.save_appearance_settings():
                self.apply_opacity(original)
                self.apply_zoom(original_zoom)
                self.apply_theme(original_theme)

    def on_show(self, event):
        """Reapply compositor-dependent settings once the native window exists."""
        event.Skip()
        if event.IsShown():
            self.apply_opacity(self.opacity)
            self._apply_native_frame_theme()

    def on_system_colour_changed(self, event):
        """Refresh System mode after GTK or another native theme changes."""
        event.Skip()
        if self.theme == "system":
            wx.CallAfter(self.apply_system_theme)

    def _system_is_dark(self):
        """Return the best available indication of the operating-system theme."""
        windows_preference = _windows_dark_preference()
        if windows_preference is not None:
            return windows_preference
        appearance = wx.SystemSettings.GetAppearance()
        if appearance.IsDark():
            return True
        background = wx.SystemSettings.GetColour(wx.SYS_COLOUR_WINDOW)
        return (background.Red() + background.Green() + background.Blue()) / 3 < 128

    def _system_colours(self):
        """Build the TUI palette for the selected or operating-system theme."""
        dark = self.theme == "dark" or (self.theme == "system" and self._system_is_dark())
        values = (
            {
                "background": "#050505",
                "surface": "#0B0D0B",
                "surface_soft": "#141714",
                "control": "#101210",
                "text": "#E5E5E5",
                "muted": "#929892",
                "accent": "#44DD55",
                "accent_label": "#44DD55",
                "accent_soft": "#17351B",
                "accent_text": "#050505",
                "header": "#0B0D0B",
                "header_text": "#44DD55",
                "border": "#5E655E",
                "separator": "#202520",
                "input_border": "#252A25",
                "frame_border": "#050505",
                "success": "#44DD55",
                "warning": "#E6D84A",
                "danger": "#FF6B6B",
            }
            if dark
            else {
                "background": "#DDE4DA",
                "surface": "#FCFDF9",
                "surface_soft": "#F4F6F2",
                "control": "#FFFFFF",
                "text": "#182018",
                "muted": "#536053",
                "accent": "#146B25",
                "accent_label": "#146B25",
                "accent_soft": "#DCEBDD",
                "accent_text": "#FFFFFF",
                "header": "#F4F6F2",
                "header_text": "#146B25",
                "border": "#4D7154",
                "separator": "#D2D9CF",
                "input_border": "#C7CEC4",
                "frame_border": "#AEB8AB",
                "success": "#146B25",
                "warning": "#756800",
                "danger": "#B3261E",
            }
        )
        return {name: wx.Colour(value) for name, value in values.items()}

    def apply_theme(self, theme):
        """Apply one of the validated application theme preferences."""
        if theme not in THEMES:
            raise ValueError(f"theme must be one of: {', '.join(THEMES)}")
        self.theme = theme
        self.apply_system_theme()

    def _style_controls(self, parent):
        """Apply semantic colours while retaining each platform's native controls."""
        for widget in self._walk_windows(parent):
            font = widget.GetFont()
            if font.IsOk():
                font.SetFamily(wx.FONTFAMILY_TELETYPE)
                widget.SetFont(font)
            if isinstance(widget, wx.StaticText) and isinstance(widget.GetParent(), PaletteChoice):
                continue
            if isinstance(widget, wx.StaticText):
                widget.SetForegroundColour(self.colours["text"])
            elif isinstance(widget, wx.CheckBox):
                widget.SetForegroundColour(self.colours["text"])
                widget.SetBackgroundColour(self.colours["surface_soft"])
            elif isinstance(widget, PaletteChoice):
                widget.apply_palette(self.colours)
            elif isinstance(widget, (wx.TextCtrl, wx.SearchCtrl, wx.Choice, wx.ListCtrl)):
                widget.SetForegroundColour(self.colours["text"])
                widget.SetBackgroundColour(self.colours["control"])
            elif isinstance(widget, wx.Button):
                widget.SetForegroundColour(self.colours["text"])
                widget.SetBackgroundColour(self.colours["surface"])

    def _input_box(self, parent, control_type, *args, track_border=True, **kwargs):
        """Create an input and its uniform Windows palette border."""
        if os.name != "nt" and control_type is not PaletteChoice:
            control = control_type(parent, *args, **kwargs)
            return control, control
        border = wx.Panel(parent, style=wx.BORDER_NONE)
        border.SetBackgroundColour(self.colours["input_border"])
        control = control_type(border, *args, **kwargs)
        content = wx.BoxSizer(wx.VERTICAL)
        content.Add(control, 1, wx.EXPAND | wx.ALL, 1)
        border.SetSizer(content)
        if track_border:
            self._theme_input_borders.append(border)
        return control, border

    def style_dialog(self, dialog):
        """Give application-owned dialogs the active terminal palette."""
        dialog.SetBackgroundColour(self.colours["surface_soft"])
        self._style_controls(dialog)
        _set_windows_frame_theme(
            dialog.GetHandle(),
            self.colours["background"] == wx.Colour("#050505"),
            self.colours,
        )
        dialog.Refresh()

    def _apply_native_frame_theme(self):
        """Keep the native Windows frame aligned with the selected palette."""
        return _set_windows_frame_theme(
            self.GetHandle(),
            self.colours["background"] == wx.Colour("#050505"),
            self.colours,
        )

    def _style_app_menu(self):
        """Apply the active palette to the owner-drawn Windows menu."""
        if not self.app_menu_bar:
            return
        renderer = self._flat_menu_renderer
        renderer.menuFaceColour = self.colours["surface"]
        renderer.menuBarFaceColour = self.colours["header"]
        renderer.itemTextColourDisabled = self.colours["muted"]
        renderer.SetMenuBarHighlightColour(self.colours["accent_soft"])
        renderer.SetMenuHighlightColour(self.colours["accent_soft"])
        renderer.menuBarFocusBorderColour = self.colours["border"]
        renderer.menuBarPressedBorderColour = self.colours["border"]
        renderer.menuFocusBorderColour = self.colours["border"]
        renderer.menuPressedBorderColour = self.colours["border"]
        menu_font = wx.Font(self.app_menu_bar.GetFont())
        menu_font.SetFamily(wx.FONTFAMILY_TELETYPE)
        renderer.apply_text_palette(
            menu_font,
            self.colours["text"],
            self.colours["accent"],
            self.colours["separator"],
        )

        def style_items(menu):
            for item in menu.GetMenuItems():
                item.SetFont(wx.Font(menu_font))
                item.SetTextColour(self.colours["text"])
                submenu = item.GetSubMenu()
                if submenu:
                    style_items(submenu)

        for index in range(self.app_menu_bar.GetMenuCount()):
            style_items(self.app_menu_bar.GetMenu(index))
        self.app_menu_bar.SetBackgroundColour(self.colours["header"])
        self.app_menu_bar.Refresh()

    def _style_windows_scrollbars(self):
        """Refresh common-control scrollbar rendering after a theme change."""
        dark = self.colours["background"] == wx.Colour("#050505")
        for widget in (self.config_panel, self.operation_panel, self.history_table, self.output):
            _set_windows_control_theme(widget.GetHandle(), dark)

    def apply_system_theme(self):
        """Apply the active terminal palette to application-owned surfaces."""
        self.colours = self._system_colours()
        self.SetBackgroundColour(self.colours["background"])
        self.shell.SetBackgroundColour(self.colours["background"])
        self.header.SetBackgroundColour(self.colours["header"])
        for panel in (self.config_panel, self.operation_panel, self.history_panel, self.output_panel):
            panel.SetBackgroundColour(self.colours["surface_soft"])
        self._style_controls(self)
        self.output.SetBackgroundColour(self.colours["surface"])
        self.output.SetForegroundColour(self.colours["text"])
        output_style = wx.TextAttr(self.colours["text"], self.colours["surface"])
        self.output.SetDefaultStyle(output_style)
        if self.output.GetLastPosition():
            self.output.SetStyle(0, self.output.GetLastPosition(), output_style)
        self.history_table.SetBackgroundColour(self.colours["control"])
        if self.history_header:
            self.history_header.SetBackgroundColour(self.colours["accent_soft"])
        for splitter in self._splitters:
            splitter.apply_palette(self.colours["separator"])
        for border in self._theme_input_borders:
            border.SetBackgroundColour(self.colours["input_border"])
        self._style_app_menu()
        self._style_windows_scrollbars()
        self._apply_native_frame_theme()
        for widget in self._theme_text:
            widget.SetForegroundColour(self.colours["text"])
        for widget in self._theme_muted:
            widget.SetForegroundColour(self.colours["muted"])
        for widget in self._theme_accent_labels:
            widget.SetForegroundColour(self.colours["accent_label"])
        for rule in self._theme_rules:
            rule.SetBackgroundColour(self.colours["separator"])
        self.header_title.SetForegroundColour(self.colours["header_text"])
        self.header_subtitle.SetForegroundColour(_mix(self.colours["header_text"], self.colours["header"], 0.78))
        for name, label in self.labels.items():
            self.label_colours[name] = self.colours["text"]
            label.SetForegroundColour(self.colours["text"])
        for heading in self._theme_accent_labels:
            heading.SetForegroundColour(self.colours["accent_label"])
        self.refresh_readiness()
        progress_colour = {
            "completed": self.colours["success"],
            "cancelled": self.colours["warning"],
            "failed": self.colours["danger"],
        }.get(self.progress.GetLabel().lower())
        if progress_colour:
            self.progress.SetForegroundColour(progress_colour)
        for index, record in enumerate(self.records):
            status_colour = {
                "completed": self.colours["text"],
                "cancelled": self.colours["warning"],
                "failed": self.colours["danger"],
            }.get(record.status)
            if status_colour:
                self.history_table.SetItemTextColour(index, status_colour)
        self._paint_history_selection()
        self.render_output()
        self.Refresh()

    def _heading(self, parent, title, subtitle=""):
        """Create a consistent native section heading."""
        box = wx.BoxSizer(wx.VERTICAL)
        heading = wx.StaticText(parent, label=f"[ {title.upper()} ]")
        heading.SetFont(wx.Font(wx.FontInfo(13).Family(wx.FONTFAMILY_TELETYPE).Bold()))
        heading.SetForegroundColour(self.colours["accent_label"])
        self._theme_accent_labels.append(heading)
        box.Add(heading)
        if subtitle:
            detail = wx.StaticText(parent, label=f"// {subtitle}")
            detail.SetForegroundColour(self.colours["muted"])
            self._theme_muted.append(detail)
            box.Add(detail, 0, wx.TOP, 3)
        return box

    def _splitter(self, parent):
        style = wx.SP_LIVE_UPDATE | wx.SP_THIN_SASH
        if os.name == "nt":
            style |= wx.SP_NO_XP_THEME
        splitter = PaletteSplitter(parent, style=style)
        self._splitters.append(splitter)
        splitter.apply_palette(self.colours["separator"])
        splitter.SetMinimumPaneSize(140)
        splitter.Bind(wx.EVT_SPLITTER_DCLICK, lambda event: self.reset_layout())
        return splitter

    def _build_workspace(self):
        shell = wx.Panel(self)
        self.shell = shell
        shell.SetBackgroundColour(self.colours["background"])

        self.header = wx.Panel(shell)
        header = self.header
        header.SetBackgroundColour(self.colours["header"])
        header_sizer = wx.BoxSizer(wx.HORIZONTAL)
        header_copy = wx.BoxSizer(wx.VERTICAL)
        title = wx.StaticText(header, label="> IMAP Migration Tools")
        self.header_title = title
        title.SetFont(wx.Font(wx.FontInfo(18).Family(wx.FONTFAMILY_TELETYPE).Bold()))
        title.SetForegroundColour(self.colours["header_text"])
        subtitle = wx.StaticText(header, label="$ count | compare | backup | restore | migrate")
        self.header_subtitle = subtitle
        subtitle.SetForegroundColour(_mix(self.colours["header_text"], self.colours["header"], 0.78))
        header_copy.Add(title)
        header_copy.Add(subtitle, 0, wx.TOP, 3)
        header_sizer.Add(header_copy, 1, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 16)
        header.SetSizer(header_sizer)

        self.outer = self._splitter(shell)
        self.upper = self._splitter(self.outer)
        config = wx.lib.scrolledpanel.ScrolledPanel(self.upper)
        self.config_panel = config
        config.SetBackgroundColour(self.colours["surface_soft"])
        form = wx.BoxSizer(wx.VERTICAL)
        form.Add(
            self._heading(config, "Configuration", "Autosaves to the selected .env file"),
            0,
            wx.BOTTOM,
            10,
        )
        group = None
        for field in FIELDS:
            if field.group != group:
                group = field.group
                heading = wx.StaticText(config, label=f":: {group}")
                heading.SetFont(
                    wx.Font(wx.FontInfo(heading.GetFont().GetPointSize()).Family(wx.FONTFAMILY_TELETYPE).Bold())
                )
                heading.SetForegroundColour(self.colours["accent_label"])
                self._theme_accent_labels.append(heading)
                form.Add(heading, 0, wx.TOP | wx.BOTTOM, 8)
                rule = wx.Panel(config, style=wx.BORDER_NONE)
                rule.SetBackgroundColour(self.colours["separator"])
                rule.SetMinSize((-1, 1))
                self._theme_rules.append(rule)
                form.Add(rule, 0, wx.EXPAND | wx.BOTTOM, 5)
            if field.kind == "boolean":
                control = wx.CheckBox(config, label=field.label)
                control.Bind(wx.EVT_CHECKBOX, self.on_edit)
                self.labels[field.name] = control
                self.label_colours[field.name] = control.GetForegroundColour()
            else:
                label = wx.StaticText(config, label=field.label)
                self.labels[field.name] = label
                self.label_colours[field.name] = label.GetForegroundColour()
                form.Add(label, 0, wx.TOP, 4)
            if field.kind == "choice":
                control, input_box = self._input_box(
                    config, _choice_type(), choices=list(field.choices), style=_input_style()
                )
                _bind_choice(control, self.on_edit)
            elif field.kind != "boolean":
                control, input_box = self._input_box(
                    config,
                    wx.TextCtrl,
                    style=_input_style(wx.TE_PASSWORD if field.sensitive else 0),
                )
                control.Bind(wx.EVT_TEXT, self.on_edit)
            else:
                input_box = control
            control.SetName(f"{field.group}: {field.label}")
            control.SetToolTip(field.help or field.name)
            self.controls[field.name] = control
            row = wx.BoxSizer(wx.HORIZONTAL)
            row.Add(input_box, 1, wx.EXPAND)
            if field.kind == "path":
                browse = wx.Button(config, label="Browse…")
                browse.Bind(wx.EVT_BUTTON, lambda event, name=field.name: self.browse(name))
                row.Add(browse, 0, wx.LEFT, 8)
            form.Add(row, 0, wx.EXPAND | wx.BOTTOM, 7)
        config_wrapper = wx.BoxSizer(wx.VERTICAL)
        config_wrapper.Add(form, 1, wx.EXPAND | wx.ALL, 16)
        config.SetSizer(config_wrapper)
        config.SetupScrolling(scroll_x=False)
        self.sidebar = self._splitter(self.upper)
        operation_panel = wx.lib.scrolledpanel.ScrolledPanel(self.sidebar, style=wx.BORDER_NONE)
        self.operation_panel = operation_panel
        operation_panel.SetBackgroundColour(self.colours["surface_soft"])
        actions = wx.BoxSizer(wx.VERTICAL)
        operation_heading = self._heading(operation_panel, "Operation", "Select and review requirements")
        self.operation_subtitle = operation_heading.GetItem(1).GetWindow()
        actions.Add(operation_heading, 0, wx.BOTTOM, 6)
        self.tools, tools_box = self._input_box(
            operation_panel,
            _choice_type(),
            choices=[op.title for op in OPERATIONS],
            style=_input_style(),
        )
        self.tools.SetSelection(0)
        _bind_choice(self.tools, lambda event: self.select_operation(OPERATIONS[self.tools.GetSelection()].name))
        actions.Add(tools_box, 0, wx.EXPAND | wx.BOTTOM, 8)
        self.operation_description = wx.StaticText(operation_panel, label="")
        self.operation_description.SetForegroundColour(self.colours["muted"])
        self._theme_muted.append(self.operation_description)
        actions.Add(self.operation_description, 0, wx.EXPAND | wx.BOTTOM, 8)
        self.mode_rows = []
        self.count_mode = self._choice(operation_panel, actions, "Count source", ["source", "destination", "local"])
        self.source_mode = self._choice(operation_panel, actions, "Compare source", ["auto", "imap", "local"])
        self.destination_mode = self._choice(operation_panel, actions, "Compare destination", ["auto", "imap", "local"])
        self.folder_label = wx.StaticText(operation_panel, label="Only this folder (empty for all)")
        actions.Add(self.folder_label, 0, wx.BOTTOM, 5)
        self.folder, folder_box = self._input_box(operation_panel, wx.TextCtrl, style=_input_style())
        actions.Add(folder_box, 0, wx.EXPAND | wx.BOTTOM, 12)
        self.readiness_panel = wx.Panel(operation_panel)
        readiness_sizer = wx.BoxSizer(wx.VERTICAL)
        self.readiness_label = wx.StaticText(self.readiness_panel, label="")
        self.readiness_label.SetFont(self.readiness_label.GetFont().Bold())
        readiness_sizer.Add(self.readiness_label, 0, wx.EXPAND | wx.ALL, 10)
        self.readiness_panel.SetSizer(readiness_sizer)
        actions.Add(self.readiness_panel, 0, wx.EXPAND | wx.BOTTOM, 8)
        self.run_button = wx.Button(operation_panel, label="> Run Count")
        self.run_button.Bind(wx.EVT_BUTTON, lambda event: self.prepare_run())
        actions.Add(self.run_button, 0, wx.EXPAND)
        operation_wrapper = wx.BoxSizer(wx.VERTICAL)
        operation_wrapper.Add(actions, 1, wx.EXPAND | wx.ALL, 8)
        operation_panel.SetSizer(operation_wrapper)
        operation_panel.SetupScrolling(scroll_x=False)
        history_panel = wx.Panel(self.sidebar, style=wx.BORDER_NONE)
        self.history_panel = history_panel
        history_panel.SetBackgroundColour(self.colours["surface_soft"])
        history_sizer = wx.BoxSizer(wx.VERTICAL)
        history_sizer.Add(self._heading(history_panel, "History", "Completed runs and saved output"), 0, wx.BOTTOM, 10)
        self.history_table, history_table_box = self._input_box(
            history_panel,
            wx.ListCtrl,
            style=_input_style(wx.LC_REPORT | wx.LC_SINGLE_SEL | wx.LC_NO_HEADER),
        )
        history_columns = (("Operation", 95), ("Status", 95), ("Started", 165))
        for index, (title, width) in enumerate(history_columns):
            self.history_table.InsertColumn(index, title, width=width)
        self.history_table.Bind(wx.EVT_LIST_ITEM_SELECTED, self.on_history_selected)
        self.history_header, history_header_box = self._input_box(
            history_panel,
            wx.Panel,
            style=wx.BORDER_NONE,
        )
        self.history_header.SetBackgroundColour(self.colours["accent_soft"])
        history_header_sizer = wx.BoxSizer(wx.HORIZONTAL)
        for title, width in history_columns:
            label = wx.StaticText(self.history_header, label=title)
            label.SetForegroundColour(self.colours["accent_label"])
            self._theme_accent_labels.append(label)
            history_header_sizer.Add(label, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT, 6)
            history_header_sizer.AddSpacer(max(0, width - label.GetBestSize().width - 6))
        history_header_sizer.AddStretchSpacer()
        self.history_header.SetSizer(history_header_sizer)
        history_header_box.SetMinSize((-1, 26))
        history_sizer.Add(history_header_box, 0, wx.EXPAND)
        history_sizer.Add(history_table_box, 1, wx.EXPAND | wx.BOTTOM, 8)
        row = wx.BoxSizer(wx.HORIZONTAL)
        row.AddStretchSpacer()
        for title, callback in (("Export…", self.export_history), ("Delete", self.delete_history)):
            button = wx.Button(history_panel, label=title)
            button.Bind(wx.EVT_BUTTON, lambda event, callback=callback: callback())
            row.Add(button, 0, wx.LEFT, 8)
        history_sizer.Add(row)
        history_wrapper = wx.BoxSizer(wx.VERTICAL)
        history_wrapper.Add(history_sizer, 1, wx.EXPAND | wx.ALL, 16)
        history_panel.SetSizer(history_wrapper)
        output_panel = wx.Panel(self.outer, style=wx.BORDER_NONE)
        output_panel.SetBackgroundColour(self.colours["surface_soft"])
        output_sizer = wx.BoxSizer(wx.VERTICAL)
        output_header = wx.BoxSizer(wx.HORIZONTAL)
        output_header.Add(
            self._heading(output_panel, "Output", "Live details and saved logs"), 1, wx.ALIGN_CENTER_VERTICAL
        )
        self.progress = wx.StaticText(output_panel, label="Idle")
        self.progress.SetForegroundColour(self.colours["muted"])
        self._theme_muted.append(self.progress)
        output_header.Add(self.progress, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT, 12)
        output_sizer.Add(output_header, 0, wx.EXPAND | wx.BOTTOM, 10)
        self.output_filter, output_filter_box = self._input_box(output_panel, wx.SearchCtrl, style=_input_style())
        self.output_filter.SetDescriptiveText("Filter output")
        self.output_filter.Bind(wx.EVT_TEXT, lambda event: self.render_output())
        output_sizer.Add(output_filter_box, 0, wx.EXPAND | wx.BOTTOM, 8)
        self.output, output_box = self._input_box(
            output_panel,
            wx.TextCtrl,
            style=_input_style(wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_DONTWRAP),
        )
        self.output.SetName("Operation output")
        output_font_size = self.output.GetFont().GetPointSize() if wx.Platform == "__WXMAC__" else 10
        self.output.SetFont(wx.Font(wx.FontInfo(output_font_size).Family(wx.FONTFAMILY_TELETYPE)))
        self.output.SetBackgroundColour(self.colours["surface"])
        output_sizer.Add(output_box, 1, wx.EXPAND | wx.BOTTOM, 8)
        row = wx.BoxSizer(wx.HORIZONTAL)
        row.AddStretchSpacer()
        self.cancel_button = wx.Button(output_panel, label="Cancel")
        self.force_button = wx.Button(output_panel, label="Force stop")
        self.cancel_button.Bind(wx.EVT_BUTTON, lambda event: self.cancel_run())
        self.force_button.Bind(wx.EVT_BUTTON, lambda event: self.force_stop())
        for button in (self.cancel_button, self.force_button):
            button.Disable()
            row.Add(button, 0, wx.LEFT, 8)
        output_sizer.Add(row)
        output_wrapper = wx.BoxSizer(wx.VERTICAL)
        output_wrapper.Add(output_sizer, 1, wx.EXPAND | wx.ALL, 16)
        output_panel.SetSizer(output_wrapper)
        self.sidebar.SplitHorizontally(operation_panel, history_panel, DEFAULT_OPERATION_HEIGHT)
        self.upper.SplitVertically(config, self.sidebar, 430)
        self.output_panel = output_panel
        self.outer.SplitVertically(self.upper, output_panel, 820)
        shell_sizer = wx.BoxSizer(wx.VERTICAL)
        shell_sizer.Add(header, 0, wx.EXPAND)
        shell_sizer.Add(self.outer, 1, wx.EXPAND | wx.ALL, 10)
        shell.SetSizer(shell_sizer)
        frame_sizer = wx.BoxSizer(wx.VERTICAL)
        if self.app_menu_bar:
            frame_sizer.Add(self.app_menu_bar, 0, wx.EXPAND)
        frame_sizer.Add(shell, 1, wx.EXPAND)
        self.SetSizer(frame_sizer)

    def _choice(self, parent, sizer, label, choices):
        text = wx.StaticText(parent, label=label)
        control, input_box = self._input_box(parent, _choice_type(), choices=choices, style=_input_style())
        control.SetName(label)
        control.SetSelection(0)
        _bind_choice(control, lambda event: self.refresh_readiness())
        sizer.Add(text, 0, wx.BOTTOM, 5)
        sizer.Add(input_box, 0, wx.EXPAND | wx.BOTTOM, 7)
        self.mode_rows.append((text, control, input_box))
        return control

    def load_form(self, values):
        self.loading = True
        for field in FIELDS:
            control = self.controls[field.name]
            value = values.get(field.name, field.default)
            if isinstance(control, wx.CheckBox):
                control.SetValue(value.lower() == "true")
            elif _is_choice(control):
                control.SetStringSelection(value)
            else:
                control.ChangeValue(value)
        self.loading = False

    def form_values(self):
        values = {}
        for name, control in self.controls.items():
            if isinstance(control, wx.CheckBox):
                value = str(control.GetValue()).lower()
            elif _is_choice(control):
                value = control.GetStringSelection()
            else:
                value = control.GetValue()
            values[name] = value
        return values

    def values(self):
        return {name: value.value for name, value in effective_values(self.env_path).items()}

    def on_edit(self, event):
        if not self.loading:
            self.autosave.StartOnce(600)
            self.refresh_readiness()

    def browse(self, name):
        with wx.DirDialog(self, "Select directory", defaultPath=self.controls[name].GetValue()) as dialog:
            if dialog.ShowModal() == wx.ID_OK:
                self.controls[name].SetValue(dialog.GetPath())

    def reload_external(self):
        digest = file_content_fingerprint(self.env_path)
        if digest == self.digest:
            return True
        self.autosave.Stop()
        try:
            values = validated_form(self.env_path)
        except (OSError, ValueError) as exc:
            if digest != self.rejected_digest:
                self.SetStatusText(f"External .env not loaded: {exc}")
            self.rejected_digest = digest
            return False
        self.load_form(values)
        self.digest = digest
        self.rejected_digest = None
        self.refresh_readiness()
        self.SetStatusText("External .env reloaded; pending form edits discarded")
        return True

    def save_configuration(self, event=None):
        self.autosave.Stop()
        if file_content_fingerprint(self.env_path) != self.digest:
            self.reload_external()
            return False
        values = self.form_values()
        errors = validate(values)
        if errors:
            name, message = next(iter(errors.items()))
            self.SetStatusText(f"{name}: {message}")
            return False
        try:
            save_form(self.env_path, values)
        except (OSError, ValueError) as exc:
            self.SetStatusText(f"Unable to save: {exc}")
            return False
        self.digest = file_content_fingerprint(self.env_path)
        self.refresh_readiness()
        override = any(field.name in os.environ for field in FIELDS)
        self.SetStatusText("Saved; OS environment overrides are active" if override else "Configuration saved")
        return True

    def select_operation(self, operation):
        self.operation = operation
        spec = OPERATION_BY_NAME[operation]
        self.tools.SetSelection([spec.name for spec in OPERATIONS].index(operation))
        for index, (label, control, input_box) in enumerate(self.mode_rows):
            visible = operation == ("count" if index == 0 else "compare")
            label.Show(visible)
            control.Show(visible)
            input_box.Show(visible)
        self.folder.Show(operation in {"backup", "restore"})
        self.folder_label.Show(operation in {"backup", "restore"})
        self.operation_description.SetLabel(spec.description)
        self.operation_description.Wrap(max(180, self.run_button.GetParent().GetClientSize().width - 32))
        self.run_button.SetLabel(f"> Run {spec.title}")
        self.run_button.GetParent().Layout()
        self.refresh_readiness()
        self.operation_panel.FitInside()

    def operation_readiness(self):
        return readiness(
            self.operation,
            self.values(),
            count_mode=self.count_mode.GetStringSelection(),
            compare_source_mode=self.source_mode.GetStringSelection(),
            compare_destination_mode=self.destination_mode.GetStringSelection(),
        )

    def refresh_readiness(self):
        values = self.values()
        if not account_ready(values, "DEST") and self.count_mode.GetStringSelection() == "destination":
            self.count_mode.SetSelection(0)
        states = {
            operation.name: readiness(
                operation.name,
                values,
                count_mode=self.count_mode.GetStringSelection(),
                compare_source_mode=self.source_mode.GetStringSelection(),
                compare_destination_mode=self.destination_mode.GetStringSelection(),
            )
            for operation in OPERATIONS
        }
        selected = self.tools.GetSelection()
        for index, operation in enumerate(OPERATIONS):
            operation_state = states[operation.name]
            status = "Warning" if operation_state.warning else "Ready" if operation_state.ready else "Missing"
            self.tools.SetString(index, f"{operation.title} — {status}")
        self.tools.SetSelection(selected)
        state = states[self.operation]
        readiness_status = "WARNING" if state.warning else "READY" if state.ready else "MISSING"
        self.readiness_label.SetLabel(f"{readiness_status} :: {state.detail}")
        self.readiness_label.Wrap(max(160, self.run_button.GetParent().GetClientSize().width - 20))
        self.run_button.Enable(state.ready and not self.controller.active)
        semantic = (
            self.colours["warning"]
            if state.warning
            else self.colours["success"]
            if state.ready
            else self.colours["danger"]
        )
        self.readiness_panel.SetBackgroundColour(_mix(semantic, self.colours["background"], 0.16))
        self.readiness_label.SetForegroundColour(semantic)
        self.run_button.SetBackgroundColour(self.colours["accent"] if state.ready else self.colours["background"])
        self.run_button.SetForegroundColour(self.colours["accent_text"] if state.ready else self.colours["muted"])
        for field in FIELDS:
            suffix = " (required)" if field.name in state.missing_fields else ""
            label = self.labels[field.name]
            label.SetLabel(field.label + suffix)
            font = label.GetFont()
            font.SetWeight(wx.FONTWEIGHT_BOLD if field.name in state.required_fields else wx.FONTWEIGHT_NORMAL)
            label.SetFont(font)
            label.SetForegroundColour(
                self.colours["danger"] if field.name in state.missing_fields else self.label_colours[field.name]
            )
            label.SetToolTip(
                f"Required for {OPERATION_BY_NAME[self.operation].title}"
                if field.name in state.required_fields
                else field.help or field.name
            )
        self.run_button.GetParent().Layout()
        self.operation_panel.FitInside()

    def confirm(self, message, require_delete=False):
        with ConfirmationDialog(self, message, require_delete) as dialog:
            accepted = dialog.ShowModal() == (wx.ID_OK if require_delete else wx.ID_YES)
            return accepted and (not require_delete or dialog.GetValue() == "DELETE")

    def prepare_run(self):
        if self.controller.active or not self.save_configuration():
            return
        state = self.operation_readiness()
        if not state.ready:
            self.SetStatusText(state.detail)
            return
        values = self.values()
        try:
            options = make_options(
                self.operation,
                values,
                self.count_mode.GetStringSelection(),
                self.source_mode.GetStringSelection(),
                self.destination_mode.GetStringSelection(),
                self.folder.GetValue(),
            )
        except ValueError:
            self.SetStatusText("Workers and batch size must be positive integers")
            return
        message, destructive = run_confirmation(self.operation, options, values)
        if not self.confirm(message, destructive):
            return
        request = RunRequest(
            build_command(OPERATION_BY_NAME[self.operation], options),
            self.working_directory,
            options.environment,
            options.environment,
            desktop_worker=True,
        )
        self.lines.clear()
        self.output.ChangeValue("")
        self.set_progress_label("Starting…")
        self.progress.SetForegroundColour(self.colours["muted"])
        self.current_run_id = self.selected_run_id = None
        self.controller.start(self.operation, values, request)
        self.cancel_button.Enable()
        self.refresh_readiness()

    def cancel_run(self):
        if self.controller.active:
            self.controller.cancel()
            self.SetStatusText("Cancellation requested; waiting for cleanup")

    def force_stop(self):
        if self.controller.active and self.confirm("Force stop this operation? Cleanup may be incomplete."):
            self.controller.cancel(force=True)

    def set_progress_label(self, label):
        """Update the output status and immediately recalculate its sizer width."""
        self.progress.SetLabel(label)
        self.progress.InvalidateBestSize()
        self.progress.GetParent().Layout()

    def poll(self, event=None):
        self.reload_external()
        dirty = False
        for _ in range(500):
            try:
                kind, payload = self.controller.events.get_nowait()
            except queue.Empty:
                break
            if kind == "started":
                self.current_run_id = self.selected_run_id = payload.run_id
                self.refresh_history()
            elif kind == "line":
                self.lines.append(payload)
                dirty = True
            elif kind == "progress":
                self.set_progress_label(
                    f"{payload.phase} | Copied {payload.copied} | Skipped {payload.skipped} | "
                    f"Failed {payload.failed} | Deleted {payload.deleted}"
                )
            elif kind == "warning":
                self.SetStatusText(payload)
            elif kind == "force_available":
                self.force_button.Enable()
                self.SetStatusText("Still running; force stop is available")
            elif kind == "finished":
                self.controller.active = False
                self.cancel_button.Disable()
                self.force_button.Disable()
                self.set_progress_label(payload.status if payload else "failed")
                status_colour = (
                    self.colours["success"]
                    if payload and payload.status == "completed"
                    else self.colours["warning"]
                    if payload and payload.status == "cancelled"
                    else self.colours["danger"]
                )
                self.progress.SetForegroundColour(status_colour)
                self.refresh_readiness()
                self.refresh_history()
                if self.closing:
                    self.Close()
                    return
        if dirty and self.selected_run_id == self.current_run_id:
            self.render_output()
        try:
            fingerprint = directory_fingerprint(history.history_dir(), "*.json")
            if fingerprint != self.history_digest:
                self.refresh_history()
                self.history_digest = fingerprint
        except OSError as exc:
            self.SetStatusText(f"History unavailable: {exc}")

    def refresh_history(self):
        try:
            records = [r for r in history.load_records() if r.status != "running" or r.run_id == self.current_run_id][
                :20
            ]
        except OSError as exc:
            self.SetStatusText(f"History unavailable: {exc}")
            return
        if records == self.records:
            return
        self.records = records
        selected = self.selected_run_id
        self.history_table.Freeze()
        self.history_table.DeleteAllItems()
        for index, record in enumerate(records):
            self.history_table.InsertItem(index, record.operation)
            self.history_table.SetItem(index, 1, record.status)
            self.history_table.SetItem(index, 2, record.started_at[:19])
            if record.status == "failed":
                self.history_table.SetItemTextColour(index, self.colours["danger"])
            elif record.status == "cancelled":
                self.history_table.SetItemTextColour(index, self.colours["warning"])
            elif record.status == "completed":
                self.history_table.SetItemTextColour(index, self.colours["text"])
        ids = [record.run_id for record in records]
        self.selected_run_id = (
            selected if selected in ids else ids[0] if ids else self.current_run_id if self.controller.active else None
        )
        self._paint_history_selection()
        self.history_table.Thaw()
        self.render_output()

    def on_history_selected(self, event):
        if 0 <= event.GetIndex() < len(self.records):
            self.selected_run_id = self.records[event.GetIndex()].run_id
            self._paint_history_selection()
            self.render_output()

    def _paint_history_selection(self):
        """Use the application palette instead of each platform's native selection blue."""
        for index, record in enumerate(self.records):
            selected = record.run_id == self.selected_run_id
            self.history_table.SetItemBackgroundColour(
                index,
                self.colours["surface"] if selected else self.colours["control"],
            )
            self.history_table.SetItemState(index, 0, wx.LIST_STATE_SELECTED)

    def render_output(self):
        try:
            lines = (
                self.lines
                if self.selected_run_id == self.current_run_id
                else history.read_log(self.selected_run_id).splitlines()
                if self.selected_run_id
                else []
            )
            match = self.output_filter.GetValue().lower()
            self.output.ChangeValue("\n".join(line for line in lines if match in line.lower()))
            self.output.ShowPosition(self.output.GetLastPosition())
        except OSError as exc:
            self.SetStatusText(f"Unable to read log: {exc}")

    def export_history(self):
        if not self.selected_run_id:
            return
        with wx.FileDialog(
            self,
            "Export log",
            defaultFile=f"{self.selected_run_id}.log",
            wildcard="Log files (*.log)|*.log|All files|*",
            style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
        ) as dialog:
            if dialog.ShowModal() != wx.ID_OK:
                return
            try:
                Path(dialog.GetPath()).write_text(history.read_log(self.selected_run_id), encoding="utf-8")
                self.SetStatusText("Log exported")
            except OSError as exc:
                self.SetStatusText(f"Unable to export: {exc}")

    def delete_history(self):
        if not self.selected_run_id:
            return
        if self.controller.active and self.selected_run_id == self.current_run_id:
            self.SetStatusText("Wait for the active run to finish before deleting it")
            return
        if self.confirm("Delete the selected run and its log?"):
            try:
                history.delete_record(self.selected_run_id)
                self.refresh_history()
            except OSError as exc:
                self.SetStatusText(f"Unable to delete: {exc}")

    def on_resize(self, event):
        event.Skip()
        if not self.IsMaximized() and not self.IsIconized():
            size = event.GetSize()
            self._last_window_size = (size.width, size.height)
        self.apply_responsive_layout()

    def apply_responsive_layout(self, width=None, height=None):
        """Apply the compact or wide arrangement for explicit client dimensions."""
        client_size = self.GetClientSize()
        width = client_size.width if width is None else width
        height = client_size.height if height is None else height
        if hasattr(self, "operation_description"):
            available = max(180, self.run_button.GetParent().GetClientSize().width - 32)
            self.operation_description.Wrap(available)
            self.readiness_label.Wrap(available)
        compact = width < 1050
        self.operation_subtitle.Show(not compact)
        if compact == self.compact:
            self.operation_panel.Layout()
            self.operation_panel.FitInside()
            return
        self.compact = compact
        self.outer.Unsplit(self.output_panel)
        self.output_panel.Show()
        if compact:
            available_height = self.outer.GetClientSize().height
            self.outer.SplitHorizontally(self.upper, self.output_panel, max(280, available_height - 145))
        else:
            self.outer.SplitVertically(self.upper, self.output_panel, 820)
        self.Layout()
        self.operation_panel.FitInside()

    def restore_layout(self):
        sizes = load_layout(self.layout_path)
        for name, splitter, default in (
            ("outer", self.outer, 820),
            ("upper", self.upper, 430),
            ("sidebar", self.sidebar, DEFAULT_OPERATION_HEIGHT),
        ):
            splitter.SetSashPosition(sizes.get(name, default))

    def reset_layout(self):
        for splitter, size in (
            (self.outer, 820),
            (self.upper, 430),
            (self.sidebar, DEFAULT_OPERATION_HEIGHT),
        ):
            splitter.SetSashPosition(size)

    def on_close(self, event):
        if self.controller.active:
            event.Veto()
            if self.confirm("Cancel the active operation and quit after cleanup?"):
                self.closing = True
                self.cancel_run()
            return
        if self.autosave.IsRunning() and not self.save_configuration():
            event.Veto()
            return
        try:
            save_layout(
                self.layout_path,
                {
                    name: splitter.GetSashPosition()
                    for name, splitter in (("outer", self.outer), ("upper", self.upper), ("sidebar", self.sidebar))
                },
                self._last_window_size,
            )
        except OSError:
            pass
        self.poller.Stop()
        self.autosave.Stop()
        self.controller.close()
        self.Destroy()


def main(argv=None):
    """Discover configuration without pinning dotenv values as OS overrides."""
    loaded = load_dotenv()
    for name in loaded.dotenv_keys:
        os.environ.pop(name, None)
    parser = argparse.ArgumentParser(description="Native IMAP Migration Tools workspace")
    parser.add_argument("--env", type=Path, help="Configuration .env file (default: discover from working directory)")
    args = parser.parse_args(argv)
    app = wx.App(False)
    frame = Workspace(args.env)
    frame.Show()
    app.MainLoop()


if __name__ == "__main__":
    main()
