"""Single-workspace Textual application for IMAP Migration Tools."""

from __future__ import annotations

import os
from collections import deque
from pathlib import Path

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.content import Content
from textual.events import Resize
from textual.screen import ModalScreen
from textual.timer import Timer
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Input,
    Label,
    OptionList,
    RichLog,
    Select,
    Static,
)

from tui.config import (
    FIELDS,
    discover_env,
    effective_values,
    read_env,
    save_form,
    validate,
)
from tui.display import DISPLAY_MODES, DisplayProfile, has_limited_color, resolve_display_profile
from tui.history import HistoryWriter, delete_record, history_dir, load_records, read_log
from tui.history import Redactor as Redactor
from tui.layout import default_layout_path, load_layout, save_layout
from tui.operations import (
    OPERATION_BY_NAME,
    OPERATIONS,
    OperationName,
    ProgressState,
    Readiness,
    RunOptions,
    account_ready,
    build_command,
    readiness,
)
from tui.operations import (
    OPERATION_SWITCHES as OPERATION_SWITCHES,
)
from tui.runner import OperationRunner, RunRequest
from tui.splitter import ResizeHandle
from ui.session import RunSession
from ui.workspace import make_options, run_confirmation, validated_form
from utils.filesystem_watch import FilesystemWatcher


def _field_id(name: str) -> str:
    return "env-" + name.lower().replace("_", "-")


class ToolButton(Static, can_focus=True):
    """Flush-aligned operation selector without Textual Button's line inset."""

    BINDINGS = [Binding("enter,space", "press", "select", show=False)]

    def __init__(self, label: str, operation: OperationName) -> None:
        super().__init__(label, id=f"tool-{operation}", classes="tool-button")
        self.operation = operation

    def action_press(self) -> None:
        self.app.select_operation(self.operation)

    def on_click(self) -> None:
        self.action_press()


class AsciiCheckbox(Checkbox):
    """Textual checkbox rendered with portable ``[ ]`` and ``[x]`` markers."""

    @property
    def _button(self) -> Content:
        marker = "[x]" if self.value else "[ ]"
        return Content.from_text(marker, markup=False).stylize_before(self.get_visual_style("toggle--button"))

    def render(self) -> Content:
        if not self.label.plain:
            return self._button
        return super().render()


class ConfirmationModal(ModalScreen[bool]):
    """Centered confirmation dialog that leaves the workspace visible underneath."""

    BINDINGS = [
        Binding("y", "yes", "yes", show=False, priority=True),
        Binding("n,escape", "no", "no", show=False, priority=True),
    ]

    def __init__(self, message: str, require_delete: bool = False) -> None:
        super().__init__()
        self.message = message
        self.require_delete = require_delete

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-dialog"):
            yield Static(self.message, id="confirm-message")
            yield Input(
                placeholder="type DELETE to confirm",
                id="confirm-input",
                classes="" if self.require_delete else "hidden",
            )
            with Horizontal(classes="compact-actions"):
                yield Button("yes", id="yes-action", variant="error")
                yield Button("no", id="no-action")

    def on_mount(self) -> None:
        target = "#confirm-input" if self.require_delete else "#yes-action"
        self.query_one(target).focus()

    @on(Button.Pressed)
    def button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "no-action":
            self.action_no()
        elif event.button.id == "yes-action":
            self.action_yes()

    def action_yes(self) -> None:
        if self.require_delete and self.query_one("#confirm-input", Input).value != "DELETE":
            self.notify("Type DELETE exactly to confirm", severity="error")
            return
        self.dismiss(True)

    def action_no(self) -> None:
        self.dismiss(False)

    @on(Input.Submitted, "#confirm-input")
    def delete_submitted(self) -> None:
        self.action_yes()


KEY_REFERENCE = """GLOBAL
Alt+1 … Alt+5   select Count, Compare, Backup, Restore, or Migrate
Alt+C           focus Configuration
Alt+O           focus Operation
Alt+L           focus Output filter
F5              run the selected operation
Alt+0           reset the complete panel layout
F1              open general help
F2              open this keyboard reference
F10             quit

NAVIGATION AND CONTROLS
Tab / Shift+Tab move between controls
Enter / Space   activate the focused tool, button, or checkbox
Arrow keys      change selections and navigate tables
PgUp / PgDn     scroll long forms and output

RESIZING
Arrow keys      resize when a separator is focused (←/→ or ↑/↓)
Double-click    reset one separator

DIALOGS
Y / N           answer a confirmation
Enter           accept the default action
Esc             cancel or close"""

GENERAL_HELP = """IMAP Migration Tools provides one workspace for configuring and running mailbox operations.

1. CONFIGURE
Enter account, authentication, local-path, and operation settings in Configuration. Changes are validated and saved automatically to the discovered .env file. Fields needed by the selected operation are highlighted; missing values receive stronger warning styling.

2. SELECT A TOOL
Choose Count, Compare, Backup, Restore, or Migrate in Tools. The icon on the right indicates whether the current configuration is ready. Operation contains only choices specific to that run; shared settings remain in Configuration.

3. RUN
Review the Operation choices and use its run button or F5. Destructive settings require an explicit confirmation. Cancel requests graceful shutdown; force stop becomes available if cleanup does not finish.

4. REVIEW
Every run is added to History immediately. Selecting a History row loads its sanitized log into Output. While the active row remains selected, Output follows the command in real time. Export saves the selected log in the project directory.

LAYOUT
Drag the visible separators to resize panels, or focus a separator and use its indicated arrow keys. Double-click resets one separator; Alt+0 resets the full layout. Customized sizes persist between launches.

Configuration secrets are masked in the form and redacted from persisted run logs."""


class InformationModal(ModalScreen[None]):
    """Centered, scrollable reference dialog displayed above the workspace."""

    BINDINGS = [Binding("escape,enter", "close", "close", show=False, priority=True)]

    def __init__(self, title: str, content: str) -> None:
        super().__init__()
        self.dialog_title = title
        self.content = content

    def compose(self) -> ComposeResult:
        with Vertical(id="info-dialog"):
            with VerticalScroll(id="info-body"):
                yield Static(self.content, id="info-content", markup=False)
            yield Static("Enter/Esc: close", id="info-footer")

    def on_mount(self) -> None:
        self.query_one("#info-dialog").border_title = self.dialog_title
        self.query_one("#info-body").focus()

    def action_close(self) -> None:
        self.dismiss(None)


OPERATION_PANEL_HEIGHTS: dict[OperationName, int] = {
    "count": 6,
    "compare": 8,
    "backup": 10,
    "restore": 10,
    "migrate": 8,
}


class ImapToolsApp(App[None]):
    """Dense, full-terminal workspace with inline navigation."""

    CSS_PATH = "styles.tcss"
    TITLE = "IMAP Migration Tools"
    ENABLE_COMMAND_PALETTE = False
    DEFAULT_KEY_LEGEND = (
        "[bold #388bff]Alt+1-5[/] tool   [bold #388bff]Alt+C/O/L[/] config/operation/log   "
        "[bold #44dd55]F5[/] run   [bold #e6d84a]drag/arrows[/] resize   "
        "[bold #d45cff]F1/F2[/] help/keys   [bold #ff4d4d]F10[/] quit"
    )
    BINDINGS = [
        Binding("alt+1", "select_operation('count')", "count", show=False, priority=True),
        Binding("alt+2", "select_operation('compare')", "compare", show=False, priority=True),
        Binding("alt+3", "select_operation('backup')", "backup", show=False, priority=True),
        Binding("alt+4", "select_operation('restore')", "restore", show=False, priority=True),
        Binding("alt+5", "select_operation('migrate')", "migrate", show=False, priority=True),
        Binding("alt+c", "focus_config", "config", show=False, priority=True),
        Binding("alt+o", "focus_operation", "operation", show=False, priority=True),
        Binding("alt+l", "focus_log", "log", show=False, priority=True),
        Binding("f5", "start_selected", "run", show=False, priority=True),
        Binding("alt+0", "reset_layout", "reset layout", show=False, priority=True),
        Binding("f1", "show_help", "help", show=False, priority=True),
        Binding("f2", "show_keys", "keys", show=False, priority=True),
        Binding("f10", "request_quit", "quit", show=False, priority=True),
    ]

    def __init__(
        self,
        env_path: Path | None = None,
        layout_path: Path | None = None,
        display_profile: DisplayProfile | None = None,
    ) -> None:
        super().__init__()
        self.display_profile = display_profile or resolve_display_profile()
        self.working_directory = Path.cwd()
        self.env_path = env_path or discover_env()
        self.layout_path = layout_path or default_layout_path()
        self.layout_path_explicit = layout_path is not None
        self.runner = OperationRunner()
        self.selected_operation: OperationName = "count"
        self.progress = ProgressState()
        self.log_lines: deque[str] = deque(maxlen=5000)
        self.current_run_id: str | None = None
        self.selected_output_id: str | None = None
        self.history_writer: HistoryWriter | None = None
        self.cancellation_requested = False
        self.operation_in_progress = False
        self.last_readiness_notice: tuple[OperationName, str] | None = None
        self.pending_action = ""
        self.pending_payload: object | None = None
        self.configuration_autosave_enabled = False
        self.configuration_save_timer: Timer | None = None
        self.configuration_status_timer: Timer | None = None
        self.filesystem_watch_timer: Timer | None = None
        self.configuration_reload_in_progress = False
        self.filesystem_watcher = FilesystemWatcher()
        self.filesystem_watcher.watch_file("configuration", self.env_path)
        self.filesystem_watcher.watch_directory("history", history_dir(), "*.json")
        self.configuration_file_digest = self.env_digest()
        self.configuration_rejected_digest: str | None = None

    def compose(self) -> ComposeResult:
        values = self.values()
        with Horizontal(id="workspace"):
            with Vertical(id="center-column"):
                with Container(id="config-panel", classes="panel"):
                    with VerticalScroll(id="config-form"):
                        group = None
                        current = read_env(self.env_path)
                        for field in FIELDS:
                            if field.group != group:
                                group = field.group
                                prefix = "--" if self.display_profile.mode == "ascii" else "──"
                                yield Label(f"{prefix} {group} ", classes="group-title")
                            yield Label(field.label, id=f"label-{_field_id(field.name)}", classes="field-label")
                            value = current.get(field.name, field.default)
                            if field.kind == "boolean":
                                yield AsciiCheckbox(
                                    value=value.lower() == "true",
                                    id=_field_id(field.name),
                                    name=field.name,
                                    compact=True,
                                )
                            elif field.kind == "choice":
                                yield Select.from_values(
                                    field.choices,
                                    value=value or field.default,
                                    compact=True,
                                    id=_field_id(field.name),
                                    name=field.name,
                                )
                            else:
                                yield Input(
                                    value=value,
                                    password=field.sensitive,
                                    type="integer" if field.kind == "integer" else "text",
                                    id=_field_id(field.name),
                                    name=field.name,
                                )
            yield ResizeHandle(
                "center-column",
                "sidebar",
                "vertical",
                minimum_before=38,
                minimum_after=22,
                marker=self.display_profile.vertical_separator,
                id="center-sidebar-handle",
            )
            with Vertical(id="sidebar"):
                with Vertical(id="tools-panel", classes="panel"):
                    for index, operation in enumerate(OPERATIONS, 1):
                        with Horizontal(classes="tool-row"):
                            yield ToolButton(f"{index}  {operation.title}", operation.name)
                            yield Static("", id=f"ready-{operation.name}", classes="readiness")
                yield ResizeHandle(
                    "tools-panel",
                    "operation-panel",
                    "horizontal",
                    minimum_before=7,
                    minimum_after=5,
                    marker=self.display_profile.horizontal_separator,
                    id="tools-operation-handle",
                )
                with VerticalScroll(id="operation-panel", classes="panel"):
                    yield Label("Source", classes="count-control control-label")
                    yield Select(
                        (
                            ("source account", "source"),
                            ("destination account", "destination"),
                            ("local backup", "local"),
                        ),
                        value="source",
                        allow_blank=False,
                        compact=True,
                        id="count-mode",
                        classes="count-control",
                    )
                    yield Label("Source", classes="compare-control control-label")
                    yield Select(
                        (("automatic", "auto"), ("source account", "imap"), ("local backup", "local")),
                        value="auto",
                        compact=True,
                        id="compare-source-mode",
                        classes="compare-control",
                    )
                    yield Label("Destination", classes="compare-control control-label")
                    yield Select(
                        (("automatic", "auto"), ("destination account", "imap"), ("local backup", "local")),
                        value="auto",
                        compact=True,
                        id="compare-dest-mode",
                        classes="compare-control",
                    )
                    yield Label("Source", classes="migrate-control control-label")
                    yield Select(
                        (("source account", "imap"),),
                        value="imap",
                        allow_blank=False,
                        compact=True,
                        disabled=True,
                        id="migrate-source-mode",
                        classes="migrate-control",
                    )
                    yield Label("Destination", classes="migrate-control control-label")
                    yield Select(
                        (("destination account", "imap"),),
                        value="imap",
                        allow_blank=False,
                        compact=True,
                        disabled=True,
                        id="migrate-dest-mode",
                        classes="migrate-control",
                    )
                    yield Label("Source", classes="backup-control control-label")
                    yield Select(
                        (("source account", "source"),),
                        value="source",
                        allow_blank=False,
                        compact=True,
                        disabled=True,
                        id="backup-source-mode",
                        classes="backup-control",
                    )
                    yield Label("Destination", classes="backup-control control-label")
                    yield Select(
                        (("local backup", "local"),),
                        value="local",
                        allow_blank=False,
                        compact=True,
                        disabled=True,
                        id="backup-dest-mode",
                        classes="backup-control",
                    )
                    yield Label("Source", classes="restore-control control-label")
                    yield Select(
                        (("local backup", "local"),),
                        value="local",
                        allow_blank=False,
                        compact=True,
                        disabled=True,
                        id="restore-source-mode",
                        classes="restore-control",
                    )
                    yield Label("Destination", classes="restore-control control-label")
                    yield Select(
                        (("destination account", "destination"),),
                        value="destination",
                        allow_blank=False,
                        compact=True,
                        disabled=True,
                        id="restore-dest-mode",
                        classes="restore-control",
                    )
                    yield Label("Only this folder", classes="transfer-control control-label folder-label")
                    yield Input(id="folder", placeholder="leave empty for all folders", classes="transfer-control")
                    yield Button("run count", id="run-operation", variant="success", classes="wide-action")
                yield ResizeHandle(
                    "operation-panel",
                    "history-panel",
                    "horizontal",
                    minimum_before=5,
                    marker=self.display_profile.horizontal_separator,
                    id="operation-history-handle",
                )
                with Vertical(id="history-panel", classes="panel"):
                    yield DataTable(id="history-table", cursor_type="row")
                    with Horizontal(classes="compact-actions"):
                        yield Button("export", id="export-history")
                        yield Button("delete", id="delete-history")
            yield ResizeHandle(
                "sidebar",
                "right-column",
                "vertical",
                minimum_before=22,
                minimum_after=40,
                marker=self.display_profile.vertical_separator,
                flexible_after=True,
                id="sidebar-right-handle",
            )
            with Vertical(id="right-column"):
                with Vertical(id="monitor-panel", classes="panel"):
                    yield Input(placeholder="filter output", id="output-filter")
                    yield RichLog(id="output-log", wrap=True, markup=False, max_lines=5000, auto_scroll=True)
                    with Horizontal(classes="compact-actions"):
                        yield Button("cancel", id="cancel-run", disabled=True)
                        yield Button("force stop", id="force-stop", disabled=True)
        yield Static(self.DEFAULT_KEY_LEGEND, id="key-legend")

    def on_mount(self) -> None:
        self.set_class(self.display_profile.mode == "ascii", "ascii-mode")
        limited_color = self.display_profile.limited_color or has_limited_color(self.console.color_system)
        self.set_class(limited_color, "limited-color")
        separator = " - " if self.display_profile.mode == "ascii" else " · "
        titles = {
            "tools-panel": "Tools",
            "history-panel": "History",
            "config-panel": "Configuration",
            "operation-panel": f"Operation{separator}Count",
            "monitor-panel": "Output",
        }
        for widget_id, title in titles.items():
            self.query_one(f"#{widget_id}").border_title = title
        history = self.query_one("#history-table", DataTable)
        history.add_column("operation", width=9)
        history.add_column("status", width=9)
        history.add_column("started", width=19)
        self.refresh_configuration()
        self.refresh_history()
        self.select_operation("count")
        self.call_after_refresh(self.initialize_layout)
        self.call_after_refresh(self.enable_configuration_autosave)

    def resize_handles(self) -> list[ResizeHandle]:
        """Return splitters in dependency order for deterministic restoration."""
        return [
            self.query_one("#center-sidebar-handle", ResizeHandle),
            self.query_one("#sidebar-right-handle", ResizeHandle),
            self.query_one("#tools-operation-handle", ResizeHandle),
            self.query_one("#operation-history-handle", ResizeHandle),
        ]

    def initialize_layout(self) -> None:
        """Capture defaults and restore saved wide-screen panel sizes."""
        if self.has_class("narrow") or self.has_class("medium"):
            return
        handles = self.resize_handles()
        for handle in handles:
            handle.capture_default()
        if self.is_headless and not self.layout_path_explicit:
            return
        saved = load_layout(self.layout_path)
        for handle in handles:
            if handle.id in saved:
                handle.restore_before_size(saved[handle.id])

    def save_current_layout(self) -> None:
        """Persist the current leading-pane size for every splitter."""
        if self.has_class("narrow") or self.has_class("medium") or (self.is_headless and not self.layout_path_explicit):
            return
        sizes = {handle.id: handle.before_size for handle in self.resize_handles() if handle.id}
        try:
            save_layout(self.layout_path, sizes)
        except OSError as exc:
            self.notify(f"Could not save panel layout: {exc}", severity="warning")

    @on(ResizeHandle.Changed)
    def splitter_changed(self) -> None:
        self.call_after_refresh(self.save_current_layout)

    @on(ResizeHandle.Focused)
    def splitter_focused(self, event: ResizeHandle.Focused) -> None:
        if self.display_profile.mode == "ascii":
            arrows = "left/right" if event.orientation == "vertical" else "up/down"
        else:
            arrows = "←/→" if event.orientation == "vertical" else "↑/↓"
        self.query_one("#key-legend", Static).update(
            f"[bold #e6d84a]{arrows}[/] resize   [bold #44dd55]double-click[/] reset splitter   "
            "[bold #388bff]Alt+0[/] reset layout"
        )

    @on(ResizeHandle.Blurred)
    def splitter_blurred(self) -> None:
        self.query_one("#key-legend", Static).update(self.DEFAULT_KEY_LEGEND)

    def enable_configuration_autosave(self) -> None:
        self.configuration_autosave_enabled = True
        self.show_neutral_configuration_status()
        self.filesystem_watch_timer = self.set_interval(1.0, self.check_external_filesystem)

    def env_digest(self) -> str:
        """Return a content fingerprint for the current env file."""
        return str(self.filesystem_watcher.fingerprint("configuration"))

    def check_external_filesystem(self) -> None:
        """Dispatch changes from every registered filesystem target."""
        self.check_external_configuration()
        if self.filesystem_watcher.poll("history"):
            self.refresh_history(self.selected_output_id)

    def check_external_configuration(self) -> None:
        """Reload a valid env file when its content changes outside the TUI."""
        digest = self.env_digest()
        if digest == self.configuration_file_digest:
            self.filesystem_watcher.refresh("configuration")
            if self.configuration_rejected_digest is not None:
                self.configuration_rejected_digest = None
                self.show_neutral_configuration_status()
            return
        if digest == self.configuration_rejected_digest:
            return
        if self.filesystem_watcher.poll("configuration"):
            self.reload_external_configuration(digest)

    def reload_external_configuration(self, digest: str) -> bool:
        """Validate and apply an external env change without overwriting it."""
        if digest == "missing":
            self.reject_external_configuration(digest, "the .env file is missing")
            return False
        try:
            form_values = validated_form(self.env_path)
        except (OSError, ValueError) as exc:
            self.reject_external_configuration(digest, str(exc))
            return False

        pending_edit = self.configuration_save_timer is not None
        if self.configuration_save_timer is not None:
            self.configuration_save_timer.stop()
            self.configuration_save_timer = None
        self.configuration_file_digest = digest
        self.filesystem_watcher.refresh("configuration")
        self.configuration_rejected_digest = None
        self.configuration_reload_in_progress = True
        with self.prevent(Input.Changed, Select.Changed, Checkbox.Changed):
            for field in FIELDS:
                widget = self.query_one(f"#{_field_id(field.name)}")
                value = form_values[field.name]
                if isinstance(widget, Checkbox):
                    widget.value = value.lower() == "true"
                elif isinstance(widget, Select):
                    widget.value = value if value else Select.BLANK
                else:
                    widget.value = value
        self.call_after_refresh(self.finish_external_configuration_reload)
        self.set_configuration_status(f"{self.display_profile.success} external .env reloaded", reset_after=1.5)
        if pending_edit:
            self.notify("External .env reloaded; the pending form edit was discarded", severity="warning")
        return True

    def reject_external_configuration(self, digest: str, detail: str) -> None:
        """Keep the form unchanged and report one warning per rejected file version."""
        self.configuration_rejected_digest = digest
        self.filesystem_watcher.refresh("configuration")
        self.set_configuration_status(f"{self.display_profile.error} external .env invalid")
        self.notify(f"External .env not loaded: {detail}", severity="error")

    def finish_external_configuration_reload(self) -> None:
        """Resume form events and refresh configuration-dependent TUI state."""
        self.configuration_reload_in_progress = False
        self.refresh_configuration(announce_readiness=True)

    def set_configuration_status(self, status: str, reset_after: float | None = None) -> None:
        """Display Configuration save state and optionally return to neutral."""
        if self.configuration_status_timer is not None:
            self.configuration_status_timer.stop()
            self.configuration_status_timer = None
        self.query_one("#config-panel").border_subtitle = status
        if reset_after is not None:
            self.configuration_status_timer = self.set_timer(reset_after, self.show_neutral_configuration_status)

    def show_neutral_configuration_status(self) -> None:
        """Show autosave status while making OS environment precedence visible."""
        self.configuration_status_timer = None
        override_active = any(field.name in os.environ for field in FIELDS)
        separator = " - " if self.display_profile.mode == "ascii" else " · "
        status = "ENV override active" if override_active else f".env{separator}autosave"
        self.query_one("#config-panel").border_subtitle = status

    def on_resize(self, event: Resize) -> None:
        was_responsive = self.has_class("narrow") or self.has_class("medium")
        is_narrow = event.size.width < 90
        is_medium = 90 <= event.size.width < 141
        self.set_class(is_narrow, "narrow")
        self.set_class(is_medium, "medium")
        if is_narrow or is_medium:
            self.apply_responsive_layout(is_narrow)
        elif was_responsive and self.is_mounted:
            self.restore_wide_layout()

    def apply_responsive_layout(self, narrow: bool) -> None:
        """Remove splitter dimensions and apply medium or narrow panel sizing."""
        for widget_id in ("center-column", "sidebar", "right-column"):
            widget = self.query_one_optional(f"#{widget_id}")
            if widget is not None:
                widget.styles.width = None
                widget.styles.height = None
        operation = self.query_one_optional("#operation-panel")
        if operation is None:
            return
        operation.styles.height = OPERATION_PANEL_HEIGHTS[self.selected_operation]
        self.query_one("#tools-panel").styles.height = 7
        if narrow:
            self.query_one("#center-column").styles.height = 24
            self.query_one("#sidebar").styles.height = 19 + OPERATION_PANEL_HEIGHTS[self.selected_operation]
            self.query_one("#history-panel").styles.height = 12
            self.query_one("#right-column").styles.height = 18
        else:
            self.query_one("#center-column").styles.height = 29
            self.query_one("#sidebar").styles.height = 29
            self.query_one("#history-panel").styles.height = "1fr"
            self.query_one("#right-column").styles.height = "1fr"

    def restore_wide_layout(self) -> None:
        """Restore CSS defaults, followed by the user's persisted desktop sizes."""
        self.query_one("#center-column").styles.width = "2fr"
        self.query_one("#sidebar").styles.width = 47
        self.query_one("#right-column").styles.width = "3fr"
        self.query_one("#center-column").styles.height = "100%"
        self.query_one("#sidebar").styles.height = "100%"
        self.query_one("#right-column").styles.height = "100%"
        self.query_one("#tools-panel").styles.height = 7
        self.query_one("#operation-panel").styles.height = OPERATION_PANEL_HEIGHTS[self.selected_operation]
        self.query_one("#history-panel").styles.height = "1fr"
        self.call_after_refresh(self.initialize_layout)

    def on_unmount(self) -> None:
        if self.configuration_save_timer is not None:
            self.configuration_save_timer.stop()
            self.configuration_save_timer = None
        if self.configuration_status_timer is not None:
            self.configuration_status_timer.stop()
            self.configuration_status_timer = None
        if self.filesystem_watch_timer is not None:
            self.filesystem_watch_timer.stop()
            self.filesystem_watch_timer = None

    def values(self) -> dict[str, str]:
        return {name: item.value for name, item in effective_values(self.env_path).items()}

    def form_values(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for field in FIELDS:
            widget = self.query_one(f"#{_field_id(field.name)}")
            if isinstance(widget, Checkbox):
                result[field.name] = str(widget.value).lower()
            elif isinstance(widget, Select):
                result[field.name] = "" if widget.value is Select.BLANK else str(widget.value)
            else:
                result[field.name] = widget.value
        return result

    def refresh_configuration(self, announce_readiness: bool = False) -> None:
        values = self.values()
        self.update_count_destination_option(values)
        self.refresh_operation_readiness(values, announce=announce_readiness)

    def update_count_destination_option(self, values: dict[str, str]) -> None:
        select = self.query_one("#count-mode", Select)
        options = select.query_one(OptionList)
        destination_ready = account_ready(values, "DEST")
        if destination_ready:
            options.enable_option_at_index(1)
        else:
            if select.value == "destination":
                select.value = "source"
            options.disable_option_at_index(1)

    def refresh_history(self, select_run_id: str | None = None) -> None:
        table = self.query_one("#history-table", DataTable)
        selected_row: int | None = None
        selected_run_id: str | None = None
        records = [
            record for record in load_records() if record.status != "running" or record.run_id == self.current_run_id
        ][:20]
        with self.prevent(DataTable.RowHighlighted):
            table.clear()
            for row, record in enumerate(records):
                table.add_row(record.operation, record.status, record.started_at[:19], key=record.run_id)
                if record.run_id == select_run_id:
                    selected_row = row
            if selected_row is not None:
                table.move_cursor(row=selected_row)
                selected_run_id = select_run_id
            elif table.row_count:
                selected_run_id = self.selected_history_id()
        self.selected_output_id = selected_run_id
        self.render_output()
        self.filesystem_watcher.refresh("history")

    def select_operation(self, operation: OperationName) -> None:
        self.selected_operation = operation
        spec = OPERATION_BY_NAME[operation]
        separator = " - " if self.display_profile.mode == "ascii" else " · "
        self.query_one("#operation-panel").border_title = f"Operation{separator}{spec.title}"
        self.query_one("#operation-panel").styles.height = OPERATION_PANEL_HEIGHTS[operation]
        if self.has_class("narrow"):
            self.query_one("#sidebar").styles.height = 19 + OPERATION_PANEL_HEIGHTS[operation]
        run_button = self.query_one("#run-operation", Button)
        run_button.label = f"run {operation}"
        for widget in self.query(".count-control"):
            widget.set_class(operation != "count", "hidden")
        for widget in self.query(".compare-control"):
            widget.set_class(operation != "compare", "hidden")
        for widget in self.query(".migrate-control"):
            widget.set_class(operation != "migrate", "hidden")
        for widget in self.query(".backup-control"):
            widget.set_class(operation != "backup", "hidden")
        for widget in self.query(".restore-control"):
            widget.set_class(operation != "restore", "hidden")
        for widget in self.query(".transfer-control"):
            widget.set_class(operation not in {"backup", "restore"}, "hidden")
        self.query_one(".folder-label").set_class(operation not in {"backup", "restore"}, "hidden")
        for candidate in OPERATIONS:
            self.query_one(f"#tool-{candidate.name}", ToolButton).set_class(candidate.name == operation, "selected")
        self.refresh_operation_readiness(announce=True, force_notice=True)

    def operation_readiness(self, operation: OperationName, values: dict[str, str] | None = None) -> Readiness:
        """Return readiness using the operation modes currently selected in the TUI."""
        if values is None:
            values = self.values()
        return readiness(
            operation,
            values,
            count_mode=str(self.query_one("#count-mode", Select).value),
            compare_source_mode=str(self.query_one("#compare-source-mode", Select).value),
            compare_destination_mode=str(self.query_one("#compare-dest-mode", Select).value),
        )

    def refresh_operation_readiness(
        self,
        values: dict[str, str] | None = None,
        *,
        announce: bool = False,
        force_notice: bool = False,
    ) -> Readiness:
        """Synchronize every readiness affordance from one evaluation path."""
        if values is None:
            values = self.values()
        states = {operation.name: self.operation_readiness(operation.name, values) for operation in OPERATIONS}
        for operation in OPERATIONS:
            state = states[operation.name]
            if not state.ready:
                marker, color, label = self.display_profile.missing, "#777777", "Missing configuration"
            elif state.warning:
                marker, color, label = self.display_profile.warning, "#ffcc33", "Destructive options enabled"
            else:
                marker, color, label = self.display_profile.ready, "#44dd55", "Ready"
            indicator = self.query_one(f"#ready-{operation.name}", Static)
            indicator.update(f"[bold {color}]{marker}[/]")
            indicator.tooltip = f"{label}: {state.detail}"

        state = states[self.selected_operation]
        self.query_one("#run-operation", Button).disabled = not state.ready or self.operation_in_progress
        self.highlight_required_settings(state)
        notice_key = (self.selected_operation, state.detail)
        if announce and not self.operation_in_progress and (force_notice or notice_key != self.last_readiness_notice):
            severity = "error" if not state.ready else "warning" if state.warning else "information"
            self.notify(state.detail, title=OPERATION_BY_NAME[self.selected_operation].title, severity=severity)
            self.last_readiness_notice = notice_key
        return state

    def highlight_required_settings(self, state: Readiness | None = None) -> None:
        state = state or self.operation_readiness(self.selected_operation)
        required = state.required_fields
        missing = state.missing_fields
        operation = OPERATION_BY_NAME[self.selected_operation].title
        for field in FIELDS:
            control = self.query_one(f"#{_field_id(field.name)}")
            label = self.query_one(f"#label-{_field_id(field.name)}", Label)
            is_required = field.name in required
            is_missing = field.name in missing
            control.set_class(is_required, "required-setting")
            label.set_class(is_required, "required-setting-label")
            control.set_class(is_missing, "missing-setting")
            label.set_class(is_missing, "missing-setting-label")
            guidance = f"Required for {operation}"
            if is_missing and field.name.endswith(("_IMAP_PASSWORD", "_OAUTH2_CLIENT_ID")):
                guidance = f"Provide either a password or OAuth2 client ID for {operation}"
            elif field.name.endswith(("_IMAP_PASSWORD", "_OAUTH2_CLIENT_ID", "_OAUTH2_CLIENT_SECRET", "_ACCOUNT_TYPE")):
                guidance = f"Authentication option for {operation}"
            missing_separator = " - " if self.display_profile.mode == "ascii" else " — "
            control.tooltip = (
                f"Missing{missing_separator}{guidance}" if is_missing else guidance if is_required else None
            )

    def selected_operation_readiness(self):
        return self.operation_readiness(self.selected_operation)

    @on(Select.Changed, "#count-mode")
    def count_mode_changed(self) -> None:
        if self.selected_operation == "count":
            self.refresh_operation_readiness(announce=True)

    @on(Select.Changed, "#compare-source-mode, #compare-dest-mode")
    def compare_mode_changed(self) -> None:
        if self.selected_operation == "compare":
            self.refresh_operation_readiness(announce=True)

    def run_options(self) -> RunOptions:
        return make_options(
            self.selected_operation,
            self.values(),
            str(self.query_one("#count-mode", Select).value),
            str(self.query_one("#compare-source-mode", Select).value),
            str(self.query_one("#compare-dest-mode", Select).value),
            self.query_one("#folder", Input).value,
        )

    def request_confirmation(self, action: str, message: str, payload: object, require_delete: bool = False) -> None:
        self.pending_action = action
        self.pending_payload = payload
        self.push_screen(ConfirmationModal(message, require_delete), self.confirmation_dismissed)

    @on(Button.Pressed)
    def button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id.startswith("tool-"):
            self.select_operation(button_id.removeprefix("tool-"))  # type: ignore[arg-type]
        elif button_id == "run-operation":
            self.prepare_run()
        elif button_id == "cancel-run":
            self.cancel_operation()
        elif button_id == "force-stop":
            self.request_confirmation("force-stop", "Type DELETE to terminate the process immediately.", None, True)
        elif button_id == "export-history":
            self.export_history()
        elif button_id == "delete-history":
            run_id = self.selected_history_id()
            if run_id:
                self.request_confirmation("delete-history", "Delete the selected run and sanitized log?", run_id)

    def confirmation_dismissed(self, confirmed: bool | None) -> None:
        action, payload = self.pending_action, self.pending_payload
        self.pending_action = ""
        self.pending_payload = None
        if not confirmed:
            return
        if action == "run":
            self.start_operation(payload)  # type: ignore[arg-type]
        elif action == "force-stop":
            self.cancellation_requested = True
            self.runner.terminate()
        elif action == "delete-history":
            delete_record(str(payload))
            self.refresh_history()
        elif action == "quit":
            if self.runner.active:
                self.runner.terminate()
            self.exit()

    def schedule_configuration_save(self, delay: float = 0.6) -> None:
        if not self.configuration_autosave_enabled or self.configuration_reload_in_progress:
            return
        if self.configuration_save_timer is not None:
            self.configuration_save_timer.stop()
        suffix = "..." if self.display_profile.mode == "ascii" else "…"
        self.set_configuration_status(f"{self.display_profile.saving} saving{suffix}")
        self.configuration_save_timer = self.set_timer(delay, self.save_configuration)

    def save_configuration(self) -> bool:
        if self.configuration_save_timer is not None:
            self.configuration_save_timer.stop()
            self.configuration_save_timer = None
        if not self.query("#config-form").nodes:
            return False
        digest = self.env_digest()
        if digest != self.configuration_file_digest:
            self.reload_external_configuration(digest)
            return False
        values = self.form_values()
        errors = validate(values)
        if errors:
            name, message = next(iter(errors.items()))
            self.set_configuration_status(f"{self.display_profile.error} invalid: {name}")
            self.notify(f"{name}: {message}", severity="error")
            return False
        try:
            save_form(self.env_path, values)
        except (OSError, ValueError) as exc:
            self.set_configuration_status(f"{self.display_profile.error} save failed")
            self.notify(f"Unable to save: {exc}", severity="error")
            return False
        self.configuration_file_digest = self.env_digest()
        self.filesystem_watcher.refresh("configuration")
        self.configuration_rejected_digest = None
        self.refresh_configuration(announce_readiness=True)
        self.set_configuration_status(f"{self.display_profile.success} saved", reset_after=1.5)
        return True

    @on(Input.Changed, "#config-form Input")
    def configuration_text_changed(self) -> None:
        self.schedule_configuration_save()

    @on(Select.Changed, "#config-form Select")
    def configuration_choice_changed(self) -> None:
        self.schedule_configuration_save(0.05)

    @on(Checkbox.Changed, "#config-form AsciiCheckbox")
    def configuration_boolean_changed(self) -> None:
        self.schedule_configuration_save(0.05)

    def prepare_run(self) -> None:
        if not self.save_configuration():
            return
        if self.runner.active:
            self.notify("An operation is already running", severity="warning")
            return
        state = self.selected_operation_readiness()
        if not state.ready:
            self.notify(state.detail, severity="error")
            return
        try:
            options = self.run_options()
        except ValueError:
            self.notify("Workers and batch size must be positive integers", severity="error")
            return
        if options.workers < 1 or options.batch < 1:
            self.notify("Workers and batch size must be positive", severity="error")
            return
        if self.selected_operation == "compare":
            local_selections = (
                ("SRC_LOCAL_PATH", "#compare-source-mode"),
                ("DEST_LOCAL_PATH", "#compare-dest-mode"),
            )
            values = self.values()
            for variable, mode_id in local_selections:
                if self.query_one(mode_id, Select).value == "local" and not values.get(variable):
                    self.notify(f"{variable} requires a path for local mode", severity="error")
                    return
        message, destructive = run_confirmation(self.selected_operation, options, self.values())
        self.request_confirmation("run", message, options, bool(destructive))

    @work(exclusive=True, group="operation")
    async def start_operation(self, options: RunOptions) -> None:
        operation = OPERATION_BY_NAME[self.selected_operation]
        self.operation_in_progress = True
        self.refresh_operation_readiness()
        self.log_lines.clear()
        self.query_one("#output-log", RichLog).clear()
        values = self.values()
        session = RunSession(operation.name, values, writer_factory=HistoryWriter)
        self.progress = session.progress
        self.query_one("#cancel-run", Button).disabled = False
        record = session.record
        self.cancellation_requested = False
        self.current_run_id = record.run_id
        self.selected_output_id = record.run_id
        self.history_writer = session.writer
        if session.warning:
            self.notify(session.warning, severity="warning")
        else:
            self.refresh_history(self.selected_output_id)
        request = self._make_run_request(operation.name, options)

        async def receive(line: str) -> None:
            sanitized = session.receive(line)
            self.log_lines.append(sanitized)
            if self.selected_output_id == record.run_id:
                match = self.query_one("#output-filter", Input).value.lower()
                if not match or match in sanitized.lower():
                    self.query_one("#output-log", RichLog).write(sanitized)

        exit_code = -1
        try:
            exit_code = await self.runner.run(request, receive)
            record.status = "cancelled" if self.cancellation_requested else "completed" if exit_code == 0 else "failed"
            record.exit_code = exit_code
        except Exception as exc:
            record.status = "failed"
            record.exit_code = -1
            await receive(f"TUI runner error: {exc}")
        finally:
            session.finish(exit_code, self.cancellation_requested)
            self.history_writer = None
            self.query_one("#cancel-run", Button).disabled = True
            self.query_one("#force-stop", Button).disabled = True
            self.operation_in_progress = False
            self.refresh_operation_readiness()
            self.refresh_history(self.selected_output_id)
            severity = "warning" if record.status == "cancelled" else "information" if exit_code == 0 else "error"
            self.notify(f"{operation.title} {record.status}", severity=severity)

    def _make_run_request(self, operation: OperationName, options: RunOptions) -> RunRequest:
        """Build a request containing only genuine per-operation environment overrides."""
        operation_environment = dict(options.environment)
        return RunRequest(
            build_command(OPERATION_BY_NAME[operation], options),
            self.working_directory,
            operation_environment,
            operation_environment,
        )

    @work(exclusive=True, group="cancellation")
    async def cancel_operation(self) -> None:
        self.cancellation_requested = True
        self.notify("Cancellation requested; waiting for cleanup", severity="warning")
        if not await self.runner.interrupt():
            self.query_one("#force-stop", Button).disabled = False
            self.notify("Still running; force stop is available", severity="warning")

    def selected_history_id(self) -> str | None:
        table = self.query_one("#history-table", DataTable)
        if not table.row_count:
            return None
        return str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)

    @on(DataTable.RowHighlighted, "#history-table")
    def history_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self.view_history(str(event.row_key.value))

    def view_history(self, run_id: str | None = None) -> None:
        run_id = run_id or self.selected_history_id()
        if not run_id:
            return
        self.selected_output_id = run_id
        self.render_output()

    def render_output(self) -> None:
        log = self.query_one("#output-log", RichLog)
        log.clear()
        match = self.query_one("#output-filter", Input).value.lower()
        lines = (
            self.log_lines
            if self.selected_output_id == self.current_run_id
            else read_log(self.selected_output_id or "").splitlines()
        )
        for line in lines:
            if not match or match in line.lower():
                log.write(line)

    def export_history(self) -> None:
        run_id = self.selected_history_id()
        if not run_id:
            return
        destination = self.working_directory / f"imap-tools-{run_id}.log"
        try:
            destination.write_text(read_log(run_id), encoding="utf-8")
            if os.name != "nt":
                destination.chmod(0o600)
        except OSError as exc:
            self.notify(f"Could not export: {exc}", severity="error")
            return
        self.notify(f"Exported {destination}")

    @on(Input.Changed, "#output-filter")
    def filter_output(self) -> None:
        self.render_output()

    def action_select_operation(self, operation: str) -> None:
        self.select_operation(operation)  # type: ignore[arg-type]

    def action_focus_config(self) -> None:
        self.query_one("#config-form").focus()

    def action_focus_operation(self) -> None:
        first_control = {
            "count": "#count-mode",
            "compare": "#compare-source-mode",
            "backup": "#folder",
            "restore": "#folder",
            "migrate": "#run-operation",
        }[self.selected_operation]
        self.query_one(first_control).focus()

    def action_focus_log(self) -> None:
        self.query_one("#output-filter", Input).focus()

    def action_start_selected(self) -> None:
        self.prepare_run()

    def action_reset_layout(self) -> None:
        if self.has_class("narrow") or self.has_class("medium"):
            if not self.is_headless or self.layout_path_explicit:
                try:
                    save_layout(self.layout_path, {})
                except OSError as exc:
                    self.notify(f"Could not reset panel layout: {exc}", severity="warning")
                    return
            self.apply_responsive_layout(self.has_class("narrow"))
            self.notify("Panel layout reset")
            return
        self.query_one("#center-column").styles.width = "2fr"
        self.query_one("#sidebar").styles.width = 47
        self.query_one("#right-column").styles.width = "3fr"
        self.query_one("#tools-panel").styles.height = 7
        self.query_one("#operation-panel").styles.height = OPERATION_PANEL_HEIGHTS[self.selected_operation]
        self.query_one("#history-panel").styles.height = "1fr"
        self.call_after_refresh(self.save_current_layout)
        self.notify("Panel layout reset")

    def action_show_keys(self) -> None:
        self.show_information("Keyboard shortcuts", KEY_REFERENCE)

    def action_show_help(self) -> None:
        self.show_information("Help", GENERAL_HELP)

    def show_information(self, title: str, content: str) -> None:
        """Open one reference dialog, replacing an existing reference dialog."""
        screen = InformationModal(title, content)
        if isinstance(self.screen, InformationModal):
            self.switch_screen(screen)
        else:
            self.push_screen(screen)

    def action_request_quit(self) -> None:
        if self.configuration_autosave_enabled and not self.save_configuration():
            return
        if self.runner.active:
            self.request_confirmation("quit", "Type DELETE to terminate the active run and quit.", None, True)
        else:
            self.exit()


def main(argv: list[str] | None = None) -> None:
    """Launch the full-screen workspace."""
    import argparse

    parser = argparse.ArgumentParser(description="Full-screen interface for IMAP Migration Tools")
    parser.add_argument(
        "--display-mode",
        choices=DISPLAY_MODES,
        default=os.environ.get("IMAP_TOOLS_DISPLAY_MODE", "auto"),
        help="terminal compatibility profile (default: IMAP_TOOLS_DISPLAY_MODE or auto)",
    )
    args = parser.parse_args(argv)
    ImapToolsApp(display_profile=resolve_display_profile(args.display_mode)).run()


if __name__ == "__main__":
    main()
