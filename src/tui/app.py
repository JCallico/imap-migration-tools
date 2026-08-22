"""Single-workspace Textual application for IMAP Migration Tools."""

from __future__ import annotations

import os
from collections import deque
from datetime import datetime, timezone
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
    SECRET_NAMES,
    discover_env,
    effective_values,
    read_env,
    save_form,
    validate,
)
from tui.history import HistoryWriter, Redactor, delete_record, load_records, new_record, read_log
from tui.operations import (
    OPERATION_BY_NAME,
    OPERATIONS,
    OperationName,
    ProgressState,
    Readiness,
    RunOptions,
    account_ready,
    account_settings,
    build_command,
    parse_output,
    readiness,
    required_settings,
)
from tui.runner import OperationRunner, RunRequest
from tui.splitter import ResizeHandle


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


OPERATION_SWITCHES: dict[str, tuple[str, ...]] = {
    "count": (),
    "compare": (),
    "backup": (
        "PRESERVE_LABELS",
        "PRESERVE_FLAGS",
        "MANIFEST_ONLY",
        "GMAIL_MODE",
        "DEST_DELETE",
    ),
    "restore": (
        "APPLY_LABELS",
        "APPLY_FLAGS",
        "GMAIL_MODE",
        "FULL_RESTORE",
        "DEST_DELETE",
    ),
    "migrate": (
        "DELETE_FROM_SOURCE",
        "DEST_DELETE",
        "PRESERVE_LABELS",
        "PRESERVE_FLAGS",
        "GMAIL_MODE",
        "FULL_MIGRATE",
    ),
}

OPERATION_PANEL_HEIGHTS: dict[OperationName, int] = {
    "count": 5,
    "compare": 8,
    "backup": 5,
    "restore": 6,
    "migrate": 5,
}


class ImapToolsApp(App[None]):
    """Dense, full-terminal workspace with inline navigation."""

    CSS_PATH = "styles.tcss"
    TITLE = "IMAP Migration Tools"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [
        Binding("alt+1", "select_operation('count')", "count", show=False, priority=True),
        Binding("alt+2", "select_operation('compare')", "compare", show=False, priority=True),
        Binding("alt+3", "select_operation('backup')", "backup", show=False, priority=True),
        Binding("alt+4", "select_operation('restore')", "restore", show=False, priority=True),
        Binding("alt+5", "select_operation('migrate')", "migrate", show=False, priority=True),
        Binding("alt+c", "focus_config", "config", show=False, priority=True),
        Binding("alt+o", "focus_operation", "operation", show=False, priority=True),
        Binding("alt+l", "focus_log", "log", show=False, priority=True),
        Binding("alt+r", "start_selected", "run", show=False, priority=True),
        Binding("alt+q", "request_quit", "quit", show=False, priority=True),
    ]

    def __init__(self, env_path: Path | None = None) -> None:
        super().__init__()
        self.working_directory = Path.cwd()
        self.env_path = env_path or discover_env()
        self.runner = OperationRunner()
        self.selected_operation: OperationName = "count"
        self.progress = ProgressState()
        self.log_lines: deque[str] = deque(maxlen=5000)
        self.current_run_id: str | None = None
        self.selected_output_id: str | None = None
        self.history_writer: HistoryWriter | None = None
        self.pending_action = ""
        self.pending_payload: object | None = None
        self.configuration_autosave_enabled = False
        self.configuration_save_timer: Timer | None = None

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
                                yield Label(f"── {group} ", classes="group-title")
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
                    id="tools-operation-handle",
                )
                with VerticalScroll(id="operation-panel", classes="panel"):
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
                    yield Label("Source side", classes="compare-control control-label")
                    yield Select(
                        (("automatic", "auto"), ("source IMAP", "imap"), ("local path", "local")),
                        value="auto",
                        compact=True,
                        id="compare-source-mode",
                        classes="compare-control",
                    )
                    yield Label("Destination side", classes="compare-control control-label")
                    yield Select(
                        (("automatic", "auto"), ("destination IMAP", "imap"), ("local path", "local")),
                        value="auto",
                        compact=True,
                        id="compare-dest-mode",
                        classes="compare-control",
                    )
                    yield Label("Only this folder", classes="transfer-control control-label folder-label")
                    yield Input(id="folder", placeholder="leave empty for all folders", classes="transfer-control")
                    yield Button("run count", id="run-operation", variant="success", classes="wide-action")
                yield ResizeHandle(
                    "operation-panel", "history-panel", "horizontal", minimum_before=5, id="operation-history-handle"
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
                id="sidebar-right-handle",
            )
            with Vertical(id="right-column"):
                with Vertical(id="monitor-panel", classes="panel"):
                    yield Input(placeholder="filter output", id="output-filter")
                    yield RichLog(id="output-log", wrap=True, markup=False, max_lines=5000, auto_scroll=True)
                    with Horizontal(classes="compact-actions"):
                        yield Button("cancel", id="cancel-run", disabled=True)
                        yield Button("force stop", id="force-stop", disabled=True)
                        yield Button("clear output", id="clear-output")
        yield Static(
            "[bold #388bff]Alt+1-5[/] tool   [bold #388bff]Alt+C/O/L[/] config/operation/log   "
            "[bold #44dd55]Alt+R[/] run   [bold #e6d84a]drag/arrows[/] resize   "
            "[bold #ff4d4d]Alt+Q[/] quit",
            id="key-legend",
        )

    def on_mount(self) -> None:
        titles = {
            "tools-panel": "Tools",
            "history-panel": "History",
            "config-panel": "Configuration",
            "operation-panel": "Operation · Count",
            "monitor-panel": "Output",
        }
        for widget_id, title in titles.items():
            self.query_one(f"#{widget_id}").border_title = title
        history = self.query_one("#history-table", DataTable)
        history.add_columns("operation", "status", "started")
        self.refresh_configuration()
        self.refresh_history()
        self.select_operation("count")
        self.call_after_refresh(self.enable_configuration_autosave)

    def enable_configuration_autosave(self) -> None:
        self.configuration_autosave_enabled = True
        self.query_one("#config-panel").border_subtitle = "autosave"

    def on_resize(self, event: Resize) -> None:
        self.set_class(event.size.width < 120, "narrow")

    def on_unmount(self) -> None:
        if self.configuration_save_timer is not None:
            self.configuration_save_timer.stop()
            self.configuration_save_timer = None

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

    def refresh_configuration(self) -> None:
        values = self.values()
        for operation in OPERATIONS:
            state = readiness(operation.name, values)
            color = "#44dd55" if state.ready else "#777777"
            marker = "✓" if state.ready else "○"
            label = "Ready" if state.ready else "Missing configuration"
            if state.warning:
                marker = "⚠"
                label = "Destructive options enabled"
                color = "#ffcc33"
            indicator = self.query_one(f"#ready-{operation.name}", Static)
            indicator.update(f"[bold {color}]{marker}[/]")
            indicator.tooltip = f"{label}: {state.detail}"
        self.update_count_destination_option(values)
        self.highlight_required_settings()

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
        table.clear()
        selected_row: int | None = None
        for row, record in enumerate(load_records()[:20]):
            table.add_row(record.operation, record.status, record.started_at[:19], key=record.run_id)
            if record.run_id == select_run_id:
                selected_row = row
        if selected_row is not None:
            table.move_cursor(row=selected_row)

    def select_operation(self, operation: OperationName) -> None:
        self.selected_operation = operation
        spec = OPERATION_BY_NAME[operation]
        self.query_one("#operation-panel").border_title = f"Operation · {spec.title}"
        self.query_one("#operation-panel").styles.height = OPERATION_PANEL_HEIGHTS[operation]
        self.highlight_required_settings()
        run_button = self.query_one("#run-operation", Button)
        run_button.label = f"run {operation}"
        run_button.disabled = not self.selected_operation_readiness().ready or self.runner.active
        for widget in self.query(".count-control"):
            widget.set_class(operation != "count", "hidden")
        for widget in self.query(".compare-control"):
            widget.set_class(operation != "compare", "hidden")
        for widget in self.query(".transfer-control"):
            widget.set_class(operation not in {"backup", "restore"}, "hidden")
        self.query_one(".folder-label").set_class(operation != "restore", "hidden")
        for candidate in OPERATIONS:
            self.query_one(f"#tool-{candidate.name}", ToolButton).set_class(candidate.name == operation, "selected")

    def highlight_required_settings(self) -> None:
        values = self.values()
        if self.selected_operation == "count":
            mode = str(self.query_one("#count-mode", Select).value)
            if mode == "local":
                required = {"BACKUP_LOCAL_PATH"}
                missing = set() if values.get("BACKUP_LOCAL_PATH") else {"BACKUP_LOCAL_PATH"}
            else:
                prefix = "DEST" if mode == "destination" else "SRC"
                required, missing = account_settings(values, prefix)
        else:
            required, missing = required_settings(self.selected_operation, values)
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
            control.tooltip = f"Missing — {guidance}" if is_missing else guidance if is_required else None

    def selected_operation_readiness(self):
        values = self.values()
        if self.selected_operation != "count":
            return readiness(self.selected_operation, values)
        mode = str(self.query_one("#count-mode", Select).value)
        if mode == "local":
            for name in (
                "SRC_IMAP_HOST",
                "SRC_IMAP_USERNAME",
                "SRC_IMAP_PASSWORD",
                "SRC_OAUTH2_CLIENT_ID",
                "IMAP_HOST",
                "IMAP_USERNAME",
                "IMAP_PASSWORD",
                "OAUTH2_CLIENT_ID",
            ):
                values[name] = ""
            return readiness("count", values)
        prefix = "DEST" if mode == "destination" else "SRC"
        ready = account_ready(values, prefix)
        return Readiness(
            ready, f"{prefix.title()} account is ready" if ready else f"Configure the {prefix.lower()} account"
        )

    @on(Select.Changed, "#count-mode")
    def count_mode_changed(self) -> None:
        if self.selected_operation == "count":
            self.select_operation("count")

    def run_options(self) -> RunOptions:
        operation = self.selected_operation
        values = self.values()
        switches = {name: values.get(name, "false").lower() == "true" for name in OPERATION_SWITCHES[operation]}
        environment: dict[str, str] = {}
        if operation == "count":
            mode = str(self.query_one("#count-mode", Select).value)
            return RunOptions(switches=switches, target=mode)
        if operation == "compare":
            source_mode = str(self.query_one("#compare-source-mode", Select).value)
            destination_mode = str(self.query_one("#compare-dest-mode", Select).value)
            source_path = ""
            destination_path = ""
            if source_mode == "imap":
                environment["SRC_LOCAL_PATH"] = ""
            elif source_mode == "local":
                source_path = values.get("SRC_LOCAL_PATH", "")
            if destination_mode == "imap":
                environment["DEST_LOCAL_PATH"] = ""
            elif destination_mode == "local":
                destination_path = values.get("DEST_LOCAL_PATH", "")
            return RunOptions(
                switches=switches,
                environment=environment,
                source_path=source_path,
                destination_path=destination_path,
            )
        workers = int(values.get("MAX_WORKERS", "4") or "4")
        batch = int(values.get("BATCH_SIZE", "10") or "10")
        folder = self.query_one("#folder", Input).value if operation in {"backup", "restore"} else ""
        return RunOptions(folder, workers, batch, "", switches, environment)

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
        elif button_id == "clear-output":
            self.query_one("#output-log", RichLog).clear()
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
            self.runner.terminate()
        elif action == "delete-history":
            delete_record(str(payload))
            self.refresh_history()
        elif action == "quit":
            if self.runner.active:
                self.runner.terminate()
            self.exit()

    def schedule_configuration_save(self, delay: float = 0.6) -> None:
        if not self.configuration_autosave_enabled:
            return
        if self.configuration_save_timer is not None:
            self.configuration_save_timer.stop()
        self.query_one("#config-panel").border_subtitle = "unsaved"
        self.configuration_save_timer = self.set_timer(delay, self.save_configuration)

    def save_configuration(self) -> bool:
        if self.configuration_save_timer is not None:
            self.configuration_save_timer.stop()
            self.configuration_save_timer = None
        if not self.query("#config-form").nodes:
            return False
        values = self.form_values()
        errors = validate(values)
        if errors:
            name, message = next(iter(errors.items()))
            self.query_one("#config-panel").border_subtitle = f"invalid: {name}"
            self.notify(f"{name}: {message}", severity="error")
            return False
        try:
            save_form(self.env_path, values)
        except (OSError, ValueError) as exc:
            self.query_one("#config-panel").border_subtitle = "save failed"
            self.notify(f"Unable to save: {exc}", severity="error")
            return False
        self.refresh_configuration()
        self.select_operation(self.selected_operation)
        self.query_one("#config-panel").border_subtitle = "saved"
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
        destructive = options.switches.get("DELETE_FROM_SOURCE") or options.switches.get("DEST_DELETE")
        message = f"Run {self.selected_operation}?"
        if destructive:
            values = self.values()
            targets: list[str] = []
            if options.switches.get("DELETE_FROM_SOURCE"):
                targets.append(f"source {values.get('SRC_IMAP_USERNAME')}@{values.get('SRC_IMAP_HOST')}")
            if options.switches.get("DEST_DELETE"):
                target = (
                    values.get("BACKUP_LOCAL_PATH")
                    if self.selected_operation == "backup"
                    else f"{values.get('DEST_IMAP_USERNAME')}@{values.get('DEST_IMAP_HOST')}"
                )
                targets.append(f"destination {target}")
            message = f"Type DELETE to run {self.selected_operation} and remove data from {', '.join(targets)}."
        self.request_confirmation("run", message, options, bool(destructive))

    @work(exclusive=True, group="operation")
    async def start_operation(self, options: RunOptions) -> None:
        operation = OPERATION_BY_NAME[self.selected_operation]
        self.log_lines.clear()
        self.query_one("#output-log", RichLog).clear()
        self.progress = ProgressState()
        self.query_one("#cancel-run", Button).disabled = False
        self.query_one("#run-operation", Button).disabled = True
        values = self.values()
        redactor = Redactor([values.get(name, "") for name in SECRET_NAMES])
        record = new_record(operation.name)
        self.current_run_id = record.run_id
        self.selected_output_id = record.run_id
        try:
            self.history_writer = HistoryWriter(record, redactor)
            self.refresh_history(self.selected_output_id)
        except OSError as exc:
            self.history_writer = None
            self.notify(f"History unavailable: {exc}", severity="warning")
        request = self._make_run_request(operation.name, options)

        async def receive(line: str) -> None:
            sanitized = self.history_writer.write(line) if self.history_writer else redactor(line)
            self.log_lines.append(sanitized)
            if self.selected_output_id == record.run_id:
                match = self.query_one("#output-filter", Input).value.lower()
                if not match or match in sanitized.lower():
                    self.query_one("#output-log", RichLog).write(sanitized)
            parse_output(sanitized, self.progress)

        exit_code = -1
        try:
            exit_code = await self.runner.run(request, receive)
            record.status = "completed" if exit_code == 0 else "failed"
            record.exit_code = exit_code
        except Exception as exc:
            record.status = "failed"
            record.exit_code = -1
            await receive(f"TUI runner error: {exc}")
        finally:
            record.finished_at = datetime.now(timezone.utc).isoformat()
            record.copied = self.progress.copied
            record.skipped = self.progress.skipped
            record.failed = self.progress.failed
            record.deleted = self.progress.deleted
            if self.history_writer:
                self.history_writer.close()
                self.history_writer = None
            self.query_one("#cancel-run", Button).disabled = True
            self.query_one("#force-stop", Button).disabled = True
            self.query_one("#run-operation", Button).disabled = not readiness(operation.name, self.values()).ready
            self.refresh_history(self.selected_output_id)
            self.notify(f"{operation.title} {record.status}", severity="information" if exit_code == 0 else "error")

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

    def action_request_quit(self) -> None:
        if self.configuration_autosave_enabled and not self.save_configuration():
            return
        if self.runner.active:
            self.request_confirmation("quit", "Type DELETE to terminate the active run and quit.", None, True)
        else:
            self.exit()


def main() -> None:
    """Launch the full-screen workspace."""
    ImapToolsApp().run()


if __name__ == "__main__":
    main()
