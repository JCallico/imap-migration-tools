"""Single-workspace Textual interaction and responsive-layout tests."""

from __future__ import annotations

import asyncio

import pytest
from textual.widgets import Button, Checkbox, DataTable, Input, OptionList, RichLog, Select, Static

import tui.app as app_module
from tui.app import ConfirmationModal, ImapToolsApp
from tui.config import read_env
from tui.operations import RunOptions


@pytest.mark.parametrize(
    ("size", "narrow"), [((60, 20), True), ((80, 24), True), ((120, 40), False), ((180, 50), False)]
)
def test_app_uses_one_responsive_workspace(tmp_path, size, narrow):
    async def run_test():
        app = ImapToolsApp(tmp_path / ".env")
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            assert len(app.screen_stack) == 1
            assert len(app.query(".panel")) == 5
            assert app.has_class("narrow") is narrow
            if not narrow:
                assert app.query_one("#center-column").region.x < app.query_one("#sidebar").region.x
                assert app.query_one("#sidebar").region.x < app.query_one("#right-column").region.x

    asyncio.run(run_test())


def test_keyboard_switches_tools_without_changing_screen(tmp_path):
    async def run_test():
        app = ImapToolsApp(tmp_path / ".env")
        async with app.run_test(size=(160, 40)) as pilot:
            original_screen = app.screen
            config_input = app.query_one("#env-src-imap-host", Input)
            config_input.focus()
            await pilot.press("alt+5")
            await pilot.pause()
            assert app.selected_operation == "migrate"
            assert config_input.value == ""
            assert app.screen is original_screen
            assert len(app.screen_stack) == 1

    asyncio.run(run_test())


def test_alt_o_focuses_operation_panel(tmp_path):
    async def run_test():
        app = ImapToolsApp(tmp_path / ".env")
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.press("alt+o")
            assert app.focused is app.query_one("#count-mode")

    asyncio.run(run_test())


def test_tools_use_icons_for_readiness(tmp_path):
    async def run_test():
        app = ImapToolsApp(tmp_path / ".env")
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            indicator = app.query_one("#ready-count", Static)
            assert str(indicator.render()) == "○"
            assert str(indicator.tooltip).startswith("Missing configuration:")

    asyncio.run(run_test())


def test_configuration_is_one_form_populated_with_defaults(tmp_path):
    async def run_test():
        app = ImapToolsApp(tmp_path / ".env")
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            assert app.query_one("#config-panel").border_title == "Configuration"
            section_titles = list(app.query(".group-title"))
            assert len(section_titles) == 10
            assert all(title.region.height == 1 for title in section_titles)
            assert all("imap-count aliases" not in str(title.render()) for title in section_titles)
            assert app.query("#env-imap-host").nodes == []
            assert app.query("#env-oauth2-client-id").nodes == []
            assert app.query("#config-tabs").nodes == []
            assert app.query("#raw-editor").nodes == []
            assert app.query("#effective-table").nodes == []
            assert app.query_one("#env-max-workers", Input).value == "4"
            assert app.query_one("#env-oauth2-cache-enabled", Checkbox).value is True
            account_type = app.query_one("#env-src-account-type", Select)
            assert account_type.value == "auto"
            assert str(account_type.query_one("#label", Static).render()) == "auto"
            account_type.focus()
            await pilot.press("enter", "down", "enter")
            assert account_type.value == "personal"
            assert str(account_type.query_one("#label", Static).render()) == "personal"

            delete_from_source = app.query_one("#env-delete-from-source", Checkbox)
            assert delete_from_source.value is False
            assert delete_from_source.render().plain == "[ ]"
            assert delete_from_source.region.width >= 4
            delete_from_source.scroll_visible()
            await pilot.pause()
            await pilot.click("#env-delete-from-source")
            assert delete_from_source.value is True
            assert delete_from_source.render().plain == "[x]"

    asyncio.run(run_test())


def test_sidebar_keeps_simplified_operations_compact(tmp_path):
    async def run_test():
        app = ImapToolsApp(tmp_path / ".env")
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            assert app.query_one("#tools-panel").region.height == 7
            assert app.query("#operation-description").nodes == []
            assert app.query(".operation-rule").nodes == []
            count_height = app.query_one("#operation-panel").region.height
            app.select_operation("migrate")
            await pilot.pause()

            assert app.query_one("#operation-panel").region.height == count_height
            assert app.query("#migrate-cache").nodes == []
            assert app.query(".option-control").nodes == []
            assert app.query("#compare-source-path").nodes == []
            assert app.query("#compare-dest-path").nodes == []

    asyncio.run(run_test())


@pytest.mark.parametrize("operation", ("compare", "restore"))
def test_operation_panel_does_not_scroll_when_controls_fit(tmp_path, operation):
    async def run_test():
        app = ImapToolsApp(tmp_path / ".env")
        async with app.run_test(size=(160, 40)) as pilot:
            app.select_operation(operation)
            await pilot.pause()
            assert app.query_one("#operation-panel").max_scroll_y == 0

    asyncio.run(run_test())


def test_transfer_options_use_configuration_performance_values(tmp_path):
    async def run_test():
        env_path = tmp_path / ".env"
        env_path.write_text('MAX_WORKERS="7"\nBATCH_SIZE="25"\n', encoding="utf-8")
        app = ImapToolsApp(env_path)
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            app.select_operation("backup")
            options = app.run_options()
            assert app.query_one(".folder-label").has_class("hidden")
            assert options.workers == 7
            assert options.batch == 25
            assert app.query("#workers").nodes == []
            assert app.query("#batch").nodes == []

            app.select_operation("migrate")
            assert app.query_one("#folder").has_class("hidden")

    asyncio.run(run_test())


def test_run_request_does_not_flatten_configuration_into_os_environment(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        'SRC_IMAP_HOST="imap.example.com"\nSRC_IMAP_USERNAME="user"\nSRC_IMAP_PASSWORD="secret"\n',
        encoding="utf-8",
    )
    app = ImapToolsApp(env_path)
    request = app._make_run_request("backup", RunOptions(environment={"SRC_LOCAL_PATH": ""}))
    assert request.environment == {"SRC_LOCAL_PATH": ""}
    assert "SRC_IMAP_HOST" not in request.environment
    assert "SRC_IMAP_PASSWORD" not in request.environment


def test_count_defaults_to_imap_and_has_no_local_override(tmp_path):
    async def run_test():
        env_path = tmp_path / ".env"
        env_path.write_text(
            'SRC_IMAP_HOST="imap.example.com"\nSRC_IMAP_USERNAME="user"\nSRC_IMAP_PASSWORD="secret"\n'
            f'BACKUP_LOCAL_PATH="{tmp_path}"\n',
            encoding="utf-8",
        )
        app = ImapToolsApp(env_path)
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            assert app.query("#count-path").nodes == []
            assert app.query(".count-control.control-label").nodes == []

            count_mode = app.query_one("#count-mode", Select)
            assert count_mode.value == "source"
            count_options = count_mode.query_one(OptionList)
            assert not count_options.get_option_at_index(0).disabled
            assert count_options.get_option_at_index(1).disabled
            default_options = app.run_options()
            assert default_options.target == "source"
            assert default_options.environment == {}

            count_mode.value = "local"
            local = app.run_options()
            assert local.target == "local"

            count_mode.value = "source"
            imap = app.run_options()
            assert imap.target == "source"

    asyncio.run(run_test())


def test_count_source_imap_accepts_empty_local_path_overrides(tmp_path):
    async def run_test():
        env_path = tmp_path / ".env"
        env_path.write_text(
            'SRC_IMAP_HOST="imap.example.com"\nSRC_IMAP_USERNAME="user"\nSRC_IMAP_PASSWORD="secret"\n'
            f'BACKUP_LOCAL_PATH="{tmp_path}"\n',
            encoding="utf-8",
        )
        app = ImapToolsApp(env_path)
        async with app.run_test(size=(160, 40)) as pilot:
            app.query_one("#count-mode", Select).value = "source"
            await pilot.pause()
            app.prepare_run()
            await pilot.pause()

            assert app.pending_action == "run"
            assert isinstance(app.screen, ConfirmationModal)

    asyncio.run(run_test())


def test_count_destination_account_is_enabled_and_selected_when_configured(tmp_path):
    async def run_test():
        env_path = tmp_path / ".env"
        env_path.write_text(
            'DEST_IMAP_HOST="dest.example.com"\nDEST_IMAP_USERNAME="dest-user"\nDEST_IMAP_PASSWORD="dest-secret"\n',
            encoding="utf-8",
        )
        app = ImapToolsApp(env_path)
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            count_mode = app.query_one("#count-mode", Select)
            assert not count_mode.query_one(OptionList).get_option_at_index(1).disabled
            count_mode.value = "destination"
            options = app.run_options()
            assert options.target == "destination"
            assert options.environment == {}

    asyncio.run(run_test())


def test_selected_operation_highlights_required_and_missing_configuration(tmp_path):
    async def run_test():
        env_path = tmp_path / ".env"
        env_path.write_text(
            'SRC_IMAP_HOST="imap.example.com"\nSRC_IMAP_USERNAME="user"\nSRC_IMAP_PASSWORD="secret"\n',
            encoding="utf-8",
        )
        app = ImapToolsApp(env_path)
        async with app.run_test(size=(160, 40)) as pilot:
            app.select_operation("backup")
            await pilot.pause()
            source_host = app.query_one("#env-src-imap-host")
            backup_path = app.query_one("#env-backup-local-path")
            unrelated = app.query_one("#env-dest-imap-host")
            assert source_host.has_class("required-setting")
            assert not source_host.has_class("missing-setting")
            assert backup_path.has_class("required-setting")
            assert backup_path.has_class("missing-setting")
            assert app.query_one("#env-src-oauth2-client-id").has_class("required-setting")
            assert app.query_one("#env-src-oauth2-client-secret").has_class("required-setting")
            assert app.query_one("#env-src-account-type").has_class("required-setting")
            assert not unrelated.has_class("required-setting")

    asyncio.run(run_test())


def test_count_highlights_all_authentication_options_for_selected_account(tmp_path):
    async def run_test():
        env_path = tmp_path / ".env"
        env_path.write_text(
            'SRC_IMAP_HOST="src.example.com"\nSRC_IMAP_USERNAME="source"\nSRC_IMAP_PASSWORD="secret"\n'
            'DEST_IMAP_HOST="dest.example.com"\nDEST_IMAP_USERNAME="destination"\nDEST_IMAP_PASSWORD="secret"\n',
            encoding="utf-8",
        )
        app = ImapToolsApp(env_path)
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            for name in (
                "src-imap-password",
                "src-oauth2-client-id",
                "src-oauth2-client-secret",
                "src-account-type",
            ):
                assert app.query_one(f"#env-{name}").has_class("required-setting")
            assert not app.query_one("#env-dest-oauth2-client-id").has_class("required-setting")

            app.query_one("#count-mode", Select).value = "destination"
            await pilot.pause()
            assert app.query_one("#env-dest-oauth2-client-id").has_class("required-setting")
            assert not app.query_one("#env-src-oauth2-client-id").has_class("required-setting")

    asyncio.run(run_test())


def test_configuration_changes_are_autosaved(tmp_path):
    async def run_test():
        env_path = tmp_path / ".env"
        app = ImapToolsApp(env_path)
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            app.query_one("#env-src-imap-password").value = "secret-value"
            await pilot.pause(0.7)
            assert read_env(env_path)["SRC_IMAP_PASSWORD"] == "secret-value"
            assert app.query_one("#config-panel").border_subtitle == "saved"
            assert app.query("#save-form").nodes == []

    asyncio.run(run_test())


def test_run_review_uses_native_modal(tmp_path):
    async def run_test():
        env_path = tmp_path / ".env"
        env_path.write_text(f'BACKUP_LOCAL_PATH="{tmp_path}"\n', encoding="utf-8")
        app = ImapToolsApp(env_path)
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            original_screen = app.screen
            app.query_one("#count-mode", Select).value = "local"
            await pilot.pause()
            app.prepare_run()
            assert app.pending_action == "run"
            await pilot.pause()
            assert isinstance(app.screen, ConfirmationModal)
            assert app.screen is not original_screen
            assert original_screen in app.screen_stack
            assert len(app.screen_stack) == 2
            dialog = app.screen.query_one("#confirm-dialog")
            assert dialog.region.center[0] == app.screen.region.center[0]
            assert abs(dialog.region.center[1] - app.screen.region.center[1]) <= 0.5
            assert dialog.region.height <= 6
            assert app.screen.query("#confirm-title").nodes == []

    asyncio.run(run_test())


def test_confirmation_modal_yes_no_defaults_and_hotkeys(tmp_path):
    async def run_test():
        app = ImapToolsApp(tmp_path / ".env")
        async with app.run_test(size=(160, 40)) as pilot:
            original_screen = app.screen
            app.request_confirmation("test", "Proceed?", None)
            await pilot.pause()
            modal = app.screen
            assert isinstance(modal, ConfirmationModal)
            assert modal.query_one("#yes-action", Button).has_focus
            assert modal.query_one("#yes-action", Button).label.plain == "yes"
            assert modal.query_one("#no-action", Button).label.plain == "no"

            await pilot.press("enter")
            await pilot.pause()
            assert app.screen is original_screen
            assert app.pending_action == ""

            app.request_confirmation("test", "Proceed?", None)
            await pilot.pause()
            modal = app.screen
            assert isinstance(modal, ConfirmationModal)
            modal.query_one("#no-action", Button).focus()
            await pilot.press("enter")
            await pilot.pause()
            assert app.screen is original_screen

            app.request_confirmation("test", "Proceed?", None)
            await pilot.pause()
            await pilot.press("n")
            await pilot.pause()
            assert app.screen is original_screen

            app.request_confirmation("test", "Proceed?", None)
            await pilot.pause()
            await pilot.press("y")
            await pilot.pause()
            assert app.screen is original_screen

    asyncio.run(run_test())


def test_autosave_enables_selected_operation_without_restart(tmp_path):
    async def run_test():
        env_path = tmp_path / ".env"
        env_path.write_text(
            'SRC_IMAP_HOST="imap.example.com"\nSRC_IMAP_USERNAME="user"\nSRC_IMAP_PASSWORD="secret"\n',
            encoding="utf-8",
        )
        app = ImapToolsApp(env_path)
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            app.select_operation("backup")
            run_button = app.query_one("#run-operation", Button)
            assert run_button.disabled

            app.query_one("#env-backup-local-path", Input).value = str(tmp_path / "backup")
            await pilot.pause(0.7)

            assert not run_button.disabled

    asyncio.run(run_test())


def test_history_uses_single_output_panel(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "load_records", lambda: [])
    monkeypatch.setattr(app_module, "read_log", lambda run_id: f"history for {run_id}\nsecond line\n")

    async def run_test():
        app = ImapToolsApp(tmp_path / ".env")
        async with app.run_test(size=(160, 40)) as pilot:
            table = app.query_one("#history-table", DataTable)
            table.add_row("count", "completed", "now", key="run-1")
            await pilot.pause()

            assert app.selected_output_id == "run-1"
            assert app.query_one("#output-log", RichLog).lines
            assert not app.query("TabbedContent").nodes

    asyncio.run(run_test())
