"""Tests for keyboard and mouse panel resizing."""

from __future__ import annotations

import asyncio

from textual.widgets import Static

from tui.app import OPERATION_PANEL_HEIGHTS, ImapToolsApp
from tui.layout import load_layout
from tui.splitter import ResizeHandle


def test_keyboard_resizes_columns_and_rows(tmp_path):
    async def run_test():
        layout_path = tmp_path / "layout.json"
        app = ImapToolsApp(tmp_path / ".env", layout_path)
        async with app.run_test(size=(180, 50)) as pilot:
            await pilot.pause()
            column_handle = app.query_one("#center-sidebar-handle", ResizeHandle)
            original_width = app.query_one("#center-column").region.width
            column_handle.focus()
            await pilot.press("right")
            await pilot.pause()
            assert app.query_one("#center-column").region.width == original_width + 2
            assert load_layout(layout_path)["center-sidebar-handle"] == original_width + 2

            row_handle = app.query_one("#operation-history-handle", ResizeHandle)
            original_height = app.query_one("#operation-panel").region.height
            row_handle.focus()
            await pilot.press("down")
            await pilot.pause()
            assert app.query_one("#operation-panel").region.height == original_height + 1

    asyncio.run(run_test())


def test_mouse_drag_resizes_column(tmp_path):
    async def run_test():
        app = ImapToolsApp(tmp_path / ".env", tmp_path / "layout.json")
        async with app.run_test(size=(180, 50)) as pilot:
            await pilot.pause()
            handle = app.query_one("#center-sidebar-handle", ResizeHandle)
            original_width = app.query_one("#center-column").region.width
            position = handle.region.offset
            await pilot.mouse_down(handle)
            await pilot.hover(None, (position.x + 4, position.y))
            await pilot.mouse_up(None, (position.x + 4, position.y))
            await pilot.pause()
            assert app.query_one("#center-column").region.width == original_width + 4

    asyncio.run(run_test())


def test_resize_enforces_adjacent_minimums(tmp_path):
    async def run_test():
        app = ImapToolsApp(tmp_path / ".env", tmp_path / "layout.json")
        async with app.run_test(size=(180, 50)) as pilot:
            await pilot.pause()
            handle = app.query_one("#center-sidebar-handle", ResizeHandle)
            handle.resize_pair(1, 500)
            await pilot.pause()
            assert app.query_one("#center-column").region.width >= handle.minimum_before
            assert app.query_one("#sidebar").region.width >= handle.minimum_after

    asyncio.run(run_test())


def test_splitter_reset_and_focus_guidance(tmp_path):
    async def run_test():
        layout_path = tmp_path / "layout.json"
        app = ImapToolsApp(tmp_path / ".env", layout_path)
        async with app.run_test(size=(180, 50)) as pilot:
            await pilot.pause()
            handle = app.query_one("#center-sidebar-handle", ResizeHandle)
            original_width = app.query_one("#center-column").region.width
            assert str(handle.render()) == "│"

            handle.focus()
            await pilot.pause()
            assert "←/→" in str(app.query_one("#key-legend", Static).render())
            await pilot.press("right")
            await pilot.pause()
            assert app.query_one("#center-column").region.width == original_width + 2

            await pilot.click(handle, times=2)
            await pilot.pause()
            assert app.query_one("#center-column").region.width == original_width

    asyncio.run(run_test())


def test_layout_is_restored_and_alt_zero_resets_it(tmp_path):
    async def run_test():
        layout_path = tmp_path / "layout.json"
        first = ImapToolsApp(tmp_path / ".env", layout_path)
        async with first.run_test(size=(180, 50)) as pilot:
            await pilot.pause()
            handle = first.query_one("#center-sidebar-handle", ResizeHandle)
            default_width = first.query_one("#center-column").region.width
            handle.focus()
            await pilot.press("right", "right")
            await pilot.pause()
            customized_width = first.query_one("#center-column").region.width
            assert customized_width == default_width + 4

        restored = ImapToolsApp(tmp_path / ".env", layout_path)
        async with restored.run_test(size=(180, 50)) as pilot:
            await pilot.pause()
            assert restored.query_one("#center-column").region.width == customized_width

            restored.select_operation("compare")
            await pilot.press("alt+0")
            await pilot.pause()
            assert restored.query_one("#center-column").region.width == default_width
            assert restored.query_one("#operation-panel").region.height == OPERATION_PANEL_HEIGHTS["compare"]
            assert load_layout(layout_path)["center-sidebar-handle"] == default_width

    asyncio.run(run_test())


def test_splitter_guard_branches_and_horizontal_rendering(tmp_path):
    async def run_test():
        app = ImapToolsApp(tmp_path / ".env", tmp_path / "layout.json")
        async with app.run_test(size=(180, 50)) as pilot:
            await pilot.pause()
            vertical = app.query_one("#center-sidebar-handle", ResizeHandle)
            horizontal = app.query_one("#operation-history-handle", ResizeHandle)

            before = vertical.before_size
            vertical.resize_pair(1, 1)
            assert vertical.before_size == before

            vertical._default_sizes = None
            vertical.reset()
            vertical.action_nudge_height(1)
            horizontal.action_nudge_width(1)
            assert str(horizontal.render()) == "─"

    asyncio.run(run_test())
