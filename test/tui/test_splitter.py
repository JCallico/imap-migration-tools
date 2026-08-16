"""Tests for keyboard and mouse panel resizing."""

from __future__ import annotations

import asyncio

from tui.app import ImapToolsApp
from tui.splitter import ResizeHandle


def test_keyboard_resizes_columns_and_rows(tmp_path):
    async def run_test():
        app = ImapToolsApp(tmp_path / ".env")
        async with app.run_test(size=(180, 50)) as pilot:
            await pilot.pause()
            column_handle = app.query_one("#center-sidebar-handle", ResizeHandle)
            original_width = app.query_one("#center-column").region.width
            column_handle.focus()
            await pilot.press("right")
            await pilot.pause()
            assert app.query_one("#center-column").region.width == original_width + 2

            row_handle = app.query_one("#operation-history-handle", ResizeHandle)
            original_height = app.query_one("#operation-panel").region.height
            row_handle.focus()
            await pilot.press("down")
            await pilot.pause()
            assert app.query_one("#operation-panel").region.height == original_height + 1

    asyncio.run(run_test())


def test_mouse_drag_resizes_column(tmp_path):
    async def run_test():
        app = ImapToolsApp(tmp_path / ".env")
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
        app = ImapToolsApp(tmp_path / ".env")
        async with app.run_test(size=(180, 50)) as pilot:
            await pilot.pause()
            handle = app.query_one("#center-sidebar-handle", ResizeHandle)
            handle.resize_pair(1, 500)
            await pilot.pause()
            assert app.query_one("#center-column").region.width >= handle.minimum_before
            assert app.query_one("#sidebar").region.width >= handle.minimum_after

    asyncio.run(run_test())
