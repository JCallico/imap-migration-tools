"""Mouse- and keyboard-driven split handles for Textual layouts."""

from __future__ import annotations

from typing import Literal

from textual import events
from textual.binding import Binding
from textual.widgets import Static

Orientation = Literal["vertical", "horizontal"]


class ResizeHandle(Static, can_focus=True):
    """Resize the widgets immediately before and after this handle."""

    BINDINGS = [
        Binding("left", "nudge_width(-2)", "shrink", show=False),
        Binding("right", "nudge_width(2)", "grow", show=False),
        Binding("up", "nudge_height(-1)", "shrink", show=False),
        Binding("down", "nudge_height(1)", "grow", show=False),
    ]

    def __init__(
        self,
        before_id: str,
        after_id: str,
        orientation: Orientation,
        *,
        minimum_before: int = 8,
        minimum_after: int = 8,
        id: str | None = None,
    ) -> None:
        super().__init__("", id=id, classes=f"resize-handle {orientation}-handle")
        self.before_id = before_id
        self.after_id = after_id
        self.orientation = orientation
        self.minimum_before = minimum_before
        self.minimum_after = minimum_after
        self._grabbed_at: int | None = None
        self._before_at_grab = 0
        self._after_at_grab = 0

    def _widgets(self):
        return self.app.query_one(f"#{self.before_id}"), self.app.query_one(f"#{self.after_id}")

    def _sizes(self) -> tuple[int, int]:
        before, after = self._widgets()
        if self.orientation == "vertical":
            return before.region.width, after.region.width
        return before.region.height, after.region.height

    def resize_pair(self, before_size: int, after_size: int) -> None:
        """Set adjacent pane sizes while enforcing both minimums."""
        total = before_size + after_size
        if total < self.minimum_before + self.minimum_after:
            return
        bounded_before = max(self.minimum_before, min(total - self.minimum_after, before_size))
        bounded_after = total - bounded_before
        before, after = self._widgets()
        if self.orientation == "vertical":
            before.styles.width = bounded_before
            after.styles.width = bounded_after
        else:
            before.styles.height = bounded_before
            after.styles.height = bounded_after

    def action_nudge_width(self, amount: int) -> None:
        if self.orientation != "vertical":
            return
        before, after = self._sizes()
        self.resize_pair(before + amount, after - amount)

    def action_nudge_height(self, amount: int) -> None:
        if self.orientation != "horizontal":
            return
        before, after = self._sizes()
        self.resize_pair(before + amount, after - amount)

    def on_mouse_down(self, event: events.MouseDown) -> None:
        if event.button != 1:
            return
        self.capture_mouse()
        self._grabbed_at = event.screen_x if self.orientation == "vertical" else event.screen_y
        self._before_at_grab, self._after_at_grab = self._sizes()
        self.add_class("dragging")
        event.stop()

    def on_mouse_move(self, event: events.MouseMove) -> None:
        if self._grabbed_at is None:
            return
        position = event.screen_x if self.orientation == "vertical" else event.screen_y
        delta = position - self._grabbed_at
        self.resize_pair(self._before_at_grab + delta, self._after_at_grab - delta)
        event.stop()

    def on_mouse_up(self, event: events.MouseUp) -> None:
        if self._grabbed_at is None:
            return
        self.release_mouse()
        self._grabbed_at = None
        self.remove_class("dragging")
        event.stop()
