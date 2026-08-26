# Full-screen terminal interface

The beta `imap-tools` interface configures and runs Count, Compare, Backup, Restore, and Migrate in one terminal
workspace. See [Installation](installation.md) for package and optional-dependency setup.

To run the interface from a source checkout after installing the development dependencies, use:

```bash
PYTHONPATH=src .venv/bin/python -m tui.app
```

## Help and panel controls

Press `F1` for general help or `F2` for the complete keyboard reference. Both open over the workspace without losing
the current configuration or run context.

Drag the visible `│` and `─` separators to resize adjacent panels. Separators are also keyboard accessible: focus one
with `Tab`, then use the arrow keys shown in the footer. Double-click a separator to reset it, or press `Alt+0` to reset
the complete layout. Customized divider positions are restored on the next launch. Output always consumes the
remaining width rather than preserving a fixed saved width.

The workspace adapts to the terminal width. At 90–140 columns it uses two columns with Output across the bottom. Below
90 columns, panels use a full-width stacked layout with compact Tools, Operation, and History sections. Wide-layout
divider positions are restored when the terminal becomes wide again.

## Terminal compatibility

For terminals with limited Unicode support, use ASCII compatibility mode:

```bash
imap-tools --display-mode ascii
```

ASCII mode uses portable borders and status markers, with bold or reverse-video cues that do not depend on color. Set
`IMAP_TOOLS_DISPLAY_MODE=ascii` to make it persistent. Supported values are `auto`, `standard`, and `ascii`.

The default `auto` mode selects ASCII for `TERM=dumb` or a non-UTF-8 locale. Use an explicit mode when a terminal
reports inaccurate capabilities. `NO_COLOR` is honored in every mode.

## Configuration changes

The interface autosaves valid form changes to `.env`. It also notices edits made outside the application and reloads
valid configuration automatically. An invalid external file leaves the current form unchanged and displays an error.
If an external edit arrives while an autosave is pending, the external file takes precedence and is not overwritten.

## History and multiple instances

History is shared by TUI instances using the same user data directory. A completed run created by another instance is
added automatically. Another instance's active run remains hidden until its summary and log are finalized, preventing
an incomplete log from appearing as a completed result.

History updates preserve the selected record and the currently focused control while that record still exists. If
another instance deletes the selected record, the interface selects an available replacement and displays its log.

For contributor details about display profiles, filesystem observation, atomic history summaries, and selection-event
handling, see [Development](development.md#tui-display-compatibility).
