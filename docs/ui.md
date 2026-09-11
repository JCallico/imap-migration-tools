# Native desktop interface

The wxPython desktop interface provides Count, Compare, Backup, Restore, and Migrate using the same configuration,
readiness, command options, redaction, and history implementation as `imap-tools`.

## Run from source

Python 3.10 or newer is required:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[ui,tui]'
PYTHONPATH=src .venv/bin/python -m ui
```

On Windows use `.venv\Scripts\python.exe` and `python -m ui` after the editable install.
The installed desktop launcher is `imap-tools-ui`.

wxPython uses native Windows, Cocoa, and GTK controls. Windows and macOS normally use published wheels. On Linux,
install your distribution's wxPython package or the GTK development dependencies needed to build wxPython. For
Ubuntu 24.04, a development environment can reuse the distribution package:

```bash
sudo apt-get install python3-venv python3-wxgtk4.0 xvfb
python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install -e '.[ui,tui]'
```

## Configuration and workspace

The application discovers `.env` from the working directory and its parents. Desktop launchers do not always start
in a project directory. Choose a specific configuration with:

```bash
imap-tools-ui --env /path/to/project/.env
```

The selected configuration directory is also the operation working directory. Form changes autosave after validation.
Existing OS environment values override `.env`; the status bar reports when such overrides are present. Passwords
and client secrets are masked. External valid edits replace pending local edits; invalid external files leave the
form intact and prevent accidental overwrite.

Select an operation and review its readiness message. All schema settings, including workers, batch size, migration
folder/cache options, Gmail flags/labels, full restore/migrate, and deletion options, are available in Configuration.
Run opens a confirmation; destructive runs require typing `DELETE` after reviewing the affected accounts or path.
Cancel requests cleanup. If the worker does not exit promptly, Force stop becomes available.

History is shared with the TUI in the existing user data directory. Other instances' unfinished runs remain hidden.
Select a completed run to filter, export, or delete its log. Active runs cannot be deleted. Logs and history use the
same secret redaction as the terminal interface.

Drag panel dividers to resize, or double-click to reset. Narrow windows put Output below Configuration and Operation.
Desktop layout and the last normal window size are stored separately in `ui-layout.json`. Use the View menu to reset
the panel layout, F1 for help, and F2 for the structured keyboard reference. The Help menu also provides application
and version information under About.
Platform menu conventions remain available, including the macOS application menu.
The interface reads the active operating-system palette through wxPython and uses native controls, consistent spacing,
and theme-aware semantic readiness colours. On Linux it follows GTK light/dark and accent colours, including theme
changes made while the application is open. The header uses GTK's active-caption and caption-text colours, while
interactive accents use the system selection colour. Open
**View → Appearance** (`Ctrl+,`) to adjust window opacity from 70% to 100%. The setting is saved in
`ui-settings.json`; desktops whose compositor does not expose native window opacity leave the control disabled. The
settings screen has separate buttons to reset opacity and zoom to their defaults.
On macOS, the fixed-width Output text follows the native body-text size for consistency with the other controls.
The same dialog adjusts zoom from 80% to 150%. **View → Zoom → Zoom in**, **Zoom out**, and **Reset zoom** use `Ctrl+=`,
`Ctrl+-`, and `Ctrl+0` on Windows/Linux and `Cmd` equivalents on macOS. Fonts, native control sizes, wrapped text, and
scrolling reflow with the selected zoom.
**View → Transparency** provides Increase, Decrease, and Reset commands in five-percentage-point steps.

## Tests and bundles

The desktop test job installs the project and wxPython, exercises actual widgets and all five operations against
local mock IMAP servers, and builds a bundle on Linux, macOS, and Windows. Existing tests are unchanged.

```bash
PYTHONPATH=src .venv/bin/python -m pytest test/ui test/ui_core -v
# For headless Linux:
xvfb-run -a .venv/bin/python -m pytest test/ui test/ui_core -v

.venv/bin/python -m pip install pyinstaller
.venv/bin/python tools/build_desktop.py
```

Bundles include a separate console-capable worker, allowing the GUI to run without a terminal while still streaming
operation output. Windows cancellation uses the worker's private stdin channel; POSIX uses process-group signals.
No local HTTP server or extra credential store is introduced. OAuth browser and encrypted token-cache behavior
remain in the existing authentication modules.

Build on each target OS. Linux builds depend on compatible system GTK libraries; they are not universal Linux binaries.
The initial CI targets are Ubuntu 24.04, the hosted macOS runner, and the hosted Windows runner. Produced artifacts are
for evaluation; signing/notarization and public distribution are separate release steps. Inspect accessibility,
keyboard behavior, scaling, theme appearance, OAuth browser handoff, and cancellation on each real desktop before
claiming release readiness. A Linux test run alone does not validate macOS or Windows.

## Parity checklist

| Area | Shared implementation / desktop coverage |
| --- | --- |
| Count, Compare, Backup, Restore, Migrate | Shared operation registry/options; real desktop-to-IMAP integration tests |
| Account and local comparison modes | Shared readiness and option construction |
| All configuration fields and defaults | Shared schema; native form coverage |
| OS environment precedence | Shared effective-value resolution |
| Autosave and external edits | Validated atomic writes; GUI conflict and invalid-file coverage |
| Destructive confirmation | Shared target description; GUI confirmation coverage |
| Run output and history | Shared runner/session/redaction; GUI filtering and history coverage |
| Cancellation / force stop | Shared runner; worker cancellation tests and platform evaluation |
| Multiple instances | Shared history format; unfinished-run hiding and selection tests |
| Help, focus, resizing, layout | Native UI adapters; platform interaction evaluation |
| Terminal ASCII / NO_COLOR | Remain terminal-specific; desktop uses system controls |
