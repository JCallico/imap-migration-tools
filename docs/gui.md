# Native desktop GUI

The wxPython desktop GUI provides Count, Compare, Backup, Restore, and Migrate using the same configuration,
readiness, command options, redaction, and history implementation as `imap-tools`.

## Run from source

Python 3.10 or newer is required. On macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[gui,tui]"
python -m gui
```

On Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[gui,tui]"
python -m gui
```

On Windows Command Prompt (`cmd.exe`):

```batch
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -e ".[gui,tui]"
python -m gui
```

The `.venv/bin/python` path is specific to macOS and Linux. Windows stores the interpreter at
`.venv\Scripts\python.exe`; it can be used directly if shell activation is unavailable. The installed desktop launcher
is `imap-tools-gui` (`imap-tools-gui.exe` on Windows).

wxPython uses native Windows, Cocoa, and GTK controls. Windows and macOS normally use published wheels. macOS uses
wxPython 4.3 or newer so explicit Light and Dark choices also update Cocoa controls, dialogs, menus, and window chrome.
On Linux, install your distribution's wxPython package or the GTK development dependencies needed to build wxPython.
For Ubuntu 24.04, a development environment can reuse the distribution package:

```bash
sudo apt-get install python3-venv python3-wxgtk4.0 xvfb
python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install -e '.[gui,tui]'
```

## Configuration and workspace

The application discovers `.env` from the working directory and its parents. Desktop launchers do not always start
in a project directory. Choose a specific configuration with:

```bash
imap-tools-gui --env /path/to/project/.env
```

On Windows PowerShell or Command Prompt, use a Windows path:

```powershell
imap-tools-gui --env "C:\Users\your-name\project\.env"
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
Desktop layout and the last normal window size are stored separately in `gui-layout.json`. Use the View menu to reset
the panel layout, F1 for help, and F2 for the structured keyboard reference. The Help menu also provides application
and version information under About.
Platform menu conventions remain available, including the macOS application menu.
The interface uses the same terminal-inspired visual language as the TUI and Android application: monospaced text,
prompt-like panel titles and actions, green operation accents, yellow warnings, red failures, and high-contrast panel
surfaces. The light palette is a light terminal palette rather than a conventional desktop form theme. Open
**View → Appearance** (`Ctrl+,`) to choose **System**, **Light**, or **Dark**. System mode follows the operating
system's light/dark choice while retaining the application's own coordinated palette; supported operating-system
theme changes are reflected while the application is open.

The Appearance window also adjusts opacity from 70% to 100%. New profiles start fully opaque so the terminal palettes
remain consistent across compositors and Windows desktops; transparency remains available as an opt-in setting.
Theme, opacity, and zoom are independent and saved in
`gui-settings.json`. Existing settings created before theme selection was available use System mode. Desktops whose
compositor does not expose native window opacity leave that control disabled. High-contrast text and semantic status
colours remain in use at every supported opacity, and the settings screen provides separate reset controls for opacity
and zoom.
On macOS, explicit Light and Dark choices are applied to the native Cocoa appearance as well as the application's
terminal palette. System mode returns Cocoa to the system appearance and continues to follow automatic appearance
changes. The fixed-width Output text follows the native body-text size for consistency with the other controls.
The same dialog adjusts zoom from 80% to 150%. **View → Zoom → Zoom in**, **Zoom out**, and **Reset zoom** use `Ctrl+=`,
`Ctrl+-`, and `Ctrl+0` on Windows/Linux and `Cmd` equivalents on macOS. Fonts, native control sizes, wrapped text, and
scrolling reflow with the selected zoom.
**View → Transparency** provides Increase, Decrease, and Reset commands in five-percentage-point steps.

## Tests and bundles

The desktop test job installs the project and wxPython, exercises actual widgets and all five operations against
local mock IMAP servers, and builds a bundle on Linux, macOS, and Windows. Existing tests are unchanged.

After activating the virtual environment, run on macOS or Linux:

```bash
PYTHONPATH=src python -m pytest test/gui test/ui -v

python -m pip install pyinstaller
python tools/build_desktop.py
```

On Linux, install Xvfb and the development requirements first. The `pytest-xvfb` plugin automatically gives the
native GUI tests a private virtual display, so test windows cannot appear on or take focus from the real desktop.
If either Xvfb or the plugin is unavailable, the native widget module is skipped instead of opening windows on the
real display. The test module also forces GTK to its X11 backend so a running Wayland session cannot bypass Xvfb.

On Windows PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m pytest test/gui test/ui -v
python -m pip install pyinstaller
python tools/build_desktop.py
```

On Windows Command Prompt:

```batch
set PYTHONPATH=src
python -m pytest test/gui test/ui -v
python -m pip install pyinstaller
python tools\build_desktop.py
```

Bundles include a separate console-capable worker, allowing the GUI to run without a terminal while still streaming
operation output. Windows cancellation uses the worker's private stdin channel; POSIX uses process-group signals.
No local HTTP server or extra credential store is introduced. OAuth browser and encrypted token-cache behavior
remain in the existing authentication modules.

The desktop window and application bundles use the same terminal-envelope artwork selected for Android. The canonical
store artwork remains `android/artwork/play-store-icon.png`; desktop runtime and Linux PNG resources plus the native
Windows `.ico` and macOS `.icns` files are derived from it. When the artwork changes, regenerate all platform assets
together so installed applications, task switchers, launchers, and window chrome keep the same identity.

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
| Help, focus, resizing, layout | Native GUI adapters; platform interaction evaluation |
| Terminal ASCII / NO_COLOR | Remain terminal-specific; desktop uses system controls |
