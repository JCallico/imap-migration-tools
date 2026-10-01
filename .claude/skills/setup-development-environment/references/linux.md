# Linux development environment

Use the distribution package manager for native libraries and a virtual environment for Python packages. Do not use
the system Python package directory as the project environment.

## Core checkout

```bash
git clone https://github.com/JCallico/imap-migration-tools.git
cd imap-migration-tools
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .
.venv/bin/python -m pip install -r requirements.txt
PYTHONPATH=src .venv/bin/python -m pytest test/ -v
```

For TUI work, install the editable `tui` extra. For GUI work, install `gui,tui` and a virtual X server. Ubuntu/Debian
can reuse the distribution wxPython build:

```bash
sudo apt-get install python3-venv python3-wxgtk4.0 xvfb
python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install -e '.[gui,tui]'
.venv/bin/python -m pip install -r requirements.txt
PYTHONPATH=src .venv/bin/python -m pytest test/gui test/ui -v
```

On Arch-derived systems, install the equivalent Python, wxWidgets/GTK, and Xvfb packages, then prefer a compatible
wxPython wheel in `.venv`. Confirm with `.venv/bin/python -c 'import wx; print(wx.version())'` before running GUI tests.
The test configuration uses Xvfb and forces GTK's X11 backend so test windows cannot appear on a live Wayland desktop.

Install native GObject/Cairo/libsecret prerequisites and `-e '.[linux-keyring]'` only when testing encrypted persistent
OAuth caching. The application must fall back to process-local caching rather than plaintext storage if unavailable.

## Desktop bundle

```bash
.venv/bin/python -m pip install pyinstaller
.venv/bin/python tools/build_desktop.py
```

Linux bundles depend on the compatible GTK stack of the build system; do not treat one Linux build as universal.

## Android

Install Android Studio or its SDK command-line tools, set `ANDROID_HOME` (or ignored `android/local.properties`), and
install the versions pinned in `.mise.toml` with `mise install`. Then use:

```bash
tools/run_android.sh
```

KVM is recommended for emulator acceleration. Use `--headless` when a graphical emulator window is unavailable.
