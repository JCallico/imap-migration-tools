# macOS development environment

Build and test on macOS so wxPython uses native Cocoa controls and PyInstaller produces a macOS bundle.

## Core checkout

Install Git and Python with Homebrew, or install `mise` and use the versions pinned by the repository:

```bash
brew install git mise
git clone https://github.com/JCallico/imap-migration-tools.git
cd imap-migration-tools
mise install
mise exec -- python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[gui,tui]'
.venv/bin/python -m pip install -r requirements.txt
PYTHONPATH=src .venv/bin/python -m pytest test/ -v
```

wxPython normally installs from a published macOS wheel. Confirm the native dependency before GUI work:

```bash
.venv/bin/python -c 'import wx; print(wx.version())'
PYTHONPATH=src .venv/bin/python -m pytest test/gui test/ui -v
```

Exercise System, Light, and Dark appearance with a disposable configuration profile. Validate macOS menu placement,
Cmd keyboard shortcuts, scaling, OAuth browser handoff, cancellation, and the fixed-width Output font on a real Mac.

## Desktop bundle

```bash
.venv/bin/python -m pip install pyinstaller
.venv/bin/python tools/build_desktop.py
```

Signing, hardened runtime, notarization, and packaging are release concerns and must be validated separately from a
local PyInstaller build.

## Android

Install Android Studio or its SDK command-line tools, set `ANDROID_HOME` when needed, then run:

```bash
tools/run_android.sh
```

The script selects the correct emulator architecture for Apple Silicon or Intel and can target a physical device.
