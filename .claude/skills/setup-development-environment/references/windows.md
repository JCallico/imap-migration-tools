# Windows development environment

Use a native Windows checkout or a host-shared, secret-free source snapshot. Build and test the Windows GUI inside
Windows; do not present a Linux cross-build as a Windows validation.

## Core checkout (PowerShell)

```powershell
git clone https://github.com/JCallico/imap-migration-tools.git
Set-Location imap-migration-tools
py -3.13 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -e .
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:PYTHONPATH = "src"
& .\.venv\Scripts\python.exe -m pytest test -v
```

If `py` is unavailable after a fresh Python installation, locate `python.exe` under
`$env:LOCALAPPDATA\Programs\Python\Python313` or open a new terminal. Do not assume the launcher was installed.

## Native GUI and bundle

```powershell
& .\.venv\Scripts\python.exe -m pip install -e ".[gui,tui]"
& .\.venv\Scripts\python.exe -m pytest test/gui test/ui -v
& .\.venv\Scripts\python.exe -m pip install pyinstaller
& .\.venv\Scripts\python.exe tools\build_desktop.py
& .\dist\imap-tools-gui\imap-tools-gui.exe --env C:\path\to\synthetic-test.env
```

wxPython's native extension requires the supported Microsoft Visual C++ Redistributable. Install the current x64
redistributable if importing `wx._core` reports a missing DLL. Never disable Windows Defender for PyInstaller; inspect
Protection History and the PyInstaller warnings, and prefer signed release artifacts for distribution.

Verify first-run System appearance with `gui-settings.json` absent in a disposable profile, then check both Windows
light and dark application modes. Keep real credentials and OAuth caches out of screenshots and shared folders.

## Android

Install Android Studio/SDK command-line tools and use the repository PowerShell launcher:

```powershell
.\tools\run_android.ps1
```

The script can install SDK packages, create/start an emulator, target a connected device, build, test, install, and
launch the app. Use `-Headless` when no graphical emulator can be displayed.
