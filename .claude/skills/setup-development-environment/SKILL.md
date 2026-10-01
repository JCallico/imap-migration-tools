---
name: setup-development-environment
description: Set up and verify an IMAP Migration Tools source checkout on Linux, macOS, or Windows, including the native GUI, TUI, Android toolchain, and Omarchy Windows-VM workflow. Use when preparing a new developer machine, repairing a broken local environment, or validating platform-specific builds.
---

# Setup Development Environment

Prepare the smallest environment needed for the requested work and verify it with an observable command. Do not install
Android or desktop-bundling tools when the user only needs the Python CLI.

## Route by host and target

1. Read `AGENTS.md`, `.mise.toml`, `pyproject.toml`, and `docs/development.md` before changing the environment.
2. Read exactly the relevant platform reference:
   - Linux: [references/linux.md](references/linux.md)
   - Windows: [references/windows.md](references/windows.md)
   - macOS: [references/macos.md](references/macos.md)
   - Omarchy host or Windows testing through Omarchy: also read [references/omarchy.md](references/omarchy.md)
3. Distinguish the host OS from the target OS. Native GUI bundles must be built and exercised on their target OS.
4. Prefer the versions pinned in `.mise.toml` for Android work. The Python project itself supports Python 3.10+.

## Shared invariants

- Keep the virtual environment at repository root as `.venv`; recreate it when its interpreter belongs to the wrong
  OS or an incompatible Python installation.
- Install the editable project and declared development requirements. Add `[gui,tui]`, `[linux-keyring]`, or
  PyInstaller only when the requested work needs them.
- Never copy `.env`, OAuth caches, signing keys, tokens, passwords, or user history into another machine or VM. Use
  `.env.example` or a synthetic test configuration.
- Run GUI tests in their documented isolated display. Do not allow automated tests or input injection to reach the
  developer's active desktop.
- Use `tools/run_android.sh` on Linux/macOS and `tools/run_android.ps1` on Windows instead of reproducing the Android
  build/emulator command sequence.
- Do not disable endpoint protection to make a bundle build. Inspect detections and fix packaging or signing instead.

## Verification

Verify the layer that was installed, then report versions and any intentionally omitted optional components:

```text
Python core: import package dependencies and run a focused or full pytest command
TUI:         launch `imap-tools --help` or the TUI in a disposable configuration
GUI:         run isolated GUI tests and launch the native app on the target OS
Bundle:      run `python tools/build_desktop.py`, then launch the produced target-native executable
Android:     use the repository launcher script for an emulator or connected device
```

Before committing repository changes, follow the complete verification sequence in `AGENTS.md`. Environment setup by
itself does not authorize staging, committing, pushing, changing system security policy, or installing privileged
packages without the user's approval.
