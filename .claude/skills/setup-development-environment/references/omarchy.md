# Omarchy host and Windows VM

Read the installed Omarchy skill/instructions before changing desktop, Hyprland, or Omarchy-managed configuration.
Use public `omarchy windows vm ...` commands; do not edit files under `/usr/share/omarchy`.

## Native Linux work

Omarchy is Arch-based. Use `mise install` for the repository-pinned Python 3.13, JDK 17, and Gradle 8.13 toolchain.
For GUI testing, ensure wxPython/GTK and Xvfb are available, and keep tests on their private Xvfb display. A running
Wayland session must never receive GUI-test windows or synthetic input.

## Windows VM lifecycle

```bash
omarchy windows vm status
omarchy windows vm install   # only when no VM is configured
omarchy windows vm launch -k
omarchy windows vm stop
```

The VM uses protected bind-mount anchors. After a host reboot, the first safe launch can require one Polkit
authorization to reattach the existing disk. Do not bypass this with `docker compose up`: without the protected mount,
Dockur can see an empty `/storage` and begin downloading a new Windows installation. Membership in the `docker` group
removes ordinary Docker prompts but is root-equivalent and does not replace the protected-mount authorization.

The host directory `~/Windows` is exposed to Windows as `\\host.lan\Data` (and may be mapped to a drive letter). Copy a
sanitized source snapshot there: exclude `.git`, virtual environments, `.env*` except a public example, caches, OAuth
state, histories, backups, and signing material. Build the Windows executable inside the VM using
[windows.md](windows.md), then copy the built bundle to a local Windows path before launching it to avoid UNC security
warnings and shared-filesystem runtime behavior.

For automated review, connect RDP through a private Xvfb display and capture that display. Send input only to the
isolated X server/RDP window; never use global Wayland input tools such as `wtype` or `ydotool`, which could type into
the developer's active desktop. Do not place the Windows password in command arguments or repository scripts—provide
it through an interactive credential channel or the user's secure store.

Verify the Windows app with a disposable `.env`, remove `gui-settings.json`, and test first-run System theme detection
in both Windows light and dark modes. Build screenshots must not expose credentials or personal mailbox data.
