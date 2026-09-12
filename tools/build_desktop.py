"""Build desktop and CLI worker bundles on the target operating system."""

import shutil
import sys
from pathlib import Path

import PyInstaller.__main__

root = Path(__file__).resolve().parents[1]

if __name__ == "__main__":
    common = [
        "--onedir",
        "--noconfirm",
        f"--paths={root / 'src'}",
        "--collect-submodules=ui",
        "--collect-submodules=imap_services",
        "--collect-submodules=auth",
        "--collect-submodules=providers",
        "--copy-metadata=imap-migration-tools",
        "--hidden-import=imap_count",
        "--hidden-import=imap_compare",
        "--hidden-import=imap_backup",
        "--hidden-import=imap_restore",
        "--hidden-import=imap_migrate",
    ]
    PyInstaller.__main__.run([str(root / "tools" / "desktop_worker.py"), *common, "--name=imap-tools-worker"])
    PyInstaller.__main__.run(
        [
            str(root / "tools" / "desktop_launcher.py"),
            *common,
            "--collect-submodules=gui",
            "--name=imap-tools-gui",
            "--windowed",
        ]
    )
    destination = root / "dist" / "imap-tools-gui"
    if sys.platform == "darwin":
        destination = root / "dist" / "imap-tools-gui.app" / "Contents" / "MacOS"
    shutil.copytree(root / "dist" / "imap-tools-worker", destination / "worker", dirs_exist_ok=True)
