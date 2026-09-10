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
        "--collect-submodules=ui_core",
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
            "--collect-submodules=ui",
            "--name=imap-tools-ui",
            "--windowed",
        ]
    )
    destination = root / "dist" / "imap-tools-ui"
    if sys.platform == "darwin":
        destination = root / "dist" / "imap-tools-ui.app" / "Contents" / "MacOS"
    shutil.copytree(root / "dist" / "imap-tools-worker", destination / "worker", dirs_exist_ok=True)
