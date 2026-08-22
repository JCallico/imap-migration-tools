"""Operation registry, readiness, command construction, and output parsing."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

OperationName = Literal["count", "compare", "backup", "restore", "migrate"]


@dataclass(frozen=True)
class OperationSpec:
    name: OperationName
    title: str
    module: str
    description: str


OPERATIONS: tuple[OperationSpec, ...] = (
    OperationSpec("count", "Count", "imap_count", "Assess message counts for an IMAP account or backup."),
    OperationSpec("compare", "Compare", "imap_compare", "Verify per-folder counts between two locations."),
    OperationSpec("backup", "Backup", "imap_backup", "Download an IMAP account to local .eml files."),
    OperationSpec("restore", "Restore", "imap_restore", "Upload a local backup to an IMAP account."),
    OperationSpec("migrate", "Migrate", "imap_migrate", "Copy or synchronize two IMAP accounts."),
)
OPERATION_BY_NAME = {operation.name: operation for operation in OPERATIONS}


@dataclass(frozen=True)
class Readiness:
    ready: bool
    detail: str
    warning: bool = False


def _auth(values: dict[str, str], prefix: str) -> bool:
    if values.get(f"{prefix}_IMAP_PASSWORD"):
        return True
    if not values.get(f"{prefix}_OAUTH2_CLIENT_ID"):
        return False
    host = values.get(f"{prefix}_IMAP_HOST", "").lower()
    return bool(values.get(f"{prefix}_OAUTH2_CLIENT_SECRET")) if "gmail" in host or "google" in host else True


def _account(values: dict[str, str], prefix: str) -> bool:
    return bool(values.get(f"{prefix}_IMAP_HOST") and values.get(f"{prefix}_IMAP_USERNAME") and _auth(values, prefix))


def account_settings(values: dict[str, str], prefix: str) -> tuple[set[str], set[str]]:
    password = f"{prefix}_IMAP_PASSWORD"
    client_id = f"{prefix}_OAUTH2_CLIENT_ID"
    client_secret = f"{prefix}_OAUTH2_CLIENT_SECRET"
    account_type = f"{prefix}_ACCOUNT_TYPE"
    required = {
        f"{prefix}_IMAP_HOST",
        f"{prefix}_IMAP_USERNAME",
        password,
        client_id,
        client_secret,
        account_type,
    }
    missing = {name for name in (f"{prefix}_IMAP_HOST", f"{prefix}_IMAP_USERNAME") if not values.get(name)}
    if not values.get(password) and values.get(client_id):
        host = values.get(f"{prefix}_IMAP_HOST", "").lower()
        if "gmail" in host or "google" in host:
            if not values.get(client_secret):
                missing.add(client_secret)
    elif not values.get(password):
        missing.update({password, client_id})
    return required, missing


def required_settings(operation: OperationName, values: dict[str, str]) -> tuple[set[str], set[str]]:
    """Return relevant and currently missing configuration fields for an operation."""
    required: set[str] = set()
    missing: set[str] = set()

    def add_account(prefix: str) -> None:
        account_required, account_missing = account_settings(values, prefix)
        required.update(account_required)
        missing.update(account_missing)

    def add_path(name: str) -> None:
        required.add(name)
        if not values.get(name):
            missing.add(name)

    if operation == "backup":
        add_account("SRC")
        add_path("BACKUP_LOCAL_PATH")
    elif operation == "restore":
        add_account("DEST")
        add_path("BACKUP_LOCAL_PATH")
    elif operation == "migrate":
        add_account("SRC")
        add_account("DEST")
    elif operation == "count":
        if values.get("BACKUP_LOCAL_PATH") or values.get("SRC_LOCAL_PATH"):
            add_path("BACKUP_LOCAL_PATH" if values.get("BACKUP_LOCAL_PATH") else "SRC_LOCAL_PATH")
        elif any(values.get(name) for name in ("IMAP_HOST", "IMAP_USERNAME", "IMAP_PASSWORD", "OAUTH2_CLIENT_ID")):
            aliases = {"IMAP_HOST", "IMAP_USERNAME"}
            required.update(aliases)
            missing.update(name for name in aliases if not values.get(name))
            auth = "IMAP_PASSWORD" if values.get("IMAP_PASSWORD") else "OAUTH2_CLIENT_ID"
            required.add(auth)
            if not values.get(auth):
                missing.add(auth)
        else:
            add_account("SRC")
    else:
        if values.get("SRC_LOCAL_PATH"):
            add_path("SRC_LOCAL_PATH")
        else:
            add_account("SRC")
        if values.get("DEST_LOCAL_PATH"):
            add_path("DEST_LOCAL_PATH")
        else:
            add_account("DEST")
    return required, missing


def account_ready(values: dict[str, str], prefix: str) -> bool:
    """Return whether a configured source or destination account can authenticate."""
    return _account(values, prefix)


def readiness(operation: OperationName, values: dict[str, str]) -> Readiness:
    """Determine whether an operation has its minimum configuration."""
    source = _account(values, "SRC")
    destination = _account(values, "DEST")
    backup_path = values.get("BACKUP_LOCAL_PATH", "")
    if operation == "count":
        local_path = backup_path or values.get("SRC_LOCAL_PATH", "")
        if local_path:
            exists = Path(local_path).expanduser().is_dir()
            return Readiness(exists, "Local backup is ready" if exists else "The configured local path does not exist")
        single = bool(
            values.get("IMAP_HOST")
            and values.get("IMAP_USERNAME")
            and (values.get("IMAP_PASSWORD") or values.get("OAUTH2_CLIENT_ID"))
        )
        ready = bool(source or single)
        return Readiness(ready, "IMAP source is ready" if ready else "Configure a local path or source account")
    if operation == "backup":
        ready = bool(source and backup_path)
        return Readiness(
            ready, "Source and backup path are ready" if ready else "Configure the source account and backup path"
        )
    if operation == "restore":
        exists = bool(backup_path and Path(backup_path).expanduser().is_dir())
        ready = bool(destination and exists)
        return Readiness(
            ready,
            "Backup and destination are ready" if ready else "Configure a destination and an existing backup path",
        )
    if operation == "migrate":
        destructive = (
            values.get("DELETE_FROM_SOURCE", "false").lower() == "true"
            or values.get("DEST_DELETE", "false").lower() == "true"
        )
        ready = bool(source and destination)
        return Readiness(
            ready, "Both IMAP accounts are ready" if ready else "Configure both IMAP accounts", destructive
        )
    source_path = values.get("SRC_LOCAL_PATH", "")
    destination_path = values.get("DEST_LOCAL_PATH", "")
    src_side = Path(source_path).expanduser().is_dir() if source_path else source
    dest_side = Path(destination_path).expanduser().is_dir() if destination_path else destination
    ready = bool(src_side and dest_side)
    return Readiness(ready, "Both comparison sides are ready" if ready else "Configure both comparison sides")


@dataclass
class RunOptions:
    folder: str = ""
    workers: int = 4
    batch: int = 10
    migrate_cache: str = ""
    switches: dict[str, bool] = field(default_factory=dict)
    environment: dict[str, str] = field(default_factory=dict)
    target: str = ""
    source_path: str = ""
    destination_path: str = ""


SWITCH_ARGUMENTS = {
    "DELETE_FROM_SOURCE": "--src-delete",
    "DEST_DELETE": "--dest-delete",
    "PRESERVE_LABELS": "--preserve-labels",
    "PRESERVE_FLAGS": "--preserve-flags",
    "GMAIL_MODE": "--gmail-mode",
    "MANIFEST_ONLY": "--manifest-only",
    "APPLY_LABELS": "--apply-labels",
    "APPLY_FLAGS": "--apply-flags",
    "FULL_RESTORE": "--full-restore",
    "FULL_MIGRATE": "--full-migrate",
}


def build_command(spec: OperationSpec, options: RunOptions) -> list[str]:
    """Build a secret-free command for an operation."""
    command = [sys.executable, "-u", "-m", spec.module]
    if spec.name == "count" and options.target:
        command.extend(("--target", options.target))
    if spec.name == "compare":
        if options.source_path:
            command.extend(("--src-path", options.source_path))
        if options.destination_path:
            command.extend(("--dest-path", options.destination_path))
    if spec.name in {"backup", "restore", "migrate"}:
        command.extend(("--workers", str(options.workers), "--batch", str(options.batch)))
    for key, enabled in options.switches.items():
        argument = SWITCH_ARGUMENTS.get(key)
        if argument is None:
            continue
        if enabled:
            command.append(argument)
        else:
            command.append(f"--no-{argument.removeprefix('--')}")
    if spec.name == "migrate" and options.migrate_cache:
        command.extend(("--migrate-cache", options.migrate_cache))
    if options.folder and spec.name in {"backup", "restore", "migrate"}:
        command.append(options.folder)
    return command


@dataclass
class ProgressState:
    phase: str = "Starting"
    current: int | None = None
    total: int | None = None
    copied: int = 0
    skipped: int = 0
    failed: int = 0
    deleted: int = 0


PROGRESS_RE = re.compile(r"Progress:\s*(?:(\d+)/(\d+)|([\d.]+)%)")
FOLDER_RE = re.compile(r"(?:Processing|Restoring|migration for).*?(?:Folder:|folder:)?\s*([^|]+)", re.IGNORECASE)


def parse_output(line: str, state: ProgressState) -> ProgressState:
    """Best-effort parsing of the scripts' human-readable output."""
    match = PROGRESS_RE.search(line)
    if match:
        if match.group(1):
            state.current, state.total = int(match.group(1)), int(match.group(2))
        else:
            state.current, state.total = int(float(match.group(3))), 100
        state.phase = "Processing"
    folder = FOLDER_RE.search(line)
    if folder:
        state.phase = folder.group(1).strip(" -")
    upper = line.upper()
    if any(word in upper for word in ("SAVED", "UPLOADED", "COPIED")):
        state.copied += 1
    if "SKIP" in upper:
        state.skipped += 1
    if any(word in upper for word in ("FAILED", "ERROR")):
        state.failed += 1
    if "DELETED" in upper:
        state.deleted += 1
    return state
