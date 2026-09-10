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
    required_fields: frozenset[str] = frozenset()
    missing_fields: frozenset[str] = frozenset()
    warnings: tuple[str, ...] = ()


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


def required_settings(
    operation: OperationName,
    values: dict[str, str],
    *,
    count_mode: str = "auto",
    compare_source_mode: str = "auto",
    compare_destination_mode: str = "auto",
) -> tuple[set[str], set[str]]:
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
        if count_mode == "local":
            add_path("BACKUP_LOCAL_PATH")
        elif count_mode in {"source", "destination"}:
            add_account("DEST" if count_mode == "destination" else "SRC")
        elif values.get("BACKUP_LOCAL_PATH") or values.get("SRC_LOCAL_PATH"):
            add_path("BACKUP_LOCAL_PATH" if values.get("BACKUP_LOCAL_PATH") else "SRC_LOCAL_PATH")
        elif any(values.get(name) for name in ("IMAP_HOST", "IMAP_USERNAME", "IMAP_PASSWORD", "OAUTH2_CLIENT_ID")):
            aliases = {"IMAP_HOST", "IMAP_USERNAME"}
            required.update(aliases)
            missing.update(name for name in aliases if not values.get(name))
            if values.get("IMAP_PASSWORD"):
                required.add("IMAP_PASSWORD")
            elif values.get("OAUTH2_CLIENT_ID"):
                required.add("OAUTH2_CLIENT_ID")
            else:
                required.update({"IMAP_PASSWORD", "OAUTH2_CLIENT_ID"})
                missing.update({"IMAP_PASSWORD", "OAUTH2_CLIENT_ID"})
        else:
            add_account("SRC")
    else:
        if compare_source_mode == "local" or (compare_source_mode == "auto" and values.get("SRC_LOCAL_PATH")):
            add_path("SRC_LOCAL_PATH")
        else:
            add_account("SRC")
        if compare_destination_mode == "local" or (
            compare_destination_mode == "auto" and values.get("DEST_LOCAL_PATH")
        ):
            add_path("DEST_LOCAL_PATH")
        else:
            add_account("DEST")
    return required, missing


def account_ready(values: dict[str, str], prefix: str) -> bool:
    """Return whether a configured source or destination account can authenticate."""
    return _account(values, prefix)


def _missing_details(missing: set[str]) -> tuple[str, ...]:
    """Translate missing field names into concise, choice-aware guidance."""
    remaining = set(missing)
    details: list[str] = []
    for prefix, label in (("SRC", "source"), ("DEST", "destination")):
        password = f"{prefix}_IMAP_PASSWORD"
        client_id = f"{prefix}_OAUTH2_CLIENT_ID"
        if {password, client_id} <= remaining:
            details.append(f"{label} password or OAuth client ID")
            remaining.difference_update({password, client_id})
    if {"IMAP_PASSWORD", "OAUTH2_CLIENT_ID"} <= remaining:
        details.append("IMAP password or OAuth client ID")
        remaining.difference_update({"IMAP_PASSWORD", "OAUTH2_CLIENT_ID"})
    labels = {
        "SRC_IMAP_HOST": "source host",
        "SRC_IMAP_USERNAME": "source username",
        "SRC_OAUTH2_CLIENT_SECRET": "source OAuth client secret",
        "DEST_IMAP_HOST": "destination host",
        "DEST_IMAP_USERNAME": "destination username",
        "DEST_OAUTH2_CLIENT_SECRET": "destination OAuth client secret",
        "IMAP_HOST": "IMAP host",
        "IMAP_USERNAME": "IMAP username",
        "IMAP_PASSWORD": "IMAP password",
        "OAUTH2_CLIENT_ID": "OAuth client ID",
        "BACKUP_LOCAL_PATH": "backup path",
        "SRC_LOCAL_PATH": "source path",
        "DEST_LOCAL_PATH": "destination path",
    }
    details.extend(labels.get(name, name.lower().replace("_", " ")) for name in sorted(remaining))
    return tuple(details)


def readiness(
    operation: OperationName,
    values: dict[str, str],
    *,
    count_mode: str = "auto",
    compare_source_mode: str = "auto",
    compare_destination_mode: str = "auto",
) -> Readiness:
    """Determine whether an operation has its minimum configuration."""
    required, missing = required_settings(
        operation,
        values,
        count_mode=count_mode,
        compare_source_mode=compare_source_mode,
        compare_destination_mode=compare_destination_mode,
    )
    source = _account(values, "SRC")
    destination = _account(values, "DEST")
    backup_path = values.get("BACKUP_LOCAL_PATH", "")
    if operation == "count":
        if count_mode in {"source", "destination"}:
            ready = destination if count_mode == "destination" else source
        else:
            local_path = backup_path or values.get("SRC_LOCAL_PATH", "")
            if count_mode == "local" or (count_mode == "auto" and local_path):
                ready = bool(local_path and Path(local_path).expanduser().is_dir())
                if local_path and not ready:
                    missing.add("BACKUP_LOCAL_PATH" if backup_path or count_mode == "local" else "SRC_LOCAL_PATH")
            else:
                single = bool(
                    values.get("IMAP_HOST")
                    and values.get("IMAP_USERNAME")
                    and (values.get("IMAP_PASSWORD") or values.get("OAUTH2_CLIENT_ID"))
                )
                ready = bool(source or single)
    elif operation == "backup":
        ready = bool(source and backup_path)
    elif operation == "restore":
        exists = bool(backup_path and Path(backup_path).expanduser().is_dir())
        ready = bool(destination and exists)
        if backup_path and not exists:
            missing.add("BACKUP_LOCAL_PATH")
    elif operation == "migrate":
        ready = bool(source and destination)
    else:
        source_path = values.get("SRC_LOCAL_PATH", "")
        destination_path = values.get("DEST_LOCAL_PATH", "")
        source_local = compare_source_mode == "local" or (compare_source_mode == "auto" and bool(source_path))
        destination_local = compare_destination_mode == "local" or (
            compare_destination_mode == "auto" and bool(destination_path)
        )
        src_side = bool(source_path and Path(source_path).expanduser().is_dir()) if source_local else source
        dest_side = (
            bool(destination_path and Path(destination_path).expanduser().is_dir())
            if destination_local
            else destination
        )
        ready = bool(src_side and dest_side)
        if source_local and source_path and not src_side:
            missing.add("SRC_LOCAL_PATH")
        if destination_local and destination_path and not dest_side:
            missing.add("DEST_LOCAL_PATH")

    warnings: list[str] = []
    if operation == "migrate" and values.get("DELETE_FROM_SOURCE", "false").lower() == "true":
        warnings.append("source deletion enabled")
    if operation in {"backup", "restore", "migrate"} and values.get("DEST_DELETE", "false").lower() == "true":
        warnings.append("destination deletion enabled")
    missing_details = _missing_details(missing)
    if not ready:
        detail = f"Missing: {', '.join(missing_details)}" if missing_details else "Missing required configuration"
    elif warnings:
        detail = f"Warning: {', '.join(warnings)}"
    else:
        detail = "Ready to run"
    return Readiness(
        ready,
        detail,
        bool(warnings),
        frozenset(required),
        frozenset(missing),
        tuple(warnings),
    )


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


OPERATION_SWITCHES: dict[str, tuple[str, ...]] = {
    "count": (),
    "compare": (),
    "backup": (
        "PRESERVE_LABELS",
        "PRESERVE_FLAGS",
        "MANIFEST_ONLY",
        "GMAIL_MODE",
        "DEST_DELETE",
    ),
    "restore": (
        "APPLY_LABELS",
        "APPLY_FLAGS",
        "GMAIL_MODE",
        "FULL_RESTORE",
        "DEST_DELETE",
    ),
    "migrate": (
        "DELETE_FROM_SOURCE",
        "DEST_DELETE",
        "PRESERVE_LABELS",
        "PRESERVE_FLAGS",
        "GMAIL_MODE",
        "FULL_MIGRATE",
    ),
}
