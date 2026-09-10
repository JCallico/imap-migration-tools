"""Shared workspace decisions without a GUI event loop."""

from __future__ import annotations

from pathlib import Path

from ui_core.config import FIELDS, read_valid_env, validate
from ui_core.operations import OPERATION_SWITCHES, RunOptions


def validated_form(path: Path) -> dict[str, str]:
    """Read a complete valid form, preserving the previous form on failure."""
    file_values = read_valid_env(path)
    values = {field.name: file_values.get(field.name, field.default) for field in FIELDS}
    errors = validate(values)
    if errors:
        name, message = next(iter(errors.items()))
        raise ValueError(f"{name}: {message}")
    return values


def make_options(operation, values, count_mode="source", source_mode="auto", destination_mode="auto", folder=""):
    """Translate workspace selections into existing command options."""
    switches = {name: values.get(name, "false").lower() == "true" for name in OPERATION_SWITCHES[operation]}
    if operation == "count":
        return RunOptions(switches=switches, target=count_mode)
    if operation == "compare":
        environment = {}
        paths = []
        for prefix, mode in (("SRC", source_mode), ("DEST", destination_mode)):
            key = f"{prefix}_LOCAL_PATH"
            if mode == "imap":
                environment[key] = ""
            paths.append(values.get(key, "") if mode == "local" else "")
        return RunOptions(switches=switches, environment=environment, source_path=paths[0], destination_path=paths[1])
    return RunOptions(
        folder if operation in {"backup", "restore"} else "",
        int(values.get("MAX_WORKERS", "4") or "4"),
        int(values.get("BATCH_SIZE", "10") or "10"),
        "",
        switches,
        {},
    )


def run_confirmation(operation, options, values):
    """Describe the same destructive targets in every frontend."""
    targets = []
    if options.switches.get("DELETE_FROM_SOURCE"):
        targets.append(f"source {values.get('SRC_IMAP_USERNAME')}@{values.get('SRC_IMAP_HOST')}")
    if options.switches.get("DEST_DELETE"):
        target = (
            values.get("BACKUP_LOCAL_PATH")
            if operation == "backup"
            else f"{values.get('DEST_IMAP_USERNAME')}@{values.get('DEST_IMAP_HOST')}"
        )
        targets.append(f"destination {target}")
    if targets:
        return f"Type DELETE to run {operation} and remove data from {', '.join(targets)}.", True
    return f"Run {operation}?", False
