"""Schema-driven configuration and safe ``.env`` persistence."""

from __future__ import annotations

import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dotenv import dotenv_values, set_key
from dotenv.parser import parse_stream

FieldKind = Literal["text", "secret", "integer", "boolean", "choice", "path"]


@dataclass(frozen=True)
class ConfigField:
    """Metadata for one supported environment variable."""

    name: str
    label: str
    group: str
    kind: FieldKind = "text"
    default: str = ""
    choices: tuple[str, ...] = ()
    help: str = ""
    advanced: bool = False

    @property
    def sensitive(self) -> bool:
        return self.kind == "secret"


FIELDS: tuple[ConfigField, ...] = (
    ConfigField("SRC_IMAP_HOST", "IMAP host", "Source Account", help="IMAP server hostname"),
    ConfigField("SRC_IMAP_USERNAME", "Username", "Source Account"),
    ConfigField("SRC_IMAP_PASSWORD", "Password", "Source Account", "secret"),
    ConfigField("DEST_IMAP_HOST", "IMAP host", "Destination Account", help="IMAP server hostname"),
    ConfigField("DEST_IMAP_USERNAME", "Username", "Destination Account"),
    ConfigField("DEST_IMAP_PASSWORD", "Password", "Destination Account", "secret"),
    ConfigField("DEST_FOLDER_PREFIX", "Folder prefix", "Destination Account", advanced=True),
    ConfigField("DEST_FOLDER_SEP", "Folder separator", "Destination Account", advanced=True),
    ConfigField("SRC_OAUTH2_CLIENT_ID", "Source client ID", "OAuth2"),
    ConfigField("SRC_OAUTH2_CLIENT_SECRET", "Source client secret", "OAuth2", "secret"),
    ConfigField("DEST_OAUTH2_CLIENT_ID", "Destination client ID", "OAuth2"),
    ConfigField("DEST_OAUTH2_CLIENT_SECRET", "Destination client secret", "OAuth2", "secret"),
    ConfigField("OAUTH2_CACHE_ENABLED", "Persistent cache", "OAuth2", "boolean", "true"),
    ConfigField("OAUTH2_CACHE_DIR", "Cache directory", "OAuth2", "path"),
    ConfigField("BACKUP_LOCAL_PATH", "Backup path", "Local paths", "path"),
    ConfigField("SRC_LOCAL_PATH", "Comparison source path", "Local paths", "path"),
    ConfigField("DEST_LOCAL_PATH", "Comparison destination path", "Local paths", "path"),
    ConfigField(
        "SRC_ACCOUNT_TYPE",
        "Source account type",
        "Microsoft account type overrides",
        "choice",
        "auto",
        ("auto", "personal", "work"),
    ),
    ConfigField(
        "DEST_ACCOUNT_TYPE",
        "Destination account type",
        "Microsoft account type overrides",
        "choice",
        "auto",
        ("auto", "personal", "work"),
    ),
    ConfigField("MAX_WORKERS", "Parallel workers", "Shared options", "integer", "4"),
    ConfigField("BATCH_SIZE", "Batch size", "Shared options", "integer", "10"),
    ConfigField("DEST_DELETE", "Delete destination orphans", "Shared options", "boolean", "false"),
    ConfigField("DELETE_FROM_SOURCE", "Delete from source", "Migration options", "boolean", "false"),
    ConfigField("PRESERVE_LABELS", "Preserve Gmail labels", "Migration options", "boolean", "false"),
    ConfigField("PRESERVE_FLAGS", "Preserve flags", "Migration options", "boolean", "false"),
    ConfigField("GMAIL_MODE", "Gmail mode", "Migration options", "boolean", "false"),
    ConfigField("MIGRATE_ONLY_FOLDER", "Only this folder", "Migration options"),
    ConfigField("MIGRATE_CACHE_DIR", "Migration cache directory", "Migration options", "path"),
    ConfigField("FULL_MIGRATE", "Ignore cached skip decisions", "Migration options", "boolean", "false"),
    ConfigField("MANIFEST_ONLY", "Manifest only", "Backup options", "boolean", "false"),
    ConfigField("APPLY_LABELS", "Apply Gmail labels", "Restore options", "boolean", "false"),
    ConfigField("APPLY_FLAGS", "Apply flags", "Restore options", "boolean", "false"),
    ConfigField("FULL_RESTORE", "Full restore", "Restore options", "boolean", "false"),
    ConfigField("OAUTH2_GOOGLE_AUTH_URL", "Google authorization URL", "Advanced OAuth2 endpoints", advanced=True),
    ConfigField("OAUTH2_GOOGLE_TOKEN_URL", "Google token URL", "Advanced OAuth2 endpoints", advanced=True),
    ConfigField(
        "OAUTH2_MICROSOFT_AUTHORITY_BASE_URL",
        "Microsoft authority URL",
        "Advanced OAuth2 endpoints",
        advanced=True,
    ),
    ConfigField(
        "OAUTH2_MICROSOFT_DISCOVERY_URL",
        "Microsoft discovery host",
        "Advanced OAuth2 endpoints",
        advanced=True,
    ),
)

FIELD_BY_NAME = {field.name: field for field in FIELDS}
SECRET_NAMES = frozenset(field.name for field in FIELDS if field.sensitive)


@dataclass(frozen=True)
class EffectiveValue:
    value: str
    source: str


def discover_env(start: Path | None = None) -> Path:
    """Return the discovered env file, or the path to create in ``start``."""
    base = (start or Path.cwd()).resolve()
    for directory in (base, *base.parents):
        candidate = directory / ".env"
        if candidate.is_file():
            return candidate
    return base / ".env"


def read_env(path: Path) -> dict[str, str]:
    """Parse an env file without modifying process environment."""
    if not path.exists():
        return {}
    return {key: value or "" for key, value in dotenv_values(path).items()}


def effective_values(path: Path, overrides: dict[str, str] | None = None) -> dict[str, EffectiveValue]:
    """Resolve values using TUI, OS, env-file, then schema defaults."""
    file_values = read_env(path)
    run_values = overrides or {}
    result: dict[str, EffectiveValue] = {}
    for field in FIELDS:
        if field.name in run_values:
            result[field.name] = EffectiveValue(run_values[field.name], "TUI override")
        elif field.name in os.environ:
            result[field.name] = EffectiveValue(os.environ[field.name], "OS environment")
        elif field.name in file_values:
            result[field.name] = EffectiveValue(file_values[field.name], ".env")
        else:
            result[field.name] = EffectiveValue(field.default, "default")
    return result


def validate(values: dict[str, str]) -> dict[str, str]:
    """Return validation errors keyed by variable name."""
    errors: dict[str, str] = {}
    for field in FIELDS:
        value = values.get(field.name, field.default)
        if field.kind == "integer" and value:
            try:
                if int(value) < 1:
                    raise ValueError
            except ValueError:
                errors[field.name] = "Must be a positive integer"
        elif field.kind == "boolean" and value.lower() not in {"true", "false", ""}:
            errors[field.name] = "Must be true or false"
        elif field.choices and value not in field.choices:
            errors[field.name] = f"Choose one of: {', '.join(field.choices)}"
    for name, value in values.items():
        if value and any(
            marker in value.lower() for marker in ("your-app-password", "your-client-id", "your-dest-client-id")
        ):
            errors[name] = "Replace the example placeholder"
    return errors


def render_new_env(values: dict[str, str]) -> str:
    """Render a grouped env file from schema metadata."""
    lines: list[str] = []
    group = None
    for field in FIELDS:
        if field.group != group:
            if lines:
                lines.append("")
            group = field.group
            lines.append(f"# {group}")
        value = values.get(field.name, field.default)
        escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        lines.append(f'{field.name}="{escaped}"')
    return "\n".join(lines) + "\n"


def save_form(path: Path, values: dict[str, str]) -> None:
    """Atomically update supported keys while retaining unknown content."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            if path.exists():
                stream.write(path.read_text(encoding="utf-8"))
            else:
                stream.write(render_new_env({}))
        for field in FIELDS:
            set_key(temp, field.name, values.get(field.name, field.default), quote_mode="always")
        os.chmod(temp, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def save_raw(path: Path, content: str) -> None:
    """Validate and atomically save raw env content."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
        with temp.open(encoding="utf-8") as stream:
            invalid = [binding.original.line for binding in parse_stream(stream) if binding.error]
        if invalid:
            raise ValueError(f"Invalid .env syntax on line {invalid[0]}")
        os.chmod(temp, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()
