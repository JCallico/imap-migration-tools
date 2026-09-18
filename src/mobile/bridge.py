"""Stable JSON boundary between native mobile clients and IMAP services."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from imap_services import (
    AccountConfig,
    BackupEstimateService,
    BackupOptions,
    BackupService,
    ComparisonService,
    CountService,
    ImapServiceError,
    ImapTarget,
    LocalTarget,
    MigrationOptions,
    MigrationService,
    OAuth2Config,
    OperationCancelled,
    RestoreOptions,
    RestoreService,
)


def _load_request(request_json: str) -> dict[str, Any]:
    try:
        request = json.loads(request_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("request must be valid JSON") from exc
    if not isinstance(request, dict):
        raise ValueError("request must be a JSON object")
    return request


def _account(value: Any, token_provider=None) -> AccountConfig:
    if not isinstance(value, dict):
        raise ValueError("account configuration is required")
    oauth_value = value.get("oauth2")
    oauth2 = None
    if oauth_value:
        token_slot = value.get("tokenSlot")

        def refresh_external_token():
            return str(token_provider.getAccessToken(str(token_slot)))

        oauth2 = OAuth2Config(
            client_id=str(oauth_value.get("clientId", "")),
            client_secret=oauth_value.get("clientSecret"),
            account_type=str(oauth_value.get("accountType", "auto")),
            access_token=oauth_value.get("accessToken"),
            provider=oauth_value.get("provider"),
            token_provider=refresh_external_token if token_provider is not None and token_slot else None,
        )
    return AccountConfig(
        host=str(value.get("host", "")),
        username=str(value.get("username", "")),
        password=value.get("password"),
        oauth2=oauth2,
    )


def _target(value: Any, token_provider=None):
    if not isinstance(value, dict):
        raise ValueError("target configuration is required")
    kind = value.get("kind")
    if kind == "local":
        return LocalTarget(str(value.get("path", "")))
    if kind == "imap":
        return ImapTarget(_account(value.get("account"), token_provider))
    raise ValueError("target kind must be 'local' or 'imap'")


def _options(request: dict[str, Any]) -> dict[str, Any]:
    value = request.get("options", {})
    if not isinstance(value, dict):
        raise ValueError("options must be a JSON object")
    return value


def _path(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} is required")
    return value


def _event_callback(listener, cancellation):
    def emit(event) -> None:
        if cancellation is not None and cancellation.isCancelled():
            raise OperationCancelled("operation cancelled")
        if listener is not None:
            listener.onEvent(json.dumps(asdict(event), separators=(",", ":")))

    return emit


def _serialize(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, tuple):
        return [_serialize(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _serialize(item) for key, item in value.items()}
    if hasattr(value, "__dataclass_fields__"):
        return {key: _serialize(item) for key, item in asdict(value).items()}
    return value


def _service(request: dict[str, Any], on_event, token_provider=None):
    operation = request.get("operation")
    options = _options(request)
    if operation == "count":
        return CountService(_target(request.get("target"), token_provider), on_event)
    if operation == "compare":
        return ComparisonService(
            _target(request.get("source"), token_provider),
            _target(request.get("destination"), token_provider),
            on_event,
            destination_folder_prefix=options.get("destinationFolderPrefix"),
            destination_folder_separator=options.get("destinationFolderSeparator"),
        )
    if operation == "backup":
        return BackupService(
            _account(request.get("source"), token_provider),
            _path(request.get("backupPath"), "backupPath"),
            BackupOptions(
                folder=options.get("folder"),
                workers=int(options.get("workers", 10)),
                batch_size=int(options.get("batchSize", 10)),
                preserve_labels=bool(options.get("preserveLabels", False)),
                preserve_flags=bool(options.get("preserveFlags", False)),
                manifest_only=bool(options.get("manifestOnly", False)),
                gmail_mode=bool(options.get("gmailMode", False)),
                delete_orphans=bool(options.get("deleteOrphans", False)),
            ),
            on_event,
        )
    if operation == "restore":
        return RestoreService(
            _path(request.get("backupPath"), "backupPath"),
            _account(request.get("destination"), token_provider),
            RestoreOptions(
                folder=options.get("folder"),
                workers=int(options.get("workers", 4)),
                batch_size=int(options.get("batchSize", 10)),
                apply_labels=bool(options.get("applyLabels", False)),
                apply_flags=bool(options.get("applyFlags", False)),
                gmail_mode=bool(options.get("gmailMode", False)),
                delete_orphans=bool(options.get("deleteOrphans", False)),
                full_restore=bool(options.get("fullRestore", False)),
            ),
            on_event,
        )
    if operation == "migrate":
        cache_path = options.get("cachePath")
        return MigrationService(
            _account(request.get("source"), token_provider),
            _account(request.get("destination"), token_provider),
            MigrationOptions(
                folder=options.get("folder"),
                workers=int(options.get("workers", 10)),
                batch_size=int(options.get("batchSize", 10)),
                delete_source=bool(options.get("deleteSource", False)),
                delete_orphans=bool(options.get("deleteOrphans", False)),
                preserve_flags=bool(options.get("preserveFlags", False)),
                preserve_labels=bool(options.get("preserveLabels", False)),
                gmail_mode=bool(options.get("gmailMode", False)),
                cache_path=Path(cache_path) if cache_path else None,
                full_migrate=bool(options.get("fullMigrate", False)),
                destination_folder_prefix=options.get("destinationFolderPrefix"),
                destination_folder_separator=options.get("destinationFolderSeparator"),
            ),
            on_event,
        )
    raise ValueError("operation must be count, compare, backup, restore, or migrate")


def run_operation(request_json: str, listener=None, cancellation=None, token_provider=None) -> str:
    """Run one operation and return a secret-free JSON envelope.

    ``listener`` and ``cancellation`` are deliberately duck typed so Chaquopy
    can supply small Kotlin/Java objects without Python-specific interfaces.
    """
    try:
        request = _load_request(request_json)
        if cancellation is not None and cancellation.isCancelled():
            raise OperationCancelled("operation cancelled")
        result = _service(request, _event_callback(listener, cancellation), token_provider).run()
        envelope = {"status": "succeeded", "result": _serialize(result)}
    except OperationCancelled:
        envelope = {"status": "cancelled"}
    except (ImapServiceError, ValueError, TypeError) as exc:
        envelope = {"status": "failed", "error": {"type": type(exc).__name__, "message": str(exc)}}
    return json.dumps(envelope, separators=(",", ":"))


def estimate_backup(request_json: str, cancellation=None, token_provider=None) -> str:
    """Estimate bytes needed by an incremental backup without fetching message bodies."""
    try:
        request = _load_request(request_json)
        if request.get("operation") != "backup":
            raise ValueError("backup estimation requires a backup request")
        options = _options(request)
        result = BackupEstimateService(
            _account(request.get("source"), token_provider),
            _path(request.get("backupPath"), "backupPath"),
            BackupOptions(
                folder=options.get("folder"),
                preserve_labels=bool(options.get("preserveLabels", False)),
                preserve_flags=bool(options.get("preserveFlags", False)),
                manifest_only=bool(options.get("manifestOnly", False)),
                gmail_mode=bool(options.get("gmailMode", False)),
            ),
            is_cancelled=(lambda: cancellation is not None and cancellation.isCancelled()),
        ).run()
        envelope = {
            "status": "succeeded",
            "estimatedBytes": result.estimated_bytes,
            "messageCount": result.message_count,
        }
    except OperationCancelled:
        envelope = {"status": "cancelled"}
    except (ImapServiceError, OSError, ValueError, TypeError) as exc:
        envelope = {"status": "failed", "error": {"message": str(exc)}}
    except Exception:
        envelope = {"status": "failed", "error": {"message": "the mailbox size estimate could not be completed"}}
    return json.dumps(envelope, separators=(",", ":"))
