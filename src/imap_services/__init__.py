"""Reusable services for IMAP backup, restore, migration, and verification."""

import logging

from imap_services.backup import BackupService
from imap_services.compare import ComparisonService
from imap_services.config import (
    AccountConfig,
    BackupOptions,
    ImapTarget,
    LocalTarget,
    MigrationOptions,
    OAuth2Config,
    RestoreOptions,
)
from imap_services.count import CountService
from imap_services.events import EventCallback, OperationEvent
from imap_services.exceptions import (
    AuthenticationError,
    CallbackError,
    ConfigurationError,
    ConnectionError,
    FilesystemError,
    ImapServiceError,
    OperationError,
)
from imap_services.migrate import MigrationService
from imap_services.restore import RestoreService
from imap_services.results import ComparisonResult, ComparisonRow, CountResult, FolderResult, TransferResult

logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    "AccountConfig",
    "AuthenticationError",
    "BackupOptions",
    "BackupService",
    "CallbackError",
    "ComparisonResult",
    "ComparisonRow",
    "ComparisonService",
    "ConfigurationError",
    "ConnectionError",
    "CountResult",
    "CountService",
    "EventCallback",
    "FilesystemError",
    "FolderResult",
    "ImapServiceError",
    "ImapTarget",
    "LocalTarget",
    "MigrationOptions",
    "MigrationService",
    "OAuth2Config",
    "OperationError",
    "OperationEvent",
    "RestoreOptions",
    "RestoreService",
    "TransferResult",
]
