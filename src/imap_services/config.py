"""Configuration models for the public IMAP services API."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

from imap_services.exceptions import ConfigurationError


@dataclass(frozen=True)
class OAuth2Config:
    client_id: str
    client_secret: Optional[str] = field(default=None, repr=False)
    account_type: str = "auto"
    access_token: Optional[str] = field(default=None, repr=False)
    provider: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.client_id:
            raise ConfigurationError("OAuth2 client_id is required")
        if self.account_type not in {"auto", "personal", "work"}:
            raise ConfigurationError("account_type must be auto, personal, or work")


@dataclass(frozen=True)
class AccountConfig:
    host: str
    username: str
    password: Optional[str] = field(default=None, repr=False)
    oauth2: Optional[OAuth2Config] = None

    def __post_init__(self) -> None:
        if not self.host or not self.username:
            raise ConfigurationError("account host and username are required")
        if bool(self.password) == bool(self.oauth2):
            raise ConfigurationError("configure exactly one of password or OAuth2")


@dataclass(frozen=True)
class LocalTarget:
    path: Path

    def __init__(self, path: Union[str, Path]) -> None:
        object.__setattr__(self, "path", Path(path).expanduser())


@dataclass(frozen=True)
class ImapTarget:
    account: AccountConfig


Target = Union[LocalTarget, ImapTarget]


@dataclass(frozen=True)
class BackupOptions:
    folder: Optional[str] = None
    workers: int = 10
    batch_size: int = 10
    preserve_labels: bool = False
    preserve_flags: bool = False
    manifest_only: bool = False
    gmail_mode: bool = False
    delete_orphans: bool = False


@dataclass(frozen=True)
class RestoreOptions:
    folder: Optional[str] = None
    workers: int = 4
    batch_size: int = 10
    apply_labels: bool = False
    apply_flags: bool = False
    gmail_mode: bool = False
    delete_orphans: bool = False
    full_restore: bool = False


@dataclass(frozen=True)
class MigrationOptions:
    folder: Optional[str] = None
    workers: int = 10
    batch_size: int = 10
    delete_source: bool = False
    delete_orphans: bool = False
    preserve_flags: bool = False
    preserve_labels: bool = False
    gmail_mode: bool = False
    cache_path: Optional[Path] = None
    full_migrate: bool = False
    destination_folder_prefix: Optional[str] = None
    destination_folder_separator: Optional[str] = None


def validate_parallelism(workers: int, batch_size: int) -> None:
    if workers <= 0 or batch_size <= 0:
        raise ConfigurationError("workers and batch_size must be positive")
