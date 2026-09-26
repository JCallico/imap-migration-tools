"""Read-only size estimation for incremental IMAP backups."""

import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Optional, Union

from imap_services._common import connect
from imap_services.config import AccountConfig, BackupOptions
from imap_services.exceptions import OperationCancelled, OperationError
from imap_services.results import BackupEstimateResult
from providers import provider_exchange, provider_gmail
from utils import imap_common

_UID_PATTERN = re.compile(rb"\bUID\s+(\d+)", re.IGNORECASE)
_SIZE_PATTERN = re.compile(rb"\bRFC822\.SIZE\s+(\d+)", re.IGNORECASE)
_FETCH_BATCH_SIZE = 250


class BackupEstimateService:
    """Estimate bytes needed by a backup without fetching message bodies."""

    def __init__(
        self,
        source: AccountConfig,
        destination: Union[str, Path],
        options: BackupOptions = BackupOptions(),
        is_cancelled: Optional[Callable[[], bool]] = None,
    ) -> None:
        self.source = source
        self.destination = Path(destination).expanduser()
        self.options = options
        self._is_cancelled = is_cancelled

    def run(self) -> BackupEstimateResult:
        if self.options.manifest_only:
            return BackupEstimateResult(0, 0)

        connection, _ = connect(self.source, "source")
        try:
            estimated_bytes = 0
            message_count = 0
            for folder in self._folders(connection):
                self._check_cancelled()
                response, _ = connection.select(f'"{folder}"', readonly=True)
                if response != "OK":
                    raise OperationError(f"could not inspect folder: {folder}")
                response, data = connection.uid("search", None, "ALL")
                if response != "OK" or not data or data[0] is None:
                    raise OperationError(f"could not list messages in folder: {folder}")

                existing_uids = _existing_uids(self.destination / folder.replace("/", os.sep))
                uids = [uid for uid in data[0].split() if _as_text(uid) not in existing_uids]
                for offset in range(0, len(uids), _FETCH_BATCH_SIZE):
                    self._check_cancelled()
                    requested = uids[offset : offset + _FETCH_BATCH_SIZE]
                    uid_set = ",".join(_as_text(uid) for uid in requested)
                    response, size_data = connection.uid("fetch", uid_set, "(UID RFC822.SIZE)")
                    if response != "OK":
                        raise OperationError(f"could not read message sizes in folder: {folder}")
                    sizes = _parse_message_sizes(size_data)
                    if len(sizes) != len(requested):
                        raise OperationError("the IMAP server did not return a complete size estimate")
                    estimated_bytes += sum(sizes.values())
                    message_count += len(sizes)
            return BackupEstimateResult(estimated_bytes, message_count)
        finally:
            try:
                connection.logout()
            except Exception:
                pass

    def _folders(self, connection) -> list[str]:
        if self.options.gmail_mode:
            return [provider_gmail.GMAIL_ALL_MAIL]
        if self.options.folder:
            return [self.options.folder]
        return [
            name
            for name in imap_common.list_selectable_folders(connection)
            if not provider_exchange.is_special_folder(name)
        ]

    def _check_cancelled(self) -> None:
        if self._is_cancelled is not None and self._is_cancelled():
            raise OperationCancelled("operation cancelled")


def _as_text(value) -> str:
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


def _existing_uids(local_folder: Path) -> set[str]:
    if not local_folder.is_dir():
        return set()
    try:
        return {
            path.name.split("_", 1)[0]
            for path in local_folder.iterdir()
            if path.name.endswith(".eml") and "_" in path.name and path.name.split("_", 1)[0].isdigit()
        }
    except OSError:
        return set()


def _parse_message_sizes(data) -> dict[str, int]:
    sizes = {}
    for item in data or ():
        metadata = item[0] if isinstance(item, tuple) else item
        if not isinstance(metadata, bytes):
            continue
        uid_match = _UID_PATTERN.search(metadata)
        size_match = _SIZE_PATTERN.search(metadata)
        if uid_match and size_match:
            sizes[uid_match.group(1).decode("ascii")] = int(size_match.group(1))
    return sizes
