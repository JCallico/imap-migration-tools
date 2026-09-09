"""Restore RFC 5322 files to an IMAP account."""

from pathlib import Path
from typing import Optional, Union

from imap_services._common import connect
from imap_services._legacy import progress_reporter
from imap_services.config import AccountConfig, RestoreOptions, validate_parallelism
from imap_services.events import EventCallback, EventSink
from imap_services.exceptions import FilesystemError, OperationError
from imap_services.results import FolderResult, TransferResult
from utils import imap_common


class RestoreService:
    """Run one configured restore operation."""

    def __init__(
        self,
        source: Union[str, Path],
        destination: AccountConfig,
        options: RestoreOptions = RestoreOptions(),
        on_event: Optional[EventCallback] = None,
    ) -> None:
        validate_parallelism(options.workers, options.batch_size)
        self.source = Path(source).expanduser()
        self.destination = destination
        self.options = options
        self._events = EventSink("restore", on_event)

    def run(self) -> TransferResult:
        from imap_services._operations import restore as legacy

        if not self.source.is_dir():
            raise FilesystemError(f"source path does not exist: {self.source}")
        legacy.MAX_WORKERS = self.options.workers
        legacy.BATCH_SIZE = self.options.batch_size
        connection, conf = connect(self.destination, "destination", self._events.message)
        apply_labels = self.options.apply_labels or self.options.gmail_mode
        apply_flags = self.options.apply_flags or self.options.gmail_mode
        manifest = {}
        if apply_labels or apply_flags:
            manifest = imap_common.load_manifest(str(self.source), "labels_manifest.json")
            if not manifest and apply_flags:
                manifest = imap_common.load_manifest(str(self.source), "flags_manifest.json")

        cache_file = cache_data = cache_lock = None
        try:
            cache_file, cache_data, cache_lock = imap_common.load_progress_cache(
                str(self.source), self.destination.host, self.destination.username, log_fn=self._events.message
            )
        except Exception as exc:
            self._events.emit("cache", f"Warning: Failed to load progress cache: {exc}", severity="warning")

        results = []
        with progress_reporter(legacy, self._events.message):
            try:
                if self.options.gmail_mode:
                    connection.logout()
                    connection = None
                    legacy.restore_gmail_with_labels(
                        str(self.source),
                        conf,
                        manifest,
                        apply_flags,
                        self.options.full_restore,
                        cache_file,
                        cache_data,
                        cache_lock,
                    )
                    results.append(FolderResult("__GMAIL_MODE__"))
                else:
                    if self.options.folder:
                        folder_path = self.source.joinpath(*self.options.folder.split("/"))
                        if not folder_path.exists():
                            raise FilesystemError(f"folder not found: {folder_path}")
                        folders = [(self.options.folder, str(folder_path))]
                    else:
                        folders = imap_common.get_backup_folders(str(self.source))
                        if not folders:
                            raise OperationError("no backup folders found")
                    for folder, folder_path in folders:
                        legacy.restore_folder(
                            folder,
                            folder_path,
                            conf,
                            manifest,
                            apply_labels,
                            apply_flags,
                            self.options.delete_orphans,
                            self.options.full_restore,
                            str(self.source),
                            cache_file,
                            cache_data,
                            cache_lock,
                        )
                        results.append(FolderResult(folder))
            finally:
                if connection:
                    try:
                        connection.logout()
                    except Exception:
                        pass
        self._events.emit("complete", "Restore completed successfully.")
        return TransferResult(tuple(results))
