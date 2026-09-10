"""Back up an IMAP account to RFC 5322 files."""

from pathlib import Path
from typing import Optional, Union

from imap_services._common import connect
from imap_services._legacy import progress_reporter
from imap_services.config import AccountConfig, BackupOptions, validate_parallelism
from imap_services.events import EventCallback, EventSink
from imap_services.exceptions import FilesystemError
from imap_services.results import FolderResult, TransferResult
from providers import provider_exchange, provider_gmail
from utils import imap_common


class BackupService:
    """Run one configured IMAP backup."""

    def __init__(
        self,
        source: AccountConfig,
        destination: Union[str, Path],
        options: BackupOptions = BackupOptions(),
        on_event: Optional[EventCallback] = None,
    ) -> None:
        validate_parallelism(options.workers, options.batch_size)
        self.source = source
        self.destination = Path(destination).expanduser()
        self.options = options
        self._events = EventSink("backup", on_event)

    def run(self) -> TransferResult:
        from imap_services._operations import backup as legacy

        try:
            self.destination.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise FilesystemError(f"could not create backup directory: {self.destination}") from exc

        legacy.MAX_WORKERS = self.options.workers
        legacy.BATCH_SIZE = self.options.batch_size
        connection, conf = connect(self.source, "source", self._events.message)
        folder_results = []
        artifacts = []
        with progress_reporter(legacy, self._events.message):
            try:
                if self.options.preserve_labels or self.options.manifest_only or self.options.gmail_mode:
                    legacy.build_labels_manifest(connection, str(self.destination), conf)
                    artifacts.append(self.destination / legacy.MANIFEST_FILENAME)
                elif self.options.preserve_flags:
                    folders = [self.options.folder] if self.options.folder else None
                    legacy.build_flags_manifest(connection, str(self.destination), folders, conf)
                    artifacts.append(self.destination / "flags_manifest.json")

                if not self.options.manifest_only:
                    if self.options.gmail_mode:
                        folders_to_run = [provider_gmail.GMAIL_ALL_MAIL]
                    elif self.options.folder:
                        folders_to_run = [self.options.folder]
                    else:
                        folders_to_run = [
                            name
                            for name in imap_common.list_selectable_folders(connection)
                            if not provider_exchange.is_special_folder(name)
                        ]
                    for folder in folders_to_run:
                        legacy.backup_folder(
                            connection,
                            folder,
                            str(self.destination),
                            conf,
                            self.options.delete_orphans,
                        )
                        folder_results.append(FolderResult(folder))
            finally:
                try:
                    connection.logout()
                except Exception:
                    pass
        self._events.emit("complete", "Backup completed successfully.")
        return TransferResult(tuple(folder_results), tuple(path for path in artifacts if path.exists()))
