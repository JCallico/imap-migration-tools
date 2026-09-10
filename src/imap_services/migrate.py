"""Migrate messages between two IMAP accounts."""

from typing import Optional

from core import imap_session
from imap_services._common import connect
from imap_services._legacy import progress_reporter
from imap_services.config import AccountConfig, MigrationOptions, validate_parallelism
from imap_services.events import EventCallback, EventSink
from imap_services.exceptions import ConnectionError, OperationError
from imap_services.results import FolderResult, TransferResult
from providers import provider_exchange, provider_gmail
from utils import imap_common


class MigrationService:
    """Run one configured direct IMAP migration."""

    def __init__(
        self,
        source: AccountConfig,
        destination: AccountConfig,
        options: MigrationOptions = MigrationOptions(),
        on_event: Optional[EventCallback] = None,
    ) -> None:
        validate_parallelism(options.workers, options.batch_size)
        self.source = source
        self.destination = destination
        self.options = options
        self._events = EventSink("migrate", on_event)

    def run(self) -> TransferResult:
        from imap_services._operations import migrate as legacy

        legacy.MAX_WORKERS = self.options.workers
        legacy.BATCH_SIZE = self.options.batch_size
        source_conn, source_conf = connect(self.source, "source", self._events.message)
        destination_conn = None
        results = []
        with progress_reporter(legacy, self._events.message):
            try:
                destination_conn, destination_conf = connect(self.destination, "destination", self._events.message)
                prefix, separator = imap_common.detect_dest_namespace(destination_conn)
                destination_conf["folder_prefix"] = self.options.destination_folder_prefix or prefix
                destination_conf["folder_sep"] = self.options.destination_folder_separator or separator
                destination_conn.configure_folder_mapping(
                    destination_conf["folder_prefix"], destination_conf["folder_sep"]
                )

                trash_folder = None
                if self.options.delete_source:
                    trash_folder = imap_common.detect_trash_folder(source_conn)

                preserve_flags = self.options.preserve_flags or self.options.gmail_mode
                preserve_labels = self.options.preserve_labels or self.options.gmail_mode
                label_index = None
                if self.options.gmail_mode and preserve_labels:
                    label_index = provider_gmail.build_gmail_label_index(source_conn, self._events.message)

                cache_file = cache_data = cache_lock = None
                if self.options.cache_path:
                    try:
                        cache_file, cache_data, cache_lock = imap_common.load_progress_cache(
                            str(self.options.cache_path),
                            self.destination.host,
                            self.destination.username,
                            log_fn=self._events.message,
                        )
                    except Exception as exc:
                        self._events.emit("cache", f"Warning: Failed to load progress cache: {exc}", severity="warning")

                gmail_mode = self.options.gmail_mode
                if self.options.folder:
                    folders = [self.options.folder]
                elif gmail_mode:
                    available = imap_common.list_selectable_folders(source_conn)
                    if provider_gmail.GMAIL_ALL_MAIL in available:
                        folders = [provider_gmail.GMAIL_ALL_MAIL]
                    else:
                        gmail_mode = False
                        folders = available
                else:
                    folders = imap_common.list_selectable_folders(source_conn)

                for folder in folders:
                    if self.options.delete_source and trash_folder == folder:
                        if self.options.folder:
                            raise OperationError("cannot migrate Trash while source deletion is enabled")
                        continue
                    if not gmail_mode and provider_exchange.is_special_folder(folder):
                        continue
                    source_conn = imap_session.ensure_connection(source_conn, source_conf)
                    destination_conn = imap_session.ensure_connection(destination_conn, destination_conf)
                    if not source_conn or not destination_conn:
                        raise ConnectionError("could not reconnect while migrating folders")
                    legacy.migrate_folder(
                        source_conn,
                        destination_conn,
                        folder,
                        self.options.delete_source,
                        source_conf,
                        destination_conf,
                        trash_folder,
                        self.options.delete_orphans,
                        preserve_flags,
                        gmail_mode,
                        label_index,
                        progress_cache_path=str(self.options.cache_path) if self.options.cache_path else None,
                        full_migrate=self.options.full_migrate,
                        progress_cache_file=cache_file,
                        progress_cache_data=cache_data,
                        progress_cache_lock=cache_lock,
                    )
                    results.append(FolderResult(folder))
            finally:
                for connection in (source_conn, destination_conn):
                    if connection:
                        try:
                            connection.logout()
                        except Exception:
                            pass
        self._events.emit("complete", "Migration completed successfully.")
        return TransferResult(tuple(results))
