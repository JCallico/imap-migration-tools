"""Compare folder counts between IMAP accounts and local backups."""

from typing import Optional

from imap_services._common import connect
from imap_services.config import ImapTarget, LocalTarget, Target
from imap_services.events import EventCallback, EventSink
from imap_services.exceptions import FilesystemError, OperationError
from imap_services.results import ComparisonResult, ComparisonRow
from utils import imap_common


def _imap_count(connection, folder: str) -> Optional[int]:
    try:
        status, data = connection.select(f'"{folder}"', readonly=True)
        if status != "OK":
            return None
        return int(data[0]) if data and data[0] else 0
    except Exception:
        return None


class ComparisonService:
    """Run one configured folder-count comparison."""

    def __init__(
        self,
        source: Target,
        destination: Target,
        on_event: Optional[EventCallback] = None,
        *,
        destination_folder_prefix: Optional[str] = None,
        destination_folder_separator: Optional[str] = None,
    ) -> None:
        self.source = source
        self.destination = destination
        self.destination_folder_prefix = destination_folder_prefix
        self.destination_folder_separator = destination_folder_separator
        self._events = EventSink("compare", on_event)

    def run(self) -> ComparisonResult:
        source_conn = None
        destination_conn = None
        for target in (self.source, self.destination):
            if isinstance(target, LocalTarget) and not target.path.is_dir():
                raise FilesystemError(f"local backup path is not a directory: {target.path}")
        try:
            if isinstance(self.source, ImapTarget):
                self._events.emit("connect", "Connecting to Source...")
                source_conn, _ = connect(self.source.account, "source", self._events.message)
            if isinstance(self.destination, ImapTarget):
                self._events.emit("connect", "Connecting to Destination...")
                destination_conn, _ = connect(self.destination.account, "destination", self._events.message)
                prefix, separator = imap_common.detect_dest_namespace(destination_conn)
                destination_conn.configure_folder_mapping(
                    self.destination_folder_prefix or prefix,
                    self.destination_folder_separator or separator,
                )

            self._events.emit("list", "Listing folders in Source...")
            if isinstance(self.source, LocalTarget):
                folders = imap_common.list_local_folders(str(self.source.path))
            else:
                folders = imap_common.list_selectable_folders(source_conn)
            if not folders:
                raise OperationError("failed to list source folders")

            rows = []
            source_total = 0
            destination_total = 0
            for folder in folders:
                source_count = self._target_count(self.source, source_conn, folder)
                destination_count = self._target_count(self.destination, destination_conn, folder)
                row = ComparisonRow(folder, source_count, destination_count)
                rows.append(row)
                if source_count is not None:
                    source_total += source_count
                if source_count is not None and destination_count is not None:
                    destination_total += destination_count
                self._events.emit("folder", folder, folder=folder, current=source_count, total=destination_count)
            result = ComparisonResult(tuple(rows), source_total, destination_total)
            self._events.emit("complete", "Comparison completed")
            return result
        finally:
            for connection in (source_conn, destination_conn):
                if connection:
                    try:
                        connection.logout()
                    except BaseException:
                        pass

    @staticmethod
    def _target_count(target: Target, connection, folder: str) -> Optional[int]:
        if isinstance(target, LocalTarget):
            return imap_common.get_local_email_count(str(target.path), folder)
        return _imap_count(connection, folder)
