"""Count messages in an IMAP account or local backup."""

import imaplib
from typing import Optional

from imap_services._common import connect
from imap_services.config import ImapTarget, LocalTarget, Target
from imap_services.events import EventCallback, EventSink
from imap_services.exceptions import FilesystemError
from imap_services.results import CountResult
from utils import imap_common


class CountService:
    """Run one configured count operation."""

    def __init__(self, target: Target, on_event: Optional[EventCallback] = None) -> None:
        self.target = target
        self._events = EventSink("count", on_event)

    def run(self) -> CountResult:
        if isinstance(self.target, LocalTarget):
            return self._count_local()
        return self._count_imap(self.target)

    def _count_local(self) -> CountResult:
        path = self.target.path
        if not path.is_dir():
            raise FilesystemError(f"local backup path is not a directory: {path}")
        self._events.emit("scan", f"Scanning local backup: {path}")
        counts: dict[str, Optional[int]] = {}
        total = 0
        for folder in imap_common.list_local_folders(str(path)):
            count = imap_common.get_local_email_count(str(path), folder)
            counts[folder] = count
            if count is not None:
                total += count
            self._events.emit("folder", folder, folder=folder, current=count)
        self._events.emit("complete", "Count completed", current=total)
        return CountResult(counts, total)

    def _count_imap(self, target: ImapTarget) -> CountResult:
        self._events.emit("connect", f"Connecting to {target.account.host}...")
        mail, _ = connect(target.account, log_fn=self._events.message)
        counts: dict[str, Optional[int]] = {}
        total = 0
        try:
            self._events.emit("list", "Listing mailboxes...")
            for folder in imap_common.list_selectable_folders(mail):
                count = None
                try:
                    status, _ = mail.select(f'"{folder}"', readonly=True)
                    if status == "OK":
                        status, data = mail.search(None, "ALL")
                        if status == "OK":
                            count = len(data[0].split()) if data and data[0] else 0
                except imaplib.IMAP4.error:
                    pass
                counts[folder] = count
                if count is not None:
                    total += count
                self._events.emit("folder", folder, folder=folder, current=count)
        finally:
            try:
                mail.logout()
            except Exception:
                pass
        self._events.emit("complete", "Count completed", current=total)
        return CountResult(counts, total)
