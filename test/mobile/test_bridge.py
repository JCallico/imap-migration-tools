"""Tests for the native-mobile JSON service boundary."""

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from imap_services import AccountConfig, BackupOptions, OperationCancelled, backup_estimate
from imap_services.events import EventSink, OperationEvent
from mobile import bridge


class Listener:
    def __init__(self):
        self.events = []

    def onEvent(self, value):
        self.events.append(json.loads(value))


class Cancellation:
    def __init__(self, cancelled=False):
        self.cancelled = cancelled

    def isCancelled(self):
        return self.cancelled


@dataclass(frozen=True)
class Result:
    total: int


def test_count_request_streams_events_and_serializes_result(monkeypatch):
    class Service:
        def __init__(self, target, on_event):
            assert target.account.username == "person@example.com"
            self.on_event = on_event

        def run(self):
            event = type(
                "Event",
                (),
                {
                    "__dataclass_fields__": {},
                },
            )
            from imap_services import OperationEvent

            self.on_event(OperationEvent("count", "complete", "Count completed", current=3))
            return Result(3)

    monkeypatch.setattr(bridge, "CountService", Service)
    listener = Listener()
    response = json.loads(
        bridge.run_operation(
            json.dumps(
                {
                    "operation": "count",
                    "target": {
                        "kind": "imap",
                        "account": {"host": "imap.example.com", "username": "person@example.com", "password": "pw"},
                    },
                }
            ),
            listener,
            Cancellation(),
        )
    )

    assert response == {"status": "succeeded", "result": {"total": 3}}
    assert listener.events[0]["current"] == 3


def test_cancelled_request_does_not_construct_service(monkeypatch):
    monkeypatch.setattr(bridge, "_service", lambda *_args: (_ for _ in ()).throw(AssertionError("not called")))

    response = json.loads(bridge.run_operation('{"operation":"count"}', cancellation=Cancellation(True)))

    assert response == {"status": "cancelled"}


def test_native_oauth_token_provider_is_forwarded_to_service_account():
    class TokenProvider:
        def __init__(self):
            self.slots = []

        def getAccessToken(self, slot):
            self.slots.append(slot)
            return "refreshed-token"

    provider = TokenProvider()
    service = bridge._service(
        {
            "operation": "count",
            "target": {
                "kind": "imap",
                "account": {
                    "host": "imap.example.com",
                    "username": "person@example.com",
                    "tokenSlot": "source",
                    "oauth2": {"clientId": "client", "accessToken": "initial", "provider": "google"},
                },
            },
        },
        None,
        provider,
    )

    refresh = service.target.account.oauth2.token_provider
    assert refresh is not None
    assert refresh() == "refreshed-token"
    assert provider.slots == ["source"]


def test_backup_estimate_counts_only_messages_missing_locally(monkeypatch, tmp_path):
    inbox = tmp_path / "INBOX"
    inbox.mkdir()
    (inbox / "1_existing.eml").write_bytes(b"existing")

    class Connection:
        def select(self, folder, readonly=False):
            assert folder == '"INBOX"'
            assert readonly is True
            return "OK", []

        def uid(self, command, *args):
            if command == "search":
                return "OK", [b"1 2 3"]
            assert command == "fetch"
            assert args == ("2,3", "(UID RFC822.SIZE)")
            return "OK", [
                (b"2 (UID 2 RFC822.SIZE 150)", b""),
                (b"3 (UID 3 RFC822.SIZE 350)", b""),
            ]

        def logout(self):
            return "BYE", []

    monkeypatch.setattr(backup_estimate, "connect", lambda *_args: (Connection(), {}))
    response = json.loads(
        bridge.estimate_backup(
            json.dumps(
                {
                    "operation": "backup",
                    "source": {"host": "imap.example.com", "username": "person@example.com", "password": "pw"},
                    "backupPath": str(tmp_path),
                    "options": {"folder": "INBOX"},
                }
            )
        )
    )

    assert response == {"status": "succeeded", "estimatedBytes": 500, "messageCount": 2}


def test_backup_estimate_reports_incomplete_server_sizes(monkeypatch, tmp_path):
    class Connection:
        def select(self, *_args, **_kwargs):
            return "OK", []

        def uid(self, command, *_args):
            if command == "search":
                return "OK", [b"1 2"]
            return "OK", [(b"1 (UID 1 RFC822.SIZE 150)", b"")]

        def logout(self):
            return "BYE", []

    monkeypatch.setattr(backup_estimate, "connect", lambda *_args: (Connection(), {}))
    response = json.loads(
        bridge.estimate_backup(
            json.dumps(
                {
                    "operation": "backup",
                    "source": {"host": "imap.example.com", "username": "person@example.com", "password": "pw"},
                    "backupPath": str(tmp_path),
                    "options": {"folder": "INBOX"},
                }
            )
        )
    )

    assert response["status"] == "failed"
    assert response["error"]["message"] == "the IMAP server did not return a complete size estimate"


def test_invalid_request_returns_safe_failure():
    response = json.loads(bridge.run_operation("not-json"))

    assert response["status"] == "failed"
    assert response["error"]["type"] == "ValueError"
    assert "not-json" not in response["error"]["message"]


@pytest.mark.parametrize(
    ("request_json", "message"),
    [
        ("[]", "request must be a JSON object"),
        ('{"operation":"count","target":{"kind":"imap"}}', "account configuration is required"),
        ('{"operation":"count","target":[]}', "target configuration is required"),
        ('{"operation":"count","target":{"kind":"unknown"}}', "target kind must be 'local' or 'imap'"),
        ('{"operation":"count","target":{"kind":"local","path":"/tmp"},"options":[]}', "options must be a JSON object"),
        (
            '{"operation":"backup","source":{"host":"imap.example.com","username":"person@example.com","password":"pw"},"backupPath":""}',
            "backupPath is required",
        ),
        ('{"operation":"unknown"}', "operation must be count, compare, backup, restore, or migrate"),
    ],
)
def test_request_validation_returns_safe_failure(request_json, message):
    response = json.loads(bridge.run_operation(request_json))

    assert response == {"status": "failed", "error": {"type": "ValueError", "message": message}}


def test_compare_request_supports_local_and_imap_targets():
    service = bridge._service(
        {
            "operation": "compare",
            "source": {"kind": "local", "path": "/tmp/backup"},
            "destination": {
                "kind": "imap",
                "account": {"host": "imap.example.com", "username": "person@example.com", "password": "pw"},
            },
        },
        None,
    )

    assert service.source.path == Path("/tmp/backup")
    assert service.destination.account.username == "person@example.com"


def test_event_callback_honours_cancellation_before_notifying_listener():
    listener = Listener()

    with pytest.raises(OperationCancelled):
        bridge._event_callback(listener, Cancellation(True))(OperationEvent("count", "scan", "Scanning"))

    assert listener.events == []


def test_serializer_handles_nested_paths_tuples_and_dicts():
    assert bridge._serialize({"paths": (Path("one"), Path("two"))}) == {"paths": ["one", "two"]}


def test_backup_estimate_requires_backup_operation():
    response = json.loads(bridge.estimate_backup('{"operation":"count"}'))

    assert response == {"status": "failed", "error": {"message": "backup estimation requires a backup request"}}


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (OperationCancelled(), {"status": "cancelled"}),
        (
            RuntimeError("sensitive detail"),
            {"status": "failed", "error": {"message": "the mailbox size estimate could not be completed"}},
        ),
    ],
)
def test_backup_estimate_handles_cancelled_and_unexpected_failures(monkeypatch, tmp_path, error, expected):
    class Service:
        def __init__(self, *_args, **_kwargs):
            pass

        def run(self):
            raise error

    monkeypatch.setattr(bridge, "BackupEstimateService", Service)
    request = json.dumps(
        {
            "operation": "backup",
            "source": {"host": "imap.example.com", "username": "person@example.com", "password": "pw"},
            "backupPath": str(tmp_path),
        }
    )

    assert json.loads(bridge.estimate_backup(request)) == expected


def test_manifest_only_estimate_does_not_connect(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_estimate, "connect", lambda *_args: (_ for _ in ()).throw(AssertionError("not called")))

    result = backup_estimate.BackupEstimateService(
        AccountConfig("imap.example.com", "person@example.com", "pw"),
        tmp_path,
        BackupOptions(manifest_only=True),
    ).run()

    assert result.estimated_bytes == 0
    assert result.message_count == 0


@pytest.mark.parametrize(
    ("select_response", "search_response", "fetch_response", "message"),
    [
        ("NO", ("OK", [b"1"]), ("OK", []), "could not inspect folder: INBOX"),
        ("OK", ("NO", []), ("OK", []), "could not list messages in folder: INBOX"),
        ("OK", ("OK", [b"1"]), ("NO", []), "could not read message sizes in folder: INBOX"),
    ],
)
def test_backup_estimate_reports_imap_failures_and_ignores_logout_failure(
    monkeypatch, tmp_path, select_response, search_response, fetch_response, message
):
    class Connection:
        def select(self, *_args, **_kwargs):
            return select_response, []

        def uid(self, command, *_args):
            return search_response if command == "search" else fetch_response

        def logout(self):
            raise OSError("connection already closed")

    monkeypatch.setattr(backup_estimate, "connect", lambda *_args: (Connection(), {}))
    service = backup_estimate.BackupEstimateService(
        AccountConfig("imap.example.com", "person@example.com", "pw"),
        tmp_path,
        BackupOptions(folder="INBOX"),
    )

    with pytest.raises(backup_estimate.OperationError, match=message):
        service.run()


def test_backup_estimate_folder_selection_and_cancellation(monkeypatch, tmp_path):
    account = AccountConfig("imap.example.com", "person@example.com", "pw")
    gmail_service = backup_estimate.BackupEstimateService(account, tmp_path, BackupOptions(gmail_mode=True))
    folder_service = backup_estimate.BackupEstimateService(account, tmp_path, BackupOptions(folder="Archive"))
    discovered_service = backup_estimate.BackupEstimateService(account, tmp_path)
    cancelled_service = backup_estimate.BackupEstimateService(account, tmp_path, is_cancelled=lambda: True)
    monkeypatch.setattr(
        backup_estimate.imap_common, "list_selectable_folders", lambda _connection: ["INBOX", "Deleted Items"]
    )
    monkeypatch.setattr(backup_estimate.provider_exchange, "is_special_folder", lambda name: name == "Deleted Items")

    assert gmail_service._folders(object()) == [backup_estimate.provider_gmail.GMAIL_ALL_MAIL]
    assert folder_service._folders(object()) == ["Archive"]
    assert discovered_service._folders(object()) == ["INBOX"]
    with pytest.raises(OperationCancelled):
        cancelled_service._check_cancelled()


def test_backup_estimate_helpers_tolerate_unreadable_directories_and_unexpected_metadata(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "iterdir", lambda _path: (_ for _ in ()).throw(OSError("unreadable")))

    assert backup_estimate._existing_uids(tmp_path) == set()
    assert backup_estimate._parse_message_sizes(["not bytes", None]) == {}


def test_cancellation_is_not_wrapped_as_callback_failure():
    sink = EventSink("count", lambda _event: (_ for _ in ()).throw(OperationCancelled()))

    with pytest.raises(OperationCancelled):
        sink.emit("scan", "Scanning")


@pytest.mark.parametrize("operation", ["backup", "restore", "migrate"])
def test_transfer_requests_construct_public_services(operation, tmp_path):
    account = {"host": "imap.example.com", "username": "person@example.com", "password": "pw"}
    request = {
        "operation": operation,
        "source": account,
        "destination": account,
        "backupPath": str(tmp_path),
        "options": {
            "workers": 2,
            "batchSize": 3,
            "folder": "INBOX",
            "deleteOrphans": True,
            "gmailMode": True,
        },
    }

    service = bridge._service(request, None)

    assert service.options.workers == 2
    assert service.options.batch_size == 3
    assert service.options.folder == "INBOX"
    assert service.options.delete_orphans is True
    assert service.options.gmail_mode is True
