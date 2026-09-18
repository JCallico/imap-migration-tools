"""Tests for the native-mobile JSON service boundary."""

import json
from dataclasses import dataclass

import pytest

from imap_services import OperationCancelled, backup_estimate
from imap_services.events import EventSink
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
