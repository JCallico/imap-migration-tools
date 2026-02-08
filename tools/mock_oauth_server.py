import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

MOCK_TENANT_ID = "00000000-0000-0000-0000-000000000000"


def _write_json(handler, status, payload):
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class MockOAuthHandler(BaseHTTPRequestHandler):
    """Minimal OAuth2 mock server for tests."""

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.endswith("/.well-known/openid-configuration"):
            issuer = f"https://login.microsoftonline.com/{MOCK_TENANT_ID}/v2.0"
            _write_json(self, 200, {"issuer": issuer})
            return

        _write_json(self, 404, {"error": "not_found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length) if length else b""

        if parsed.path == "/google/token":
            _write_json(self, 200, {"access_token": "mock-google-token"})
            return

        if parsed.path == "/microsoft/token":
            _write_json(self, 200, {"access_token": "mock-microsoft-token"})
            return

        _write_json(self, 404, {"error": "not_found"})

    def log_message(self, _format, *_args):
        # Silence default HTTP server logging during tests.
        return


class MockOAuthServer(HTTPServer):
    allow_reuse_address = True


def start_server_thread(port=0):
    server = MockOAuthServer(("localhost", port), MockOAuthHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    return thread, server
