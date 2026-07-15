"""Loopback/isolated-link HTTP adapter for the versioned host model proxy."""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from .model_proxy import HostModelProxy, ProxyRejection


class _ProxyHandler(BaseHTTPRequestHandler):
    server_version = "crumple-model-proxy.v1"
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        proxy: HostModelProxy = self.server.proxy  # type: ignore[attr-defined]
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if length < 0 or length > proxy.limits.max_request_bytes:
                raise ProxyRejection("REQUEST_TOO_LARGE")
            authorization = self.headers.get("Authorization", "")
            if not authorization.startswith("Bearer "):
                raise ProxyRejection("CAPABILITY_INVALID")
            token = authorization.removeprefix("Bearer ")
            body = self.rfile.read(length)
            if len(body) != length:
                raise ProxyRejection("REQUEST_HTTP_PREMATURE_EOF")
            response = proxy.handle(self.path, token, body)
            self.send_response(response.status)
            self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Length", str(len(response.body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(response.body)
        except ProxyRejection as rejection:
            body = json.dumps({"error": {"code": rejection.code}}, separators=(",", ":")).encode()
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, _format: str, *_args) -> None:
        return


class ProxyHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], proxy: HostModelProxy):
        super().__init__(address, _ProxyHandler)
        self.proxy = proxy


@contextmanager
def running_proxy(proxy: HostModelProxy, host: str = "127.0.0.1") -> Iterator[ProxyHTTPServer]:
    server = ProxyHTTPServer((host, 0), proxy)
    thread = threading.Thread(target=server.serve_forever, name="crumple-model-proxy", daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
