"""Loopback HTTP contract tests; a local fake server is NOT model evidence."""
import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agentic_aiops.shadow_holdout import request_local_completion


@contextmanager
def serve(body: bytes, *, status: int = 200):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers["Content-Length"])
            received.append((
                self.path, self.headers.get("Content-Type"),
                self.rfile.read(length),
            ))
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            if status == 302:
                self.send_header("Location", "https://example.com/exfil")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1", received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_loopback_http_posts_one_text_payload():
    response = b'{"model":"example","choices":[]}'
    with serve(response) as (url, received):
        actual = request_local_completion(
            url, {"model": "example", "messages": [
                {"role": "user", "content": "你好"}
            ]}, timeout=1,
        )
    assert actual["model"] == "example"
    assert len(received) == 1
    path, content_type, sent = received[0]
    assert path == "/v1/chat/completions"
    assert content_type == "application/json"
    assert json.loads(sent)["messages"][0]["content"] == "你好"


@pytest.mark.parametrize("status,body", [
    (500, b"{}"),
    (302, b"{}"),
    (200, b"garbage"),
    (200, b""),
    (200, b"x" * (1024 * 1024 + 1)),
])
def test_loopback_http_error_or_oversized_body_fails(status, body):
    with serve(body, status=status) as (url, received):
        with pytest.raises(ValueError):
            request_local_completion(url, {"model": "example"}, timeout=2)
    assert len(received) == 1


@pytest.mark.parametrize("url", [
    "http://localhost:123/v1",
    "http://127.0.0.2:123/v1",
    "https://127.0.0.1:123/v1",
    "http://127.0.0.1:123/v1/",
    "http://127.0.0.1:0/v1",
])
def test_only_literal_loopback_endpoint_allowed(url):
    with pytest.raises(ValueError):
        request_local_completion(url, {}, timeout=1)


@contextmanager
def serve_framed(body, headers):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            self.send_response(200)
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}/v1'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize('kind', ['short-length', 'unfinished-chunk'])
def test_incomplete_http_framing_is_rejected(kind):
    body = b'{"model":"example","choices":[]}'
    if kind == 'short-length':
        headers = [('Content-Length', str(len(body) + 7))]
    else:
        headers = [('Transfer-Encoding', 'chunked')]
        body = f'{len(body):x}\r\n'.encode() + body + b'\r\n'
    with serve_framed(body, headers) as url:
        with pytest.raises(ValueError, match='incomplete|malformed'):
            request_local_completion(url, {}, timeout=2)


@pytest.mark.parametrize('kind', ['length', 'chunked'])
def test_complete_http_framing_accepted(kind):
    body = b'{"model":"example","choices":[]}'
    if kind == 'length':
        headers = [('Content-Length', str(len(body)))]
    else:
        headers = [('Transfer-Encoding', 'chunked')]
        body = f'{len(body):x}\r\n'.encode() + body + b'\r\n0\r\n\r\n'
    with serve_framed(body, headers) as url:
        assert request_local_completion(url, {}, timeout=2)['model'] == 'example'
