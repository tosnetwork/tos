"""The E03 Rust-client recorder must forward and retain success and errors."""

import importlib.util
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import urllib.error
import urllib.request


def load_proxy():
    path = Path(__file__).with_name("e03_http_proxy.py")
    spec = importlib.util.spec_from_file_location("e03_proxy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Upstream(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        status = 500 if b'"fail"' in raw else 200
        body = b'{"ok":false,"error":"precise failure"}' if status == 500 else b'{"ok":true,"result":7}'
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def test_proxy_retains_exact_request_response_and_status(tmp_path, monkeypatch):
    proxy_module = load_proxy()
    transcript = tmp_path / "tosctl-http.jsonl"
    monkeypatch.setenv("E03_HTTP_TRANSCRIPT", str(transcript))
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    proxy = ThreadingHTTPServer(
        ("127.0.0.1", 0), proxy_module.make_handler(f"http://127.0.0.1:{upstream.server_port}")
    )
    for server in (upstream, proxy):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{proxy.server_port}/jsonRPC"
        good = b'{"method":"getWalletInformation"}'
        bad = b'{"method":"fail"}'
        assert urllib.request.urlopen(urllib.request.Request(url, data=good)).read() == b'{"ok":true,"result":7}'
        try:
            urllib.request.urlopen(urllib.request.Request(url, data=bad))
            raise AssertionError("HTTP 500 was not forwarded")
        except urllib.error.HTTPError as error:
            assert error.code == 500 and error.read() == b'{"ok":false,"error":"precise failure"}'
        rows = [json.loads(row) for row in transcript.read_text().splitlines()]
        assert [row["status"] for row in rows] == [200, 500]
        assert [row["request_body"] for row in rows] == [good.decode(), bad.decode()]
        assert [row["response_body"] for row in rows] == [
            '{"ok":true,"result":7}', '{"ok":false,"error":"precise failure"}'
        ]
    finally:
        proxy.shutdown()
        upstream.shutdown()
