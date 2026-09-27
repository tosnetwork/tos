#!/usr/bin/env python3
"""Local E03-only forwarding proxy that retains tosctl's raw HTTP exchanges.

The Python transcript cannot observe Rust ClientJsonRpc. This loopback proxy
records that missing boundary without changing either the node or tosctl.
"""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.error
import urllib.request

from e03_http_trace import record


def make_handler(upstream):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.forward(None)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            self.forward(self.rfile.read(length))

        def forward(self, body):
            url = upstream.rstrip("/") + self.path
            request = urllib.request.Request(
                url, data=body, method=self.command,
                headers={"Content-Type": self.headers.get("Content-Type", "application/json")},
            )
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    status, raw = response.status, response.read()
            except urllib.error.HTTPError as error:
                status, raw = error.code, error.read()
            record(url, body, status, raw)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_):
            pass

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--upstream", required=True)
    args = parser.parse_args()
    ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(args.upstream)).serve_forever()


if __name__ == "__main__":
    main()
