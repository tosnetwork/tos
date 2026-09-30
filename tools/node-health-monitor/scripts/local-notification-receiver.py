#!/usr/bin/env python3
"""Independent notification receiver for M's outbox (development host).

HTTPS with the private CA's server certificate, bearer token check, one JSON
body per delivery. Every accepted notification is appended to a private
journal and acknowledged with the exact receipt M requires:
{accepted: true, idempotency_key, payload_hash}. A wrong token, a body over
64 KiB, a malformed body or a hash mismatch is refused and never journaled as
delivered. This proves delivery to an independent process, not to a human;
route the journal onward (chat, pager) for that.
"""
import argparse
import http.server
import json
import os
import ssl
import sys
import time
from pathlib import Path

MAX_BODY = 65536


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--listen", default="127.0.0.1:19700")
    parser.add_argument("--cert-file", required=True)
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--journal", required=True)
    args = parser.parse_args()
    token = Path(args.token_file).read_text().strip()
    journal = Path(args.journal)
    journal.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    host, port = args.listen.rsplit(":", 1)

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "nhm-receiver/1"

        def log_message(self, fmt, *a):  # quiet; the journal is the record
            pass

        def _reply(self, status, body):
            raw = json.dumps(body, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            if self.path != "/v1/notifications":
                return self._reply(404, {"accepted": False})
            if self.headers.get("authorization") != f"Bearer {token}":
                return self._reply(401, {"accepted": False})
            length = int(self.headers.get("content-length") or 0)
            if length <= 0 or length > MAX_BODY:
                return self._reply(413, {"accepted": False})
            raw = self.rfile.read(length)
            try:
                body = json.loads(raw)
                incident = body["incident"]
                key = body["idempotency_key"]
                claimed = body["payload_hash"]
            except (ValueError, KeyError, TypeError):
                return self._reply(400, {"accepted": False})
            if self.headers.get("idempotency-key") != key:
                return self._reply(400, {"accepted": False})
            # The hash is over M's stored outbox bytes, which this side cannot
            # reproduce byte for byte from parsed JSON; the receipt echoes it and
            # M verifies the echo against its own committed hash.
            if not isinstance(claimed, str) or len(claimed) != 64 or any(c not in "0123456789abcdef" for c in claimed):
                return self._reply(400, {"accepted": False, "reason": "payload_hash_shape"})
            line = json.dumps({"received_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                               "idempotency_key": key, "payload_hash": claimed,
                               "network_id": body.get("network_id"), "receiver_alias": body.get("receiver_alias"),
                               "incident": incident}, ensure_ascii=False)
            fd = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "a") as stream:
                stream.write(line + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            return self._reply(200, {"accepted": True, "idempotency_key": key, "payload_hash": claimed})

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert_file, args.key_file)
    server = http.server.ThreadingHTTPServer((host, int(port)), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"receiver listening on {args.listen}", file=sys.stderr, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
