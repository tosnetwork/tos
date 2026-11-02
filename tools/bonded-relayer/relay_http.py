"""One-message, bounded HTTP/1.1 transport for the BR1 loopback boundary."""

from __future__ import annotations

import re
import socket
import time

from relay_core import Refused, encode

HEADER_LIMIT = 8192
RESPONSE_LIMIT = 64 * 1024
TOKEN = re.compile(rb"[A-Za-z0-9-]+\Z")


class HTTPRefused(Refused):
    pass


def remaining(sock: socket.socket, deadline: float):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise HTTPRefused("HTTP deadline exceeded")
    sock.settimeout(seconds)


def receive(
    sock: socket.socket, maximum: int, deadline: float, header_deadline: float | None = None
) -> tuple[str, dict, bytes]:
    """Read one request or response. With `header_deadline`, the request line and headers
    must be complete by it (trickled bytes do not extend it) and the body by `deadline`."""
    header_deadline = deadline if header_deadline is None else min(header_deadline, deadline)
    data = bytearray()
    while True:
        split = data.find(b"\r\n\r\n")
        if split >= 0:
            if split > HEADER_LIMIT:
                raise HTTPRefused("HTTP headers too large")
            break
        if len(data) >= HEADER_LIMIT + 4:
            raise HTTPRefused("HTTP headers too large")
        remaining(sock, header_deadline)
        chunk = sock.recv(min(4096, HEADER_LIMIT + 4 - len(data)))
        if not chunk:
            raise HTTPRefused("incomplete HTTP headers")
        data.extend(chunk)
    lines = bytes(data[:split]).split(b"\r\n")
    if len(lines) > 33 or len(lines[0]) > 256:
        raise HTTPRefused("HTTP header count or request line limit")
    try:
        start = lines[0].decode("ascii")
        headers = {}
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            if not separator or not TOKEN.fullmatch(name):
                raise HTTPRefused("malformed HTTP header")
            key = name.decode("ascii").lower()
            text = value.decode("ascii").strip(" \t")
            if key in headers or any(ord(c) < 32 or ord(c) == 127 for c in text):
                raise HTTPRefused("duplicate or invalid HTTP header")
            headers[key] = text
    except UnicodeError as error:
        raise HTTPRefused("non-ASCII HTTP headers") from error
    if any(
        key in headers for key in ("transfer-encoding", "content-encoding", "expect", "upgrade")
    ):
        raise HTTPRefused("unsupported HTTP framing")
    length = headers.get("content-length")
    if length is None and start.startswith("GET "):
        length = "0"
    if length is None or not re.fullmatch(r"0|[1-9][0-9]{0,7}", length):
        raise HTTPRefused("one canonical Content-Length is required")
    length = int(length)
    if length > maximum:
        raise HTTPRefused("HTTP body too large")
    if length and headers.get("content-type") != "application/json":
        raise HTTPRefused("application/json required")
    body = bytearray(data[split + 4 :])
    if len(body) > length:
        raise HTTPRefused("HTTP pipelining is not supported")
    while len(body) < length:
        remaining(sock, deadline)
        chunk = sock.recv(min(65536, length - len(body)))
        if not chunk:
            raise HTTPRefused("incomplete HTTP body")
        body.extend(chunk)
    return start, headers, bytes(body)


def respond(sock: socket.socket, status: int, result: dict, deadline: float):
    phrases = {
        200: "OK",
        202: "Accepted",
        400: "Bad Request",
        401: "Unauthorized",
        404: "Not Found",
        405: "Method Not Allowed",
        422: "Unprocessable Content",
        429: "Too Many Requests",
        503: "Service Unavailable",
    }
    body = encode(result)
    if len(body) > RESPONSE_LIMIT:
        status, body = 503, b'{"error":"response_unavailable"}'
    header = (
        f"HTTP/1.1 {status} {phrases[status]}\r\n"
        "Content-Type: application/json\r\nCache-Control: no-store\r\n"
        "Connection: close\r\nX-Content-Type-Options: nosniff\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("ascii")
    remaining(sock, deadline)
    sock.sendall(header + body)
