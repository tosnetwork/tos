#!/usr/bin/env python3
"""One bounded, read-only QueryService projection witness over its private UDS.

The service-token value is never included in output. This probe makes no grant,
query, AURA, or M import request; it is suitable for a low-rate soak sampler.
"""

import argparse
import http.client
import json
import os
import signal
import socket
import stat
import sys


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=2)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(2)
        self.sock.connect(self.path)


def private_token(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_size > 4096
        ):
            raise ValueError("private token file rejected")
        raw = os.read(fd, 4097)
        if len(raw) != info.st_size:
            raise ValueError("private token file changed")
        value = raw.decode("utf-8").strip()
        if len(value) < 32 or not all(33 <= ord(char) <= 126 for char in value):
            raise ValueError("private token format rejected")
        return value
    finally:
        os.close(fd)


def u64_or_null(value):
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.isdecimal()
        or (len(value) > 1 and value[0] == "0")
        or int(value) > 2**64 - 1
    ):
        raise ValueError("invalid projection counter")
    return value


def sample(sock_path, token_path):
    token = private_token(token_path)
    conn = UnixHTTPConnection(sock_path)
    try:
        conn.request(
            "GET",
            "/v1/control/projection-health",
            headers={"Authorization": "Bearer " + token, "Accept": "application/json", "Connection": "close"},
        )
        reply = conn.getresponse()
        raw = reply.read(4097)
        content_type = (reply.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
        if len(raw) > 4096 or reply.status not in (200, 503) or content_type != "application/json":
            raise ValueError("projection response rejected")
        value = json.loads(raw)
        if type(value) is not dict or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
            raise ValueError("projection schema rejected")
        required = {
            "projection_status", "manager_conflicted", "caught_up_at_last_import",
            "query_watermark", "cursor_global_m_seq", "source_global_m_seq",
            "lag_global_m_seq", "source_identity_match",
        }
        if not required.issubset(value):
            raise ValueError("projection fields missing")
        status = value.get("projection_status")
        if status not in {
            "caught_up", "lagging", "conflict", "source_unavailable",
            "uninitialized", "identity_or_watermark_mismatch", "transition",
        }:
            raise ValueError("projection status rejected")
        conflicted = value.get("manager_conflicted")
        caught_up = value.get("caught_up_at_last_import")
        identity = value.get("source_identity_match")
        if type(conflicted) is not bool or type(caught_up) is not bool or not (
            type(identity) is bool or identity is None
        ):
            raise ValueError("projection flags rejected")
        cursor = u64_or_null(value.get("cursor_global_m_seq"))
        source = u64_or_null(value.get("source_global_m_seq"))
        lag = u64_or_null(value.get("lag_global_m_seq"))
        query_watermark = u64_or_null(value.get("query_watermark"))
        if query_watermark is None:
            raise ValueError("query watermark missing")
        if cursor is not None and source is not None and lag is not None:
            if int(source) < int(cursor) or int(source) - int(cursor) != int(lag):
                raise ValueError("projection lag inconsistent")
        if status == "caught_up" and not (
            reply.status == 200 and not conflicted and caught_up and identity is True
            and cursor is not None and source == cursor and lag == "0"
        ):
            raise ValueError("false caught-up projection")
        if status == "conflict" and not (reply.status == 503 and conflicted):
            raise ValueError("false conflict projection")
        if status == "lagging" and not (
            reply.status == 200 and not conflicted and identity is True
            and lag is not None and (not caught_up or lag != "0")
        ):
            raise ValueError("false lagging projection")
        if status == "source_unavailable" and not (reply.status == 503 and source is None):
            raise ValueError("false unavailable projection")
        if status == "transition":
            # Q changed during the producer's before/after snapshot. The M
            # head was available, but this mixed generation is unavailable.
            if reply.status != 503 or conflicted or source is None:
                raise ValueError("false transition projection")
            if cursor is None:
                if identity is not None or lag is not None:
                    raise ValueError("false transition projection")
            elif type(identity) is not bool or lag != (
                str(int(source) - int(cursor)) if int(source) >= int(cursor) else None
            ):
                raise ValueError("false transition projection")
        if status == "identity_or_watermark_mismatch" and not (
            reply.status == 503 and identity is False or reply.status == 503 and lag is None
        ):
            raise ValueError("false identity projection")
        return {
            "probe_ok": True,
            "projection_caught_up": status == "caught_up",
            "http_status": reply.status,
            "projection_status": status,
            "manager_conflicted": conflicted,
            "caught_up_at_last_import": caught_up,
            "source_identity_match": identity,
            "cursor_global_m_seq": cursor,
            "source_global_m_seq": source,
            "lag_global_m_seq": lag,
            "query_watermark": query_watermark,
        }
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--token-file", required=True)
    args = parser.parse_args()

    def expired(_signum, _frame):
        raise TimeoutError("projection probe deadline")

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 3)
    try:
        result = sample(args.socket, args.token_file)
        code = 0
    except (OSError, ValueError, TimeoutError, UnicodeError, json.JSONDecodeError) as error:
        result = {"probe_ok": False, "error_kind": type(error).__name__}
        code = 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())
