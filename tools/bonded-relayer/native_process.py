"""Bounded Linux stdio transport for an operator-pinned BR1 native backend.

This is not a proof verifier. The backend is part of the trusted computing base;
its implementation and release still require review. Network responses must never
be connected directly to this interface. There is no shell or executable search.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import selectors
import signal
import stat
import subprocess
import threading
import time
from pathlib import Path

from relay_core import Refused, digest, encode, integer, unique_object

OPERATIONS = frozenset(
    {
        "capabilities",
        "pool_head",
        "preflight",
        "prepare",
        "validate_prepared",
        "recheck",
        "broadcast",
        "evidence",
        "descriptor",
        "sign_quote",
        "verify_quote",
    }
)
MAX_INPUT = 2 * 1024 * 1024
MAX_OUTPUT = 2 * 1024 * 1024
MAX_STDERR = 16 * 1024
MAX_EXECUTABLE = 128 * 1024 * 1024


class Unavailable(RuntimeError):
    """No verified result was obtained; never interpret this as chain rejection."""


def object_from_bytes(wire: bytes, limit: int = MAX_OUTPUT) -> dict:
    if type(wire) is not bytes or not 0 < len(wire) <= limit:
        raise Refused("JSON outside byte bound")
    try:
        value = json.loads(
            wire,
            object_pairs_hook=unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(Refused("nonfinite JSON")),
        )
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Refused("invalid JSON object") from error
    if type(value) is not dict:
        raise Refused("JSON object required")
    return value


class PinnedProgram:
    """Execute an immutable snapshot, not a path checked before a later exec.

    A sealed memfd prevents pathname replacement and in-place executable changes
    after hashing. System libraries remain part of the reviewed host environment.
    Only the operator supplies the program, digest and private working directory.
    """

    def __init__(self, executable: Path, sha256: str, state_dir: Path, *, timeout: int = 15):
        digest(sha256)
        self.timeout = integer(timeout, 1, 60)
        path = Path(executable)
        directory = Path(state_dir)
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise Refused("backend executable must be canonical and absolute")
        if not directory.is_absolute() or directory.resolve(strict=True) != directory:
            raise Refused("backend directory must be canonical and absolute")
        metadata = directory.stat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
        ):
            raise Refused("backend directory must be owned and private")
        self.directory = directory
        self.sha256 = sha256
        self._slots = threading.BoundedSemaphore(2)
        self._lifecycle = threading.Lock()
        self.fd = -1
        source = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        copied = -1
        try:
            metadata = os.fstat(source)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid not in (0, os.geteuid())
                or metadata.st_mode & 0o022
                or not metadata.st_mode & 0o111
                or not 4 <= metadata.st_size <= MAX_EXECUTABLE
            ):
                raise Refused("unsafe native executable")
            copied = os.memfd_create("br1-native", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            hasher = hashlib.sha256()
            size = 0
            while chunk := os.read(source, 65536):
                if size == 0 and not chunk.startswith(b"\x7fELF"):
                    raise Refused("native backend must be an ELF executable")
                size += len(chunk)
                if size > MAX_EXECUTABLE:
                    raise Refused("native executable exceeds byte bound")
                hasher.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(copied, view)
                    if written <= 0:
                        raise Unavailable("native snapshot write failed")
                    view = view[written:]
            if size != metadata.st_size or hasher.hexdigest() != sha256:
                raise Refused("native executable digest mismatch")
            os.fchmod(copied, 0o500)
            fcntl.fcntl(
                copied,
                fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL,
            )
            self.fd, copied = copied, -1
        finally:
            os.close(source)
            if copied >= 0:
                os.close(copied)

    def close(self):
        with self._lifecycle:
            if self.fd >= 0:
                os.close(self.fd)
                self.fd = -1

    def exchange(self, operation: str, wire: bytes) -> bytes:
        if operation not in OPERATIONS:
            raise Refused("unknown native operation")
        if type(wire) is not bytes or not 0 < len(wire) <= MAX_INPUT:
            raise Refused("native input outside byte bound")
        if not self._slots.acquire(blocking=False):
            raise Unavailable("native concurrency limit")
        owned = -1
        try:
            with self._lifecycle:
                if self.fd < 0:
                    raise Unavailable("native program is closed")
                owned = os.dup(self.fd)
            return self._exchange(operation, wire, owned)
        finally:
            if owned >= 0:
                os.close(owned)
            self._slots.release()

    def _exchange(self, operation: str, wire: bytes, executable: int) -> bytes:
        end = time.monotonic() + self.timeout
        process = subprocess.Popen(
            [f"/proc/self/fd/{executable}", "--stdio", operation],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.directory,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": str(self.directory)},
            pass_fds=(executable,),
            start_new_session=True,
            close_fds=True,
        )
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        sent = 0
        try:
            with selectors.DefaultSelector() as selector:
                for stream, name, event in (
                    (process.stdin, "stdin", selectors.EVENT_WRITE),
                    (process.stdout, "stdout", selectors.EVENT_READ),
                    (process.stderr, "stderr", selectors.EVENT_READ),
                ):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, event, name)
                while selector.get_map():
                    remaining = end - time.monotonic()
                    if remaining <= 0:
                        raise Unavailable("native operation deadline exceeded")
                    for key, _ in selector.select(remaining):
                        stream, name = key.fileobj, key.data
                        if name == "stdin":
                            try:
                                sent += os.write(stream.fileno(), wire[sent : sent + 65536])
                            except BrokenPipeError as error:
                                raise Unavailable("native input was not consumed") from error
                            if sent == len(wire):
                                selector.unregister(stream)
                                stream.close()
                        else:
                            chunk = os.read(stream.fileno(), 65536)
                            if not chunk:
                                selector.unregister(stream)
                                continue
                            maximum = MAX_OUTPUT if name == "stdout" else MAX_STDERR
                            if len(buffers[name]) + len(chunk) > maximum:
                                raise Unavailable("native output outside byte bound")
                            buffers[name].extend(chunk)
                # Observe exit without reaping: the process group id cannot be
                # recycled before cleanup of any remaining descendants.
                while (
                    os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None
                ):
                    if time.monotonic() >= end:
                        raise Unavailable("native operation deadline exceeded")
                    time.sleep(0.01)
            os.killpg(process.pid, signal.SIGKILL)
            result = process.wait(timeout=2)
            if result != 0:
                raise Unavailable("native operation failed")
            return bytes(buffers["stdout"])
        except (OSError, subprocess.SubprocessError) as error:
            raise Unavailable("native transport failed") from error
        finally:
            # Until wait() above succeeds the leader still owns its PID. On an
            # error, kill the group before reaping, including blocked children.
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


class NativeRPC:
    """A private process response bound to the complete invocation, not HTTP JSON."""

    def __init__(self, program: PinnedProgram):
        self.program = program

    def call(self, operation: str, payload: dict) -> dict | None:
        wire = encode(
            {
                "schema": "tos.br1.native.request.v1",
                "nonce": secrets.token_hex(16),
                "operation": operation,
                "payload": payload,
            }
        )
        reply = object_from_bytes(self.program.exchange(operation, wire))
        if set(reply) != {"schema", "request_sha256", "status", "result"}:
            raise Unavailable("unexpected native response fields")
        if (
            reply["schema"] != "tos.br1.native.reply.v1"
            or reply["request_sha256"] != hashlib.sha256(wire).hexdigest()
        ):
            raise Unavailable("native response binding mismatch")
        if reply["status"] == "refused":
            raise Refused("native verification refused")
        if reply["status"] != "ok" or (
            reply["result"] is not None and type(reply["result"]) is not dict
        ):
            raise Unavailable("invalid native response")
        return reply["result"]
