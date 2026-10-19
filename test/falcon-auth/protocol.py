"""Explicit wire helpers for the native E2E suite, NOT a production wallet SDK."""

# Repository-local imports require the explicit path bootstrap below.
# ruff: noqa: E402

import functools
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
from cells import Cell, from_boc

CONTEXT = b"TOS-AUTH-FALCON512-PADDED-v1"
SUBMIT = 0x46414C31
AUTH = 0x41555448


def emulator_library(build):
    """Shared library suffix differs per platform; fail loudly rather than late."""
    for name in ("libemulator.so", "libemulator.dylib", "emulator.dll"):
        candidate = Path(build) / "emulator" / name
        if candidate.exists():
            return candidate
    raise SystemExit(
        f"no emulator library in {Path(build) / 'emulator'}; build the emulator target first"
    )


def chain(data):
    parts = [data[i : i + 127] for i in range(0, len(data), 127)] or [b""]
    tail = None
    for part in reversed(parts):
        node = Cell().raw(part)
        if tail is not None:
            node.ref(tail)
        tail = node
    return tail


def clone(cell):
    # Never mutate a Cell after its cached commitment was computed.
    return from_boc(cell.boc())


def commitment(request):
    return Cell().uint(0x544F532D41555448, 64).ref(request).hash


def module_data(public_key, network, profile=1):
    if len(public_key) != 897:
        raise ValueError("Falcon-512 padded public key must contain exactly 897 bytes")
    return Cell().sint(network, 32).uint(profile, 16).ref(chain(public_key))


def submission(envelope, signature, query_id=0):
    if len(signature) != 666:
        raise ValueError("Falcon-512 padded signature must contain exactly 666 bytes")
    return Cell().uint(SUBMIT, 32).uint(query_id, 64).ref(envelope).ref(chain(signature))


def parse_message(message):
    s = message.slice()
    assert s.uint(1) == 0, "expected a real internal message"
    s.uint(1)
    bounce = s.uint(1)
    bounced = s.uint(1)
    sender, destination, value = s.addr(), s.addr(), s.coins()
    assert s.maybe() is None, "no extra currencies in this profile"
    s.coins()
    forward_fee = s.coins()
    created_lt = s.uint(64)
    created_at = s.uint(32)
    assert s.uint(1) == 0, "unexpected StateInit in relay/transfer"
    body = s.ref() if s.uint(1) else Cell(s.bits, s.refs)
    return {
        "sender": sender,
        "destination": destination,
        "value": value,
        "bounce": bounce,
        "bounced": bounced,
        "forward_fee": forward_fee,
        "created_lt": created_lt,
        "created_at": created_at,
        "body": body,
    }


def signing_message(root, digest, tag=CONTEXT):
    return (
        tag
        + b"\x00"
        + root[0].to_bytes(4, "big", signed=True)
        + root[1].to_bytes(32, "big")
        + digest
    )


class Signer:
    """PUBLIC TEST DATA. Test-only deterministic entropy, never imported by wallet code."""

    def __init__(self, library):
        sys.path.insert(0, str(ROOT / "tools/falcon"))
        from backend import Backend

        self.backend = Backend(library)
        self.handles = {}

    def handle(self, key):
        if key not in self.handles:
            import hashlib
            from unittest.mock import patch

            entropy = hashlib.sha384(b"PUBLIC TEST DATA FALCON KEY " + str(key).encode()).digest()
            with patch("backend.os.urandom", return_value=entropy):
                self.handles[key] = self.backend.generate_key()
        return self.handles[key]

    @functools.lru_cache(maxsize=2048)
    def sign(self, message, context=CONTEXT, key=0):
        import hashlib
        from unittest.mock import patch

        h = self.handle(key)
        if context != CONTEXT and len(message) == 97:
            message = context + message[28:]
        entropy = hashlib.sha384(b"PUBLIC TEST DATA FALCON SIGN " + message + bytes([key])).digest()
        with patch("backend.os.urandom", return_value=entropy):
            return h.public_key, self.backend.sign(h, message)

    def public_key(self, key=0):
        return self.handle(key).public_key
