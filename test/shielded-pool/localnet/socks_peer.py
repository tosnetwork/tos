"""A gated SOCKS5 stand-in for the Tor client on an isolated local network.

The transport tests' `SocksPeer` forwards whatever name the client asks for to
one fixed upstream, which is what they need. On a live network that is too
permissive to prove anything: this peer admits exactly one onion name on one
port, refuses every other target before an upstream exists, and keeps a
receipt per connection that names no credential. Credentials are compared in
memory only; a receipt says which isolation group a connection belonged to
(an opaque counter) and whether the client authenticated, never what it sent.

What this proves is a transport boundary: the client reached the operator
only through an authenticated SOCKS peer that admitted the operator's onion
name. It proves nothing about onion anonymity, which needs a real Tor circuit.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "test/bonded-relayer"))
sys.path.insert(0, str(ROOT / "tools/bonded-relayer"))
from test_tor_transport import SocksPeer  # noqa: E402

PATH_CLASSES = ("/v1/quote", "/v1/submit", "/v1/status", "/v1/health")


def path_class(path: str | None) -> str | None:
    """The request's endpoint without its query or any identifier it carries."""
    if path is None:
        return None
    for known in PATH_CLASSES:
        if path == known or path.startswith(known + "?") or path.startswith(known + "/"):
            return known
    return "other"


class GatedSocksPeer(SocksPeer):
    """`SocksPeer` that admits one name on one port and writes redacted receipts."""

    # The stand-in keeps one fixed port across runs; connections the previous
    # run left in TIME-WAIT must not keep the next run from binding it.
    allow_reuse_address = True

    def __init__(
        self,
        upstream: tuple[str, int],
        allowed_name: str,
        allowed_port: int,
        listen_port: int = 0,
    ) -> None:
        super().__init__(upstream, listen_port)
        self.allowed = (allowed_name, allowed_port)
        self.receipts: list[dict[str, Any]] = []
        self._groups: dict[tuple[bytes, bytes], int] = {}
        self._lock = threading.Lock()
        self.client_timeout = 120.0
        self.upstream_timeout = 120.0

    def accept_target(self, host: str, port: int) -> bool:
        return (host, port) == self.allowed

    def isolation_group(self, user: bytes | None, password: bytes | None) -> int | None:
        """An opaque per-credential-pair counter; the pair itself stays in memory."""
        if user is None or password is None:
            return None
        with self._lock:
            return self._groups.setdefault((user, password), len(self._groups) + 1)

    def observe(self, record: dict[str, Any]) -> None:
        target = record.get("target")
        receipt = {
            "connection": len(self.receipts) + 1,
            "authenticated": record.get("user") is not None and record.get("password") is not None,
            "isolation_group": self.isolation_group(record.get("user"), record.get("password")),
            "target_allowed": target == list(self.allowed) or target == self.allowed,
            "target_name_known": None if target is None else target[0] == self.allowed[0],
            "refused_target": bool(record.get("refused_target")),
            "endpoint": path_class(record.get("path")),
            "forwarded": bool(record.get("forwarded")),
            "dropped": bool(record.get("dropped")),
            "upstream_status": record.get("upstream_status"),
        }
        with self._lock:
            self.receipts.append(receipt)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(receipt) for receipt in self.receipts]


def serve(peer: GatedSocksPeer) -> threading.Thread:
    thread = threading.Thread(target=peer.serve_forever, kwargs={"poll_interval": 0.05})
    thread.daemon = True
    thread.start()
    return thread


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--upstream-port", type=int, required=True)
    parser.add_argument("--onion", required=True)
    parser.add_argument("--onion-port", type=int, default=80)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    peer = GatedSocksPeer(
        ("127.0.0.1", args.upstream_port), args.onion, args.onion_port, args.listen_port
    )
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    thread = serve(peer)
    print(json.dumps({"listening": peer.server_address, "allowed": list(peer.allowed)}), flush=True)
    stop.wait()
    peer.shutdown()
    thread.join(timeout=5)
    args.receipts.write_text(json.dumps(peer.snapshot(), indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
