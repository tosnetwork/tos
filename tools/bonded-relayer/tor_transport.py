"""Onion-only TCP through a separately supervised local Tor daemon.

This is a bounded SOCKS5 adapter, not an onion-routing implementation. No
resolver, environment proxy, redirect, retry, or direct fallback is used.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import re
import secrets
import socket

from relay_core import Refused, integer
from relay_http import remaining


@dataclasses.dataclass(frozen=True)
class OnionEndpoint:
    host: str
    port: int

    @classmethod
    def parse(cls, origin: str) -> OnionEndpoint:
        if type(origin) is not str:
            raise Refused("canonical HTTP v3 onion origin required")
        match = re.fullmatch(r"http://([a-z2-7]{56}\.onion)(?::([1-9][0-9]{0,4}))?", origin)
        if match is None:
            raise Refused("canonical HTTP v3 onion origin required")
        host, port = match.groups()
        decoded = base64.b32decode(host[:-6].upper())
        checksum = hashlib.sha3_256(b".onion checksum" + decoded[:32] + b"\x03").digest()[:2]
        if decoded[34:] != b"\x03" or decoded[32:34] != checksum:
            raise Refused("invalid v3 onion checksum or version")
        number = integer(int(port) if port else 80, 1, 65535)
        if port == "80":
            raise Refused("omit the default onion port")
        return cls(host, number)

    @property
    def authority(self) -> str:
        return self.host if self.port == 80 else f"{self.host}:{self.port}"

    @property
    def origin(self) -> str:
        return "http://" + self.authority


def _read(sock: socket.socket, count: int, deadline: float) -> bytes:
    data = bytearray()
    while len(data) < count:
        remaining(sock, deadline)
        part = sock.recv(count - len(data))
        if not part:
            raise Refused("incomplete Tor SOCKS reply")
        data.extend(part)
    return bytes(data)


class TorProxy:
    """One isolation context per wallet relay session; never a bearer capability.

    The daemon must enable IsolateSOCKSAuth. These random credentials select a
    circuit isolation group; they do not authenticate the daemon. The local
    host and daemon are trusted. Use a new instance for an unrelated transfer.
    """

    def __init__(self, port: int = 9050):
        self.port = integer(port, 1024, 65535)
        self._user = secrets.token_hex(16).encode("ascii")
        self._password = secrets.token_hex(16).encode("ascii")

    def connect(self, endpoint: OnionEndpoint, deadline: float) -> socket.socket:
        # Revalidate even when a caller constructed the dataclass directly.
        endpoint = OnionEndpoint.parse(endpoint.origin)
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            remaining(connection, deadline)
            connection.connect(("127.0.0.1", self.port))
            remaining(connection, deadline)
            connection.sendall(b"\x05\x01\x02")
            if _read(connection, 2, deadline) != b"\x05\x02":
                raise Refused("Tor SOCKS isolation authentication required")
            credentials = b"\x01" + bytes([len(self._user)]) + self._user
            credentials += bytes([len(self._password)]) + self._password
            remaining(connection, deadline)
            connection.sendall(credentials)
            if _read(connection, 2, deadline) != b"\x01\x00":
                raise Refused("Tor SOCKS authentication refused")
            host = endpoint.host.encode("ascii")
            remaining(connection, deadline)
            connection.sendall(
                b"\x05\x01\x00\x03" + bytes([len(host)]) + host + endpoint.port.to_bytes(2, "big")
            )
            reply = _read(connection, 4, deadline)
            if reply[:3] != b"\x05\x00\x00":
                raise Refused("Tor onion connection unavailable")
            if reply[3] == 1:
                size = 4
            elif reply[3] == 4:
                size = 16
            elif reply[3] == 3:
                size = _read(connection, 1, deadline)[0]
                if size == 0:
                    raise Refused("invalid Tor SOCKS bound address")
            else:
                raise Refused("invalid Tor SOCKS address type")
            _read(connection, size + 2, deadline)
            return connection
        except BaseException:
            connection.close()
            raise
