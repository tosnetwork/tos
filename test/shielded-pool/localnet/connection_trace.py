"""Independent connection evidence for a command: the kernel's record of its
`connect` calls, taken with `strace`, not the command's own account of itself.

The client's journal and the operator's journal both describe what their
authors believe happened. Whether the client ever opened a TCP connection to
the operator's port directly, bypassing the SOCKS peer, is a question neither
can answer. The syscall trace can: every `connect` the client and its children
made is in it, with the destination, and the adjudication below holds that
list against the one route the gate permits.
"""

from __future__ import annotations

import dataclasses
import re
import shutil
from pathlib import Path

CONNECT = re.compile(r"connect\(\d+, \{sa_family=(?P<family>AF_INET6?|AF_UNIX)(?P<rest>[^}]*)\}")
PORT = re.compile(r"sin6?_port=htons\((\d+)\)")
ADDRESS = re.compile(r'inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6, "([^"]+)"')
UNIX_PATH = re.compile(r'sun_path="([^"]*)"')


@dataclasses.dataclass(frozen=True)
class Connect:
    family: str
    address: str
    port: int | None


def strace_argv(argv: list[str], trace_file: Path) -> list[str]:
    """`argv` wrapped so that every `connect` of it and its children is recorded."""
    strace = shutil.which("strace")
    if strace is None:
        raise RuntimeError("strace is not installed; connection evidence needs it")
    return [strace, "-f", "-qq", "-e", "trace=connect", "-s", "256", "-o", str(trace_file), *argv]


def parse_connects(text: str) -> list[Connect]:
    connects: list[Connect] = []
    for line in text.splitlines():
        match = CONNECT.search(line)
        if match is None:
            continue
        family, rest = match.group("family"), match.group("rest")
        if family == "AF_UNIX":
            path = UNIX_PATH.search(rest)
            connects.append(Connect(family, path.group(1) if path else "", None))
            continue
        port = PORT.search(rest)
        address = ADDRESS.search(rest)
        connects.append(
            Connect(
                family,
                (address.group(1) or address.group(2)) if address else "",
                int(port.group(1)) if port else None,
            )
        )
    return connects


@dataclasses.dataclass(frozen=True)
class ConnectionVerdict:
    passed: bool
    reason: str
    tcp_destinations: list[str]


def adjudicate_connections(
    connects: list[Connect],
    *,
    socks_port: int,
    operator_port: int,
    permitted_ports: frozenset[int],
) -> ConnectionVerdict:
    """Every network connection went to the SOCKS peer or a permitted local
    read port; none went to the operator's port, and none left loopback."""
    destinations = sorted({f"{c.address}:{c.port}" for c in connects if c.family != "AF_UNIX"})
    direct = [c for c in connects if c.family != "AF_UNIX" and c.port == operator_port]
    if direct:
        return ConnectionVerdict(False, "a direct connection to the operator's port", destinations)
    foreign = [
        c
        for c in connects
        if c.family != "AF_UNIX" and c.address not in ("127.0.0.1", "::1", "::ffff:127.0.0.1")
    ]
    if foreign:
        return ConnectionVerdict(False, f"a connection left loopback: {foreign[0]}", destinations)
    unexpected = [
        c
        for c in connects
        if c.family != "AF_UNIX" and c.port not in permitted_ports and c.port != socks_port
    ]
    if unexpected:
        return ConnectionVerdict(False, f"an unexpected destination: {unexpected[0]}", destinations)
    if not any(c.port == socks_port for c in connects):
        return ConnectionVerdict(False, "the command never reached the SOCKS peer", destinations)
    return ConnectionVerdict(True, "only the SOCKS peer and permitted local reads", destinations)
