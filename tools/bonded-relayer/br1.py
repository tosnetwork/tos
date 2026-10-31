#!/usr/bin/env python3
"""Localnet-only BR1 entry point. No native provider or activation approval is implied."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import json
import os
import signal
import stat
import sys
import threading
from pathlib import Path

from native_adapter import NativeAdapter
from native_process import NativeRPC, PinnedProgram, Unavailable, object_from_bytes
from relay_core import Engine, Journal, Refused, Release, integer
from relay_service import RelayServer, Service

CONFIG_LIMIT = 16384


def configuration(path: Path) -> dict:
    """Read through a no-follow descriptor; never load private keys from arguments."""
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise Refused("configuration must be canonical and absolute")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_nlink != 1
            or st.st_uid != os.geteuid()
            or st.st_mode & 0o077
            or not 0 < st.st_size <= CONFIG_LIMIT
        ):
            raise Refused("configuration must be an owned private regular file")
        chunks = bytearray()
        while chunk := os.read(fd, CONFIG_LIMIT + 1 - len(chunks)):
            chunks.extend(chunk)
            if len(chunks) > CONFIG_LIMIT:
                raise Refused("configuration exceeds byte bound")
        data = object_from_bytes(bytes(chunks), CONFIG_LIMIT)
    finally:
        os.close(fd)
    if (
        set(data)
        != {
            "schema",
            "mode",
            "release",
            "backend",
            "backend_sha256",
            "state_dir",
            "journal",
            "port",
            "fee",
            "funding_cap",
            "max_reserved",
            "max_pending",
        }
        or data["schema"] != "tos.br1.localnet.config.v1"
        or data["mode"] != "localnet"
    ):
        raise Refused("only the reviewed localnet configuration shape is supported")
    if type(data["release"]) is not dict or set(data["release"]) != {
        f.name for f in dataclasses.fields(Release)
    }:
        raise Refused("complete operator-pinned release required")
    data["release"] = Release(**data["release"])
    for key in ("backend", "state_dir", "journal"):
        if type(data[key]) is not str or not Path(data[key]).is_absolute():
            raise Refused("absolute operator paths required")
    state = Path(data["state_dir"])
    journal = Path(data["journal"])
    if state.resolve(strict=True) != state or journal.parent != state:
        raise Refused("journal must be directly within the canonical private state directory")
    st = state.stat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise Refused("state directory must be owned and private")
    integer(data["port"], 1024, 65535)
    integer(data["fee"], 1, (1 << 63) - 1)
    integer(data["max_reserved"], 1, (1 << 63) - 1)
    integer(data["funding_cap"], 1, data["max_reserved"])
    integer(data["max_pending"], 1, 64)
    return data


def run(config: dict, *, check_only: bool = False) -> int:
    """Never substitutes a fixture, manual broadcaster, or unpinned executable."""
    with contextlib.ExitStack() as stack:
        program = PinnedProgram(
            Path(config["backend"]), config["backend_sha256"], Path(config["state_dir"])
        )
        stack.callback(program.close)
        journal = Journal(
            Path(config["journal"]),
            config["release"],
            require_quotes=True,
            max_pending=config["max_pending"],
            max_reserved=config["max_reserved"],
        )
        stack.callback(journal.close)
        adapter = NativeAdapter(journal, NativeRPC(program))
        service = Service(
            Engine(journal, adapter),
            fee=config["fee"],
            funding_cap=config["funding_cap"],
            enabled=True,
        )
        if check_only:
            print(
                json.dumps(
                    {
                        "schema": "tos.br1.localnet.check.v1",
                        "capabilities_available": True,
                        "production_approved": False,
                    }
                )
            )
            return 0
        server = RelayServer(service, ("127.0.0.1", config["port"]))
        stack.callback(server.server_close)
        server.timeout = 0.2
        stop = threading.Event()
        previous = {}
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, lambda *_: stop.set())

        def restore_signals():
            for sig, handler in previous.items():
                signal.signal(sig, handler)

        stack.callback(restore_signals)

        def recovery():
            while not stop.wait(1):
                service.tick(stop=stop)

        worker = threading.Thread(target=recovery, name="br1-recovery", daemon=False)
        worker.start()
        try:
            while not stop.is_set():
                server.handle_request()
        finally:
            stop.set()
            # Every native operation has a deadline. Join before closing the
            # journal or sealed executable; never race close against a signer.
            worker.join()
            server.server_close()
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--check", action="store_true", help="probe the pinned native provider; do not listen"
    )
    args = parser.parse_args(argv)
    try:
        return run(configuration(args.config), check_only=args.check)
    except (OSError, Refused, Unavailable, ValueError, TypeError):
        # Operator paths, payloads and subprocess stderr are intentionally not reflected.
        print(
            "BR1_UNAVAILABLE: private configuration or required native provider unavailable",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
