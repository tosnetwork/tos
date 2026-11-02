#!/usr/bin/env python3
"""Lose a real native prepare reply, then verify ordinary restart recovery.

The crash mode submits once on an isolated global-id-3 network. Exit 86 means
the native reply was received but never returned to the Python engine.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

from control import configuration, reconcile, write_new
from native_adapter import NativeAdapter
from native_process import NativeRPC, PinnedProgram
from relay_core import Engine, Journal, Request, encode
from relay_service import Service


def inactive(unit):
    if not re.fullmatch(r"[a-zA-Z0-9_.@-]+\.service", unit):
        raise RuntimeError("literal user service name required")
    result = subprocess.run(
        ["systemctl", "--user", "show", unit, "-p", "ActiveState", "-p", "MainPID"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode not in (0, 4) or set(result.stdout.splitlines()) != {
        "ActiveState=inactive",
        "MainPID=0",
    }:
        raise RuntimeError("stop the isolated operator service before crash injection")


def crash(args, config, request):
    inactive(args.inactive_unit)
    with contextlib.ExitStack() as cleanup:
        program = PinnedProgram(
            Path(config["backend"]), config["backend_sha256"], Path(config["state_dir"])
        )
        cleanup.callback(program.close)
        journal = Journal(
            Path(config["journal"]),
            config["release"],
            require_quotes=True,
            max_pending=config["max_pending"],
            max_reserved=config["max_reserved"],
        )
        cleanup.callback(journal.close)
        identity = Request.parse(encode(request)).identity
        if journal.get(identity) is not None:
            raise RuntimeError("existing request: restart and reconcile; never submit again")

        class LostReply(NativeRPC):
            def call(self, operation, payload):
                value = super().call(operation, payload)
                if operation == "prepare":
                    inactive(args.inactive_unit)
                    row = journal.get(identity)
                    if row["state"] != "reserved" or row["message"] is not None:
                        raise RuntimeError("expected reserved job without prepared bytes")
                    write_new(
                        args.out / "prepare-reply-lost.json",
                        {
                            "request_id": identity,
                            "reply_sha256": hashlib.sha256(encode(value)).hexdigest(),
                            "exit": 86,
                            "python_state": "reserved",
                            "message": None,
                        },
                    )
                    os._exit(86)
                return value

        service = Service(
            Engine(journal, NativeAdapter(journal, LostReply(program))),
            fee=config["fee"],
            funding_cap=config["funding_cap"],
            enabled=True,
        )
        write_new(args.out / "submit-started.json", {"request_id": identity})
        service._submit({"request": request, "status_token": args.token.read_text().strip()})
        raise RuntimeError("lost-reply fault was not reached")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("crash", "verify"), required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--token", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inactive-unit")
    parser.add_argument("--capture", type=Path)
    args = parser.parse_args()
    config = configuration(args.config)
    if config["release"].global_id != 3:
        parser.error("isolated global-id-3 network required")
    if args.mode == "crash" and not args.inactive_unit:
        parser.error("crash requires --inactive-unit")
    if args.mode == "verify" and not args.capture:
        parser.error("verify requires --capture")
    os.umask(0o077)
    if args.mode == "crash":
        inactive(args.inactive_unit)
    args.out.mkdir(mode=0o700, exist_ok=args.mode == "verify")
    if args.out.stat().st_mode & 0o077:
        parser.error("private output directory required")
    request = json.loads(args.request.read_bytes())
    if args.mode == "crash":
        crash(args, config, request)
    else:
        fault = json.loads((args.out / "prepare-reply-lost.json").read_bytes())
        marker = json.loads((args.out / "submit-started.json").read_bytes())
        identity = Request.parse(encode(request)).identity
        if (
            fault.get("request_id") != identity
            or marker.get("request_id") != identity
            or fault.get("exit") != 86
            or fault.get("python_state") != "reserved"
            or fault.get("message", False) is not None
            or not isinstance(fault.get("reply_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", fault["reply_sha256"])
        ):
            raise RuntimeError("matching completed crash evidence required")
        # reconcile() does not submit unless mode is literally 'submit'.
        reconcile(args, config, request, prepared_sha256=fault["reply_sha256"])
        print("BR1_PREPARED_REPLY_RECOVERY_PASS")


if __name__ == "__main__":
    main()
