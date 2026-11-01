#!/usr/bin/env python3
"""Real local BR1 fault controls; custody and fresh client proofs stay external."""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import json
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/bonded-relayer"))
from br1 import configuration  # noqa: E402
from native_adapter import NativeAdapter  # noqa: E402
from native_process import NativeRPC, PinnedProgram, Unavailable  # noqa: E402
from relay_core import Engine, Journal, Refused, Request, encode  # noqa: E402


def write_new(path, value):
    with path.open("x", encoding="utf-8") as stream:
        path.chmod(0o600)
        json.dump(value, stream, indent=2)
        stream.write("\n")


def post(port, path, value):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", encode(value), {"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise RuntimeError("response bound")
    return json.loads(raw)


def captured_sends(directory, message):
    count = 0
    for path in directory.glob("*.request.json"):
        value = json.loads(path.read_bytes())
        if value.get("method") == "sendBoc":
            if base64.b64decode(value["params"]["boc"], validate=True) == message:
                count += 1
    return count


def reconcile(args, config, request):
    """Only an explicit submit mode writes; every recovery query is read-only."""
    token = args.token.read_text().strip()
    identity = Request.parse(encode(request)).identity
    if args.mode == "submit":
        with sqlite3.connect(f"file:{config['journal']}?mode=ro", uri=True) as database:
            if database.execute("SELECT 1 FROM jobs WHERE id=?", (identity,)).fetchone():
                raise RuntimeError("request already exists: use reconcile, never submit again")
        # A marker precedes the only possible HTTP submit. A stopped runner is
        # resumed with --mode reconcile, never another submit invocation.
        write_new(args.out / "submit-started.json", {"request_id": identity})
        try:
            post(config["port"], "/v1/submit", {"request": request, "status_token": token})
        except (OSError, urllib.error.URLError):
            pass
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            status = post(
                config["port"], "/v1/status", {"request_id": identity, "status_token": token}
            )
        except (OSError, urllib.error.URLError):
            time.sleep(0.5)
            continue
        if status["status"] == "executed":
            break
        if status["status"] in ("rejected", "cancelled"):
            raise RuntimeError("expected execution, got terminal refusal")
        time.sleep(0.5)
    else:
        raise RuntimeError("original request has not reconciled")
    with sqlite3.connect(f"file:{config['journal']}?mode=ro", uri=True) as database:
        row = database.execute(
            "SELECT message,message_hash FROM jobs WHERE id=?", (identity,)
        ).fetchone()
    if row is None or row[1] != status["message_hash"]:
        raise RuntimeError("persisted original message binding")
    count = captured_sends(args.capture, bytes(row[0]))
    if count != 1:
        raise RuntimeError(f"exact original message sent {count} times, expected one")
    native_db = Path(config["state_dir"]) / "leases.db"
    with sqlite3.connect(f"file:{native_db}?mode=ro", uri=True) as database:
        credits = database.execute(
            "SELECT count(*) FROM fee_notes WHERE note_body=?", (request["fee_note_body"],)
        ).fetchone()[0]
    if credits != 1:
        raise RuntimeError("expected exactly one finalized native fee import")
    write_new(
        args.out / "VERDICT.json",
        {
            "result": "PASS-EXACT-ORIGINAL-EXECUTION-WITHOUT-RESEND",
            "request_id": identity,
            "message_hash": status["message_hash"],
            "original_message_sha256": hashlib.sha256(row[0]).hexdigest(),
            "captured_exact_sends": count,
            "finalized_fee_imports": credits,
            "finality": status["finality"],
        },
    )


def expiry(args, config, request):
    """One prepare; compare old/new recheck after SDK V3's 120-second TTL."""
    release = dataclasses.asdict(config["release"])
    program = PinnedProgram(
        Path(config["backend"]), config["backend_sha256"], Path(config["state_dir"]), timeout=30
    )
    try:
        rpc = NativeRPC(program)

        class StopBeforeRPC(NativeAdapter):
            def recheck(self, release, request, prepared):
                raise Unavailable("fault control stops after durable UNKNOWN, before RPC")

        journal = Journal(
            Path(config["journal"]),
            config["release"],
            require_quotes=True,
            max_pending=config["max_pending"],
            max_reserved=config["max_reserved"],
        )
        try:
            parsed = Request.parse(encode(request))
            row = journal.get(parsed.identity)
            adapter = StopBeforeRPC(journal, rpc)
            if args.mode == "expiry":
                if row is not None:
                    raise RuntimeError("request already exists: resume, never prepare again")
                engine = Engine(journal, adapter)
                write_new(args.out / "prepare-started.json", {"boundary": "before-RPC"})
                if engine.submit(parsed) != "unknown":
                    raise RuntimeError("expected durable UNKNOWN at before-RPC boundary")
                row = journal.get(parsed.identity)
            elif row is None or row["state"] != "unknown":
                raise RuntimeError("resume needs the original UNKNOWN job")
            prepared = NativeAdapter._prepared(Engine._prepared(row))
            historical = {
                "release": release,
                "request": request,
                "prepared": prepared,
                "slot": row["slot"],
                "issued_at": row["issued"],
                "funding": row["funding"],
            }
            prepared_file = args.out / "prepared.json"
            if args.mode == "expiry":
                write_new(prepared_file, prepared)
            elif json.loads(prepared_file.read_bytes()) != prepared:
                raise RuntimeError("original persisted bytes changed")
        finally:
            journal.close()
        rpc.call("validate_prepared", historical)
        deadline = prepared_file.stat().st_mtime + 122
        while time.time() < deadline:
            time.sleep(0.5)
        if time.time() >= request["valid_until"]:
            raise RuntimeError("candidate expired too: cannot isolate wallet TTL")
        rpc.call("validate_prepared", historical)
        payload = {"release": release, "request": request, "prepared": prepared}
        baseline = PinnedProgram(
            args.baseline, args.baseline_sha256, Path(config["state_dir"]), timeout=30
        )
        try:
            value = NativeRPC(baseline).call("recheck", payload)
            if len(value["permit"]) != 64:
                raise RuntimeError("baseline did not reach permit issuance")
        finally:
            baseline.close()
        try:
            rpc.call("recheck", payload)
        except Refused:
            pass
        else:
            raise RuntimeError("new provider issued expired-wallet permit")
        write_new(
            args.out / "VERDICT.json",
            {
                "result": "PASS-OLD-ACCEPTS-NEW-REFUSES-EXPIRED-WALLET",
                "historical_validation_after_expiry": True,
                "candidate_still_live": True,
                "broadcast_attempts": 0,
                "replacement_signatures": 0,
                "signed_message_sha256": hashlib.sha256(
                    base64.b64decode(prepared["message_b64"], validate=True)
                ).hexdigest(),
                "scope": "Retain this native lease and drain worker; never reset custody.",
            },
        )
    finally:
        program.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode", choices=("submit", "reconcile", "expiry", "expiry-resume"), required=True
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--token", type=Path)
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--baseline-sha256")
    args = parser.parse_args()
    if args.mode.startswith("expiry"):
        if not all((args.baseline, args.baseline_sha256)):
            parser.error("expiry requires a pinned baseline")
    elif not all((args.token, args.capture)):
        parser.error("submit/reconcile require private token file and capture directory")
    args.out.mkdir(mode=0o700, parents=False, exist_ok=True)
    if args.out.stat().st_mode & 0o077:
        parser.error("output directory must be private")
    config = configuration(args.config)
    request = json.loads(args.request.read_bytes())
    if config["release"].global_id != 3:
        parser.error("fault controls require isolated global id 3")
    if args.mode.startswith("expiry"):
        expiry(args, config, request)
    else:
        reconcile(args, config, request)
    print("BR1_NATIVE_FAULT_CONTROL_PASS", args.mode)


if __name__ == "__main__":
    main()
