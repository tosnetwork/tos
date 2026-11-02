"""Recover existing real local signed attempts without preparing or broadcasting.

The fixture custody stays private on its authorized host. Only sanitized hashes
are emitted; the runner never exports a message, acceptance, seed or SQL snapshot.
"""

import argparse
import base64
import hashlib
import json
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools/bonded-relayer"))
from native_process import NativeRPC, PinnedProgram  # noqa: E402
from relay_core import Refused  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--custody", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--min-cases", type=int, default=1)
    parser.add_argument("--inactive-unit", required=True)
    args = parser.parse_args()
    if args.out.exists() or not 1 <= args.min_cases <= 32:
        parser.error("new output and1..32 minimum cases required")

    def quiesced():
        result = subprocess.run(
            [
                "systemctl",
                "--user",
                "show",
                args.inactive_unit,
                "--property=ActiveState",
                "--property=MainPID",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        state = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if result.returncode or state != {"MainPID": "0", "ActiveState": "inactive"}:
            raise RuntimeError("quiesce the named local relayer before historical guard checks")

    quiesced()
    config = json.loads((args.custody / "provider.json").read_bytes())
    if config["release"]["global_id"] != 3:
        parser.error("disposable global-id-3 custody only")
    db = args.custody / "leases.db"
    if not db.is_file() or db.stat().st_size > 16 * 1024 * 1024:
        parser.error("existing bounded native store required")
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    connection = sqlite3.connect("file:" + str(args.custody / "journal.db") + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    rows = []
    try:
        with closing(
            PinnedProgram(args.provider, args.sha256, args.custody, timeout=30)
        ) as program:
            rpc = NativeRPC(program)
            for row in connection.execute(
                "SELECT * FROM jobs WHERE state='executed' ORDER BY slot LIMIT 32"
            ):
                payload = dict(
                    release=config["release"],
                    request=json.loads(row["request"]),
                    slot=row["slot"],
                    issued_at=row["issued"],
                    funding=row["funding"],
                )
                recovered = rpc.call("recover_prepared", payload)
                assert base64.b64decode(recovered["message_b64"]) == bytes(row["message"]), (
                    "recovered message changed"
                )
                assert base64.b64decode(recovered["acceptance_b64"]) == bytes(row["acceptance"]), (
                    "recovered acceptance changed"
                )
                assert recovered["message_hash"] == row["message_hash"], (
                    "recovered TVM hash changed"
                )
                for field in ("slot", "issued_at", "funding"):
                    try:
                        rpc.call("recover_prepared", {**payload, field: payload[field] + 1})
                    except Refused:
                        pass
                    else:
                        raise AssertionError("changed " + field + " recovered")
                rows.append(
                    dict(
                        request=row["id"],
                        message_hash=row["message_hash"],
                        exact_message=True,
                        exact_acceptance=True,
                        changed_bindings_refused=3,
                    )
                )
    finally:
        connection.close()
    assert len(rows) >= args.min_cases, "insufficient real signed fixture attempts"
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before, (
        "native database changed during read-only recovery"
    )
    quiesced()
    report = dict(
        result="PASS",
        provider_sha256=args.sha256,
        actual_local_signed_attempts=rows,
        operations=["recover_prepared"],
        native_store_unchanged=True,
        inactive_unit=args.inactive_unit,
        chain_writes=0,
        new_signatures=0,
        scope="Historical recovery of real finalized local messages after quote expiry; not a new end-to-end lost-reply transfer.",
    )
    with args.out.open("x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    print(
        json.dumps(
            dict(
                result="PASS",
                real_signed_attempts=len(rows),
                binding_refusals=3 * len(rows),
                writes=0,
            )
        )
    )


if __name__ == "__main__":
    main()
