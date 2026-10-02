#!/usr/bin/env python3
"""Compile the PR review regressions with each repaired guard removed in turn.

Run only with exclusive ownership of the checkout; never alongside another test
or build. Raw output remains outside Git. Every edited source is restored even
when a compiler or assertion fails unexpectedly.
"""

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASES = [
    (
        "cross-round-ack",
        "crypto/smartcont/nominator-pool/pool.fc",
        "result = result.store_ref(paid);",
        "result = result;",
        "recovery_ack_survives_accepted_and_rejected_later_stakes",
        "old recovery ACK remains repairable after later stake result",
    ),
    (
        "query-allocation",
        "crypto/smartcont/validator-controller-v1.fc",
        "(sequence < ((1 << 64) - 1)) & (query == sequence + 1)",
        "(query > sequence) & (query < (1 << 64))",
        "relay_query_allocation_refuses_large_jumps_without_burning_the_next_id",
        "nonconsecutive valid-signature query must be refused",
    ),
    (
        "single-bounce-retry",
        "crypto/smartcont/single-nominator-pool/single-nominator-code.fc",
        "single_protocol = single::previous();",
        "single::remember(query, hash, amount, prefix, 0, owner_address, validator_address, controller_address);",
        "single_pool_reuses_the_authoritative_query_after_a_real_controller_bounce",
        "pool order",
    ),
    (
        "single-prior-result",
        "crypto/smartcont/single-nominator-pool/single-nominator-code.fc",
        "single_protocol = single::previous();",
        "single_protocol = null();",
        "single_pool_bounce_preserves_a_previous_unacknowledged_result",
        "real bounce must retain the previous ACK repair record",
    ),
    (
        "recovery-confirmation-binding",
        "crypto/smartcont/nominator-pool/pool.fc",
        "(op == 0x47656133) & recovery_duplicate",
        "(op == 0x47656133)",
        "recovery_ack_survives_accepted_and_rejected_later_stakes",
        "unbound recovery confirmation cannot erase repair metadata",
    ),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=64)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ, TOS_ROOT=str(ROOT))
    results = []
    for name, relative, old, replacement, test, failure in CASES:
        path = ROOT / relative
        original = path.read_bytes()
        assert original.decode().count(old) == 1, (name, "mutation anchor changed")
        command = [
            "cargo",
            "test",
            "--manifest-path",
            "tosctl/src/Cargo.toml",
            "--locked",
            "-p",
            "contracts",
            "--test",
            "elector_sandbox",
            f"-j{args.jobs}",
            f"security_audit::relay::{test}",
            "--",
            "--exact",
            "--nocapture",
        ]
        row = {
            "case": name,
            "source": relative,
            "source_sha256": hashlib.sha256(original).hexdigest(),
            "command": command,
        }
        try:
            for stage in ("baseline", "mutant", "restored"):
                data = (
                    original
                    if stage != "mutant"
                    else original.decode().replace(old, replacement).encode()
                )
                path.write_bytes(data)
                log = args.out / f"{name}-{stage}.log"
                with log.open("wb") as output:
                    result = subprocess.run(
                        command,
                        cwd=ROOT,
                        env=environment,
                        stdout=output,
                        stderr=subprocess.STDOUT,
                        timeout=600,
                    )
                raw = log.read_bytes()
                row[stage] = {
                    "exit": result.returncode,
                    "log": str(log),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "source_sha256": hashlib.sha256(data).hexdigest(),
                }
                if stage == "mutant":
                    assert (
                        result.returncode == 101
                        and failure.encode() in raw
                        and b"panicked at" in raw
                    ), row
                    assert b"test result: FAILED. 0 passed; 1 failed" in raw, row
                else:
                    assert result.returncode == 0 and b"test result: ok. 1 passed" in raw, row
        finally:
            path.write_bytes(original)
            results.append(row)
            (args.out / "index.json").write_text(json.dumps(results, indent=2) + "\n")
        print(name, "baseline 0 / compiled assertion 101 / restored 0", flush=True)


if __name__ == "__main__":
    main()
