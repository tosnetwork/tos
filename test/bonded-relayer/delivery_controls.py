#!/usr/bin/env python3
"""Remove real A1/B1/C1 guards in disposable source trees and require named failures.

Shared, identical test tooling in the parallel branches. --lane selects only
files delivered by that branch. Neither fixtures nor successful controls are
native funded-network acceptance evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
A = "tools/bonded-relayer/native_adapter.py"
P = "tools/bonded-relayer/native_process.py"
S = "tools/bonded-relayer/relay_service.py"
H = "tools/bonded-relayer/relay_http.py"
C = "tools/bonded-relayer/relay_client.py"
Q = "tools/shielded-pool-wallet/src/relayer_quote.rs"
CASES = {
    "adapter": (
        (
            P,
            'reply["request_sha256"] != hashlib.sha256(wire).hexdigest()',
            "False",
            "test_native_boundary.ProtocolTests.test_unrelated_and_schema_drift_replies_refuse",
        ),
        (
            A,
            "hashlib.sha256(key).hexdigest() != self.release.worker_key_hash",
            "False",
            "test_native_boundary.AdapterTests.test_wrong_worker_quote_refuses_before_native_verification",
        ),
        (
            A,
            "self._permits.pop(key, None)",
            "self._permits.get(key)",
            "test_native_boundary.AdapterTests.test_exact_permit_is_consumed_even_after_ambiguous_write",
        ),
        (
            A,
            '"amount": str(terms["amount"])',
            '"amount": fee["amount"]',
            "test_native_boundary.AdapterTests.test_fee_credit_substitutions_refuse",
        ),
    ),
    "service": (
        (
            S,
            "allow_reuse_address = True",
            "allow_reuse_address = False",
            "test_relay_service.ServiceTests.test_server_restarts_after_active_close_without_sharing_listener",
        ),
        (
            S,
            'not hmac.compare_digest(expected, terms["status_hash"])',
            "False",
            "test_relay_service.ServiceTests.test_capability_and_quote_mismatch_refuse_before_proof_work",
        ),
        (
            S,
            'request.funding_cap > terms["funding_cap"]',
            "False",
            "test_relay_service.ServiceTests.test_capability_and_quote_mismatch_refuse_before_proof_work",
        ),
        (
            H,
            "if length > maximum:",
            "if False:",
            "test_relay_service.HTTPBoundTests.test_content_length_bound_is_not_an_unrelated_parse_failure",
        ),
        (
            C,
            "encode(authenticated) != encode(quote.terms)",
            "False",
            "test_relay_service.HTTPTests.test_modified_quote_object_is_reverified_before_submission",
        ),
    ),
    "composed": (
        (
            "test/bonded-relayer/run_delivery_fixture.py",
            "if args.require_native:",
            "if False:",
            "test_delivery_fixture_runner.DeliveryRunnerTests.test_native_requirement_refuses_before_running_fixture_or_writing_receipt",
        ),
        (
            "test/bonded-relayer/run_delivery_fixture.py",
            "if actual != SCENARIOS:",
            "if False:",
            "test_delivery_fixture_runner.DeliveryRunnerTests.test_missing_or_extra_scenario_cannot_be_reported_as_complete",
        ),
    ),
    "rust": (
        (
            Q,
            "if !key.verify(terms, signature, CONTEXT)",
            "if false && !key.verify(terms, signature, CONTEXT)",
            "wrong_worker_and_modified_signature_refuse",
        ),
        (
            Q,
            "terms.is_empty() || terms.len() > MAX_TERMS_BYTES",
            "false",
            "byte_bound_is_checked_on_both_sides",
        ),
        (
            Q,
            'b"TOS-BR1-QUOTE-v1"',
            'b"TOS-BONDED-RELAYER-v1"',
            "real_worker_signature_authenticates_exact_terms",
        ),
    ),
}
FILES = {
    "adapter": (
        A,
        P,
        "tools/bonded-relayer/relay_core.py",
        "tools/bonded-relayer/relay_wire.py",
        "test/bonded-relayer/test_native_boundary.py",
    ),
    "service": (
        S,
        H,
        C,
        "tools/bonded-relayer/relay_core.py",
        "tools/bonded-relayer/relay_wire.py",
        "test/bonded-relayer/_service_fixture.py",
        "test/bonded-relayer/test_relay_service.py",
    ),
}

FILES["composed"] = tuple(
    dict.fromkeys(
        (
            *FILES["adapter"],
            *FILES["service"],
            "tools/bonded-relayer/br1.py",
            "test/bonded-relayer/two_operator_harness.py",
            "test/bonded-relayer/test_two_operator.py",
            "test/bonded-relayer/run_delivery_fixture.py",
            "test/bonded-relayer/test_delivery_fixture_runner.py",
        )
    )
)


def run(root: Path, lane: str, name: str | None):
    if lane == "rust":
        command = [
            "cargo",
            "test",
            "--locked",
            "--manifest-path",
            "tools/shielded-pool-wallet/Cargo.toml",
            "--test",
            "relayer_quote",
        ]
        if name:
            command.extend([name, "--", "--exact"])
        timeout, cwd = 600, root
    else:
        module = {
            "adapter": "test_native_boundary",
            "service": "test_relay_service",
            "composed": "test_delivery_fixture_runner",
        }[lane]
        command = [sys.executable, "-B", "-m", "unittest", "-v", name or module]
        timeout, cwd = 60, root / "test/bonded-relayer"
    with tempfile.TemporaryFile() as log:
        result = subprocess.run(
            command,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        size = log.tell()
        if size > 256 * 1024:
            raise RuntimeError("control output exceeds retained byte bound")
        log.seek(0)
        return result.returncode, log.read().decode("utf-8", errors="replace")


def snapshot(root: Path, lane: str) -> tuple[str, ...]:
    if lane == "rust":
        # Only the standalone crates and their two fixed shared inputs are
        # required; no test ever mutates the operator's checkout.
        for name in ("tools/shielded-pool-wallet", "tools/shielded-pool-circuit"):
            shutil.copytree(
                ROOT / name,
                root / name,
                ignore=shutil.ignore_patterns("target", "crosscheck", ".git"),
            )
        names = ("tosctl/src/block/src/poseidon2_kat.rs", "crypto/poseidon2/manifest.bin")
        for name in names:
            dest = root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, dest)
        return (Q, "tools/shielded-pool-wallet/tests/relayer_quote.rs")
    for name in FILES[lane]:
        dest = root / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, dest)
    return FILES[lane]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lane", choices=tuple(CASES), required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    records = []
    with tempfile.TemporaryDirectory(prefix="br1-controls-") as directory:
        root = Path(directory)
        names = snapshot(root, args.lane)
        hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in names}
        code, log = run(root, args.lane, None)
        expected_tests = {"adapter": 29, "service": 29, "composed": 2, "rust": 5}[args.lane]
        observed = re.search(
            r"running (\d+) tests" if args.lane == "rust" else r"Ran (\d+) tests", log
        )
        if (
            code != 0
            or observed is None
            or int(observed.group(1)) != expected_tests
            or ("5 passed; 0 failed; 0 ignored" if args.lane == "rust" else "\nOK\n") not in log
        ):
            raise RuntimeError(
                "control baseline did not pass its complete inventory: " + log[-2000:]
            )
        for path, old, new, name in CASES[args.lane]:
            target = root / path
            original = target.read_text()
            if original.count(old) != 1:
                raise RuntimeError("mutation anchor drift: " + path + ": " + old)
            try:
                target.write_text(original.replace(old, new, 1))
                code, log = run(root, args.lane, name)
                if args.lane == "rust":
                    detected = (
                        code == 101
                        and f"test {name} ... FAILED" in log
                        and "assertion" in log
                        and "error: could not compile" not in log
                    )
                else:
                    detected = (
                        code == 1
                        and f"FAIL: {name.rsplit('.', 1)[-1]}" in log
                        and "AssertionError:" in log
                        and "\nERROR:" not in log
                    )
                if not detected:
                    raise RuntimeError(
                        "mutant was not rejected by its named assertion: "
                        + name
                        + "\n"
                        + log[-2000:]
                    )
                records.append(
                    {
                        "path": path,
                        "guard": old,
                        "test": name,
                        "mutant_exit": code,
                        "intended_assertion_failed": True,
                        "failure_excerpt": "\n".join(
                            line
                            for line in log.splitlines()
                            if line.startswith(("FAIL:", "AssertionError:", "test "))
                            or "assertion" in line
                        )[:2048],
                    }
                )
                print("BR1_CONTROL_DETECTED", args.lane, name)
            finally:
                target.write_text(original)
            code, restored = run(root, args.lane, name)
            if code != 0:
                raise RuntimeError("restored targeted control failed: " + restored[-2000:])
        code, final = run(root, args.lane, None)
        if code != 0:
            raise RuntimeError("restored full suite failed: " + final[-2000:])
        if not all(
            hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == value
            for name, value in hashes.items()
        ):
            raise RuntimeError("original checkout changed while controls ran")
    receipt = {
        "schema": "tos.br1.delivery.controls.v1",
        "lane": args.lane,
        "baseline_tests": expected_tests,
        "control_runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "source_sha256": hashes,
        "baseline_passed": True,
        "restored_passed": True,
        "sources_unchanged": True,
        "controls": records,
        "production_accepted": False,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    print("BR1_DELIVERY_CONTROLS_OK", args.lane, len(records))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
