#!/usr/bin/env python3
"""Run the complete C1 process fixture registry, never claim native acceptance."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = frozenset(
    {
        "test_two_distinct_processes_receive_independent_quotes_and_fees",
        "test_crash_after_ambiguous_write_never_resigns_or_resubmits",
        "test_crash_after_preparation_resumes_exact_persisted_message",
        "test_foreign_quote_is_rejected_before_either_operator_signs",
        "test_bad_proof_with_fee_shaped_output_never_prepares",
        "test_concurrent_duplicate_requests_have_one_broadcast",
        "test_destination_refusal_has_no_fee_credit_or_false_success",
        "test_unrelated_receipt_cannot_finalize_a_request",
        "test_lost_http_acknowledgement_is_recoverable_by_identity",
    }
)
SOURCES = (
    "tools/bonded-relayer/relay_core.py",
    "tools/bonded-relayer/relay_wire.py",
    "tools/bonded-relayer/native_process.py",
    "tools/bonded-relayer/native_adapter.py",
    "tools/bonded-relayer/relay_http.py",
    "tools/bonded-relayer/relay_service.py",
    "tools/bonded-relayer/relay_client.py",
    "tools/bonded-relayer/br1.py",
    "test/bonded-relayer/two_operator_harness.py",
    "test/bonded-relayer/test_two_operator.py",
    "test/bonded-relayer/test_native_boundary.py",
    "test/bonded-relayer/run_delivery_fixture.py",
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--require-native",
        action="store_true",
        help="refuse fixture substitution for the open funded-localnet gate",
    )
    args = parser.parse_args(argv)
    if args.require_native:
        print(
            "BR1_NATIVE_ACCEPTANCE_UNAVAILABLE: native provider and funded scenario driver are not delivered by C1",
            file=sys.stderr,
        )
        return 2
    from test_two_operator import TwoOperatorTests

    actual = set(unittest.defaultTestLoader.getTestCaseNames(TwoOperatorTests))
    if actual != SCENARIOS:
        print("BR1_FIXTURE_INVENTORY_MISMATCH", file=sys.stderr)
        return 1
    hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(TwoOperatorTests)
    )
    unchanged = all(
        hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == value
        for name, value in hashes.items()
    )
    success = (
        result.wasSuccessful()
        and result.testsRun == len(SCENARIOS)
        and not result.skipped
        and unchanged
    )
    receipt = {
        "schema": "tos.br1.delivery.fixture.v1",
        "scope": "process_http_sqlite_fixture",
        "native_chain_executed": False,
        "funded_operators": False,
        "production_accepted": False,
        "fixture_passed": success,
        "cases": sorted(SCENARIOS),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "sources_unchanged": unchanged,
        "source_sha256": hashes,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    if success:
        print("BR1_PROCESS_FIXTURE_OK_NOT_NATIVE_ACCEPTANCE")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
