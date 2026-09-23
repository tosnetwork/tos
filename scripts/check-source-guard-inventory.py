#!/usr/bin/env python3
"""Fail closed when a required configure-only source guard leaves CTest."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REQUIRED_SOURCE_GUARDS = frozenset(
    {
        "adnl-query-id-analysis",
        "adnl-query-id-trace-source",
        "benchmark-exclusion-source",
        "branch-chain-python-ci-source",
        "consensus-no-fallback",
        "config-genesis-data-layout-source",
        "finality-evidence-admission-marker-mutations",
        "finality-evidence-admission-source",
        "frozen-boc-toolchain-resolution",
        "jsonrpc-route-gating",
        "lite-query-error-response-source",
        "n6-acceptance-criteria",
        "n6-cluster-runner",
        "n6-diagnostic-observations",
        "n6-manifest-completeness",
        "n6-microbench-results",
        "n6-scale-sweep-cardinality",
        "n6-skip-vote-semantics",
        "n6-threshold-proposal",
        "pending-finality-retry-policy-source",
        "pq-e2e-initial-validators-source",
        "pq-finality-boundary-source",
        "pq-launch-cap-mutations",
        "pq-launch-cap-source",
        "quic-ctest-isolation-source",
        "test-quorum-static-grep",
        "tosctl-pq-stake-builder-source",
        "validator-id-key-hash-source",
        "validator-session-assembly-source",
    }
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path, required=True)
    args = parser.parse_args()
    result = subprocess.run(
        [
            "ctest",
            "--test-dir",
            str(args.build_dir),
            "--show-only=json-v1",
            "-L",
            "source-guard",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(result.stdout)
    observed = {test["name"] for test in payload["tests"]}
    if observed != REQUIRED_SOURCE_GUARDS:
        missing = sorted(REQUIRED_SOURCE_GUARDS - observed)
        unexpected = sorted(observed - REQUIRED_SOURCE_GUARDS)
        raise RuntimeError(
            "SOURCE_GUARD_INVENTORY_FAILURE: registered source-guard set changed; "
            f"missing={missing} unexpected={unexpected}"
        )
    print(
        "SOURCE_GUARD_INVENTORY_OK: "
        f"all {len(REQUIRED_SOURCE_GUARDS)} required configure-only guards are registered"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
