#!/usr/bin/env python3
"""Prove each requested N6 sweep scale controls the booted topology."""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/tostester/src"))

import tostester.n6_cluster as n6_cluster  # noqa: E402


class FakeRemoteBackend:
    def manifest(self):
        return {"kind": "remote-command"}


async def run_gate(root: Path) -> None:
    boot_requests: list[int] = []

    async def fake_run_cluster(
        install, artifact_dir, backend, validators, base_port, require_lite, latency_profile_path
    ):
        del install, artifact_dir, backend, base_port, require_lite, latency_profile_path
        boot_requests.append(validators)
        return {
            "nodes": [
                {"role": "validator", "name": f"validator-{index}"}
                for index in range(validators)
            ]
            + [{"role": "non-validator-verifier", "name": "verifier"}],
            "consensus_milestones": {
                "time_to_first_proposal_ns": 1,
                "time_to_first_notarization_certificate_ns": 2,
                "time_to_first_final_certificate_ns": 3,
            },
        }

    original = n6_cluster.run_cluster
    n6_cluster.run_cluster = fake_run_cluster
    try:
        result = await n6_cluster.run_scale_sweep(
            SimpleNamespace(source_dir=ROOT),
            root / "scale-sweep",
            FakeRemoteBackend(),
            [4, 7],
            ROOT / "test/pq-native/n6-scale-profiles/no-simulated-latency.json",
            31000,
        )
    finally:
        n6_cluster.run_cluster = original

    requested = [point["requested_validators"] for point in result["scale_points"]]
    booted = [point["booted_validators"] for point in result["scale_points"]]
    if boot_requests != [4, 7] or requested != [4, 7] or booted != [4, 7]:
        raise RuntimeError(
            f"distinct requested scales did not control booted topology: "
            f"calls={boot_requests} requested={requested} booted={booted}"
        )
    if len(set(booted)) != len(booted):
        raise RuntimeError(f"distinct requested scales produced duplicate boot counts: {booted}")
    if result["required_release_scales"] != [21]:
        raise RuntimeError(
            f"release scale requirement changed: {result['required_release_scales']}"
        )
    if result["required_release_scales_measured"] != []:
        raise RuntimeError(
            "diagnostic sweep claimed required release scales: "
            f"{result['required_release_scales_measured']}"
        )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="n6-scale-cardinality-") as temporary:
        asyncio.run(run_gate(Path(temporary)))
    print("N6_SCALE_SWEEP_CARDINALITY_OK: distinct requested scales boot distinct topologies")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, RuntimeError, ValueError) as error:
        print(f"N6_SCALE_SWEEP_CARDINALITY_FAILURE: {error}", file=sys.stderr)
        raise SystemExit(1) from error
