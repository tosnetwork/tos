#!/usr/bin/env python3
"""Exercise actual service boundaries after compiled guard removal."""

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = dict(os.environ, CARGO_INCREMENTAL="0", CARGO_BUILD_PIPELINING="false")
CASES = [
    (
        "collector-conflict",
        "health-services/src/collector.rs",
        "tos_health_core::native::canonical_hash(&immutable)?",
        "String::new()",
        "r4_collector_preserves_source_identity_and_immutable_payload",
    ),
    (
        "legacy-source-bound",
        "health-services/src/collector.rs",
        '|| record.source_id != "collector"',
        "",
        "r4_collector_preserves_source_identity_and_immutable_payload",
    ),
    # The typed native sample is no longer optional on the snapshot route; the guard the old 'typed-route'
    # case removed does not exist. The mutant now drops the native sample from the snapshot instead.
    (
        "typed-source-required",
        "health-services/src/edge.rs",
        "    sources.push(match native {",
        "    let _ = (match native {",
        "typed_sampler_and_edge_read_only_cache",
    ),
    # The record is an enum now; the mutant keys the cache on the payload-only content hash of whichever version
    # arrived, instead of the immutable identity hash that also covers the metadata.
    (
        "typed-identity",
        "health-services/src/native_cache.rs",
        "&value.immutable_hash()?,",
        "&match &value { NativeRecord::V1(v) => v.content_hash.clone(), NativeRecord::V2(v) => v.content_hash.clone(), NativeRecord::V3(v) => v.content_hash.clone() },",
        "typed_cache_duplicate_age_and_conflict_are_sticky",
    ),
    (
        "age-budget",
        "health-services/src/native_cache.rs",
        "if adjusted_age > 30_000",
        "if false",
        "typed_cache_duplicate_age_and_conflict_are_sticky",
    ),
    (
        "typed-publication",
        "health-services/src/native_cache.rs",
        "self.typed = Some((value, Instant::now()));",
        "self.typed = None;",
        "typed_sampler_and_edge_read_only_cache",
    ),
    # Pairing is written once per typed record version; the mutant removes the generation check from all three.
    (
        "pair-mismatch",
        "health-core/src/native.rs",
        "|| self.generation.0 != exact_u64(generation).map_err(str::to_owned)?",
        "|| false",
        "mismatched_pair_has_no_retry_and_no_publication",
        3,
    ),
    # Both native adapters (v2 and v3) carry the completeness flag; the mutant forces it in both.
    (
        "pq-quality",
        "health-services/src/manager_poll.rs",
        "complete: value.quality.instrumentation_complete",
        "complete: true",
        "native_adapter_does_not_turn_missing_pq_into_zero",
        2,
    ),
    (
        "collector-age",
        "health-services/src/collector.rs",
        "source.source_age_ms = None;",
        "",
        "r4_collector_preserves_source_identity_and_immutable_payload",
    ),
    # The poll now matches on the validation error; the mutant makes the result always Ok so no snapshot is refused.
    (
        "native-inventory",
        "health-services/src/manager_poll.rs",
        "if let Err(e) = snapshot.validate(&config.node_id, &config.network_id) {",
        "if let Err(e) = snapshot.validate(&config.node_id, &config.network_id).or::<String>(Ok(())) {",
        "scheduled_native_poll_checks_inventory_over_mtls",
    ),
]


def run(name):
    target = "ingress" if name.startswith("scheduled_") else "native_typed"
    return subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "-p",
            "tos-health-services",
            "--test",
            target,
            name,
            "--",
            "--exact",
        ],
        cwd=ROOT,
        env=ENV,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


for case in CASES:
    label, file, old, new, name = case[:5]
    expected = case[5] if len(case) > 5 else 1  # occurrences the anchor must have; all are replaced
    path = ROOT / "crates" / file
    original = path.read_text()
    baseline = run(name)
    if baseline.returncode or "1 passed" not in baseline.stdout:
        raise RuntimeError(f"{label} baseline\n{baseline.stdout}")
    if original.count(old) != expected:
        raise RuntimeError(f"{label}: target count {original.count(old)}, expected {expected}")
    try:
        path.write_text(original.replace(old, new))
        result = run(name)
        if result.returncode == 0 or f"{name} ... FAILED" not in result.stdout:
            raise RuntimeError(f"{label}: no compiled assertion failure\n{result.stdout}")
        print(label + ": compiled mutant killed", flush=True)
    finally:
        path.write_text(original)
print("all service mutation sources restored")
