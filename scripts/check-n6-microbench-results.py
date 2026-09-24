#!/usr/bin/env python3
"""Validate the diagnostic N6.2 feasibility result without blessing thresholds."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


def fail(message: str) -> None:
    print(f"N6_MICROBENCH_RESULTS_FAILURE: {message}", file=sys.stderr)
    raise SystemExit(1)


root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]).resolve()
result_path = root / "doc/pq-native/N6-MICROBENCH-RESULTS.json"
if not result_path.is_file():
    fail("results file is missing")
result = json.loads(result_path.read_text(encoding="utf-8"))
if (
    result.get("evidence_class") != "DIAGNOSTIC_FEASIBILITY_ONLY"
    or result.get("release_evidence_eligible") is not False
):
    fail("parked N5 gaps were presented as release evidence")
if result.get("acceptance_evaluation") != {
    "status": "NOT_EVALUATED_OWNER_CRITERIA_UNSET",
    "thresholds_moved_to_fit_results": False,
}:
    fail("diagnostic measurements claimed a threshold verdict")
if (
    result.get("build", {}).get("type") != "Release"
    or result.get("build", {}).get("pq_backend") != "native-ml-dsa-44"
):
    fail("result did not use the Release build and validator ML-DSA backend")
host = result.get("host", {})
if (
    not host.get("affinity_cpus")
    or not host.get("cpu_model")
    or not isinstance(host.get("governor_observed"), str)
    or not host["governor_observed"].strip()
    or host.get("frequency_or_governor_changed_by_runner") is not False
):
    fail("CPU affinity/frequency/governor provenance is incomplete")

commit = result.get("git_commit", "")
if len(commit) != 40:
    fail("result has no exact measured Git commit")
try:
    subprocess.run(
        ["git", "-C", root, "cat-file", "-e", f"{commit}^{{commit}}"],
        check=True,
        capture_output=True,
    )
    measured_source = subprocess.check_output(
        ["git", "-C", root, "show", f"{commit}:test/pq-native/n6-microbench.cpp"]
    )
    measured_criteria = subprocess.check_output(
        [
            "git",
            "-C",
            root,
            "show",
            f"{commit}:doc/pq-native/N6-ACCEPTANCE-CRITERIA.json",
        ]
    )
except subprocess.CalledProcessError as exc:
    fail(f"measured commit, benchmark source, or acceptance criteria is unavailable: {exc}")
if result.get("acceptance_criteria_sha256") != hashlib.sha256(measured_criteria).hexdigest():
    fail("result does not bind the acceptance criteria at its measured commit")
if (
    hashlib.sha256(measured_source).hexdigest()
    != hashlib.sha256((root / "test/pq-native/n6-microbench.cpp").read_bytes()).hexdigest()
):
    fail("benchmark source differs from the source at the measured commit")

required_single = {
    "mldsa44_sign",
    "mldsa44_verify_valid",
    "mldsa44_verify_invalid",
    "key_id_derivation",
    "pqbytes_1312_pack_unpack",
    "pqbytes_2420_pack_unpack",
    "pending_finality_primitives",
}
if set(result.get("single_operations", {})) != required_single:
    fail("single-operation matrix is incomplete")
policy = result.get("sample_policy", {})
if policy.get("single_warmup", 0) < 1000 or policy.get("single_measured", 0) < 10000:
    fail("single-operation warmup/sample count is below the precommitted minimum")


def check_stats(name: str, stats: dict[str, object]) -> None:
    samples = stats.get("samples")
    if not isinstance(samples, int) or samples < 1:
        fail(f"{name} has no samples")
    if samples >= 100 and stats.get("p99_us") is None:
        fail(f"{name} omitted p99 despite sufficient samples")
    if samples < 100 and stats.get("p99_us") is not None:
        fail(f"{name} claims p99 from only {samples} samples")
    if samples < 20:
        fail(f"{name} has too few samples even for p95")


for name, stats in result["single_operations"].items():
    check_stats(name, stats)
matrix = result.get("certificate_proof_matrix", [])
if [row.get("signers") for row in matrix] != [1, 4, 21, 32, 64, 100, 200, 300, 400]:
    fail("certificate/proof signer matrix is incomplete")
required_timings = {
    "n4_certificate_parse",
    "n4_certificate_verify",
    "n5_13_serialize",
    "n5_13_parse",
    "n5_13_verify",
    "block_proof_signature_reference_roundtrip_verify",
    "lite_signature_set_roundtrip_verify",
}
for row in matrix:
    if set(row.get("timings", {})) != required_timings:
        fail(f"{row.get('signers')}-signer timing matrix is incomplete")
    for name, stats in row["timings"].items():
        check_stats(f"{row['signers']}/{name}", stats)
    if row["sizes"]["n5_13_boc_bytes"] > 1_020_996:
        fail(f"{row['signers']}-signer #13 exceeds the frozen structural maximum")
if result.get("structural_401", {}).get("accepted") is not False:
    fail("401 signers were not structurally refused")
if [entry.get("validators") for entry in result.get("authority_classification", [])] != [
    21,
    100,
    400,
]:
    fail("authority-classification matrix is incomplete")
for entry in result["authority_classification"]:
    if set(entry) != {"validators", "memo_miss_current_and_next", "memo_hit"}:
        fail(f"authority/{entry['validators']} does not separate memo miss and hit")
    check_stats(f"authority/{entry['validators']}/miss", entry["memo_miss_current_and_next"])
    check_stats(f"authority/{entry['validators']}/hit", entry["memo_hit"])
workers = [entry.get("workers") for entry in result.get("concurrency_sweep_100_signers", [])]
if (
    not workers
    or workers[0] != 1
    or workers != sorted(set(workers))
    or any(worker not in {1, 2, 4, 8, 16} for worker in workers)
):
    fail("bounded concurrency sweep is invalid")
for entry in result["concurrency_sweep_100_signers"]:
    check_stats(f"concurrency/{entry['workers']}", entry["batch"])
actor = result.get("actor_thread_decision", {})
if (
    actor.get("launch_proof_signers") != 100
    or actor.get("single_thread_actor_callback_stall_us", 0) <= 0
):
    fail("actor callback stall was not measured at the historical 100-signer diagnostic point")
if (
    actor.get("decision") != "OPEN_UNTIL_OWNER_ACCEPTS_NONZERO_CRITERIA"
    or actor.get("worker_pool_changed") is not False
):
    fail("measurement made an unauthorized worker-pool decision")

print(
    "N6_MICROBENCH_RESULTS_OK: diagnostic feasibility matrix is complete and makes no launch claim"
)
