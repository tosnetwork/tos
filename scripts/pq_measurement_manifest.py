#!/usr/bin/env python3
"""Write the reproducible manifest that precedes every PQ measurement run.

This module deliberately does not start validators.  It validates and writes the
contract a later runner must satisfy before doing so.  Diagnostic manifests are
never release evidence; release manifests additionally require a clean tree and
an exact-commit N5 closure artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
REQUIRED_CORRECTNESS_QUESTION_IDS = (
    "classical-e2e-fixtures-incompatible-with-pq-consensus",
    "classical-config-vote-tooling-incompatible-with-pq-contract",
    "classical-stake-producers-incompatible-with-pq-elector",
    "pool-first-stake-birth-witness-missing",
    "merkle-base-state-mismatch",
)
REQUIRED_MEASUREMENT_GAP_IDS = (
    "release-scale-matrix-unmeasured",
    "carrier-scale-transport-unmeasured",
    "sustained-finality-distribution-unmeasured",
)

INHERITED_SIMPLEX_DEPENDENCIES = {
    "ton_current_consensus": "Simplex",
    "ton_production_committee_approx": 400,
    "tos_enforced_launch_cap": 21,
}
INHERITED_SIMPLEX_FORK_POINT = {
    "commit": "628506c9e",
    "validator_consensus_simplex_files": 16,
}
INHERITED_SIMPLEX_GAP_EVIDENCE = {
    "release-scale-matrix-unmeasured": {
        "upstream_validators_approx": 400,
        "capped_validators": 21,
        "relative_scale": "21/400 (about one nineteenth)",
    },
    "carrier-scale-transport-unmeasured": {
        "pq_21_signature_bytes": 50820,
        "ed25519_400_signature_bytes": 25600,
        "relative_bytes": "1.99x",
        "unreachable_structural_carrier_ceiling_bytes": 984260,
    },
    "sustained-finality-distribution-unmeasured": {
        "pq_21_verify_us_at_67_6_each": 1419.6,
        "ed25519_400_verify_us_at_30_each": 12000,
        "relative_verify_cost": "0.12x (about one eighth)",
    },
}

REQUIRED_SCALES = (21,)
REQUIRED_NETWORK_PROFILES = ("baseline", "launch-wan", "degraded")
REQUIRED_WORKLOADS = ("consensus-isolation", "target-load", "high-load")
POSITIVE_CRITERIA_FIELDS = (
    "max_p99_persisted_finality_ms",
    "max_p99_block_signature_verify_ms",
    "max_p99_lite_verify_ms",
    "max_cpu_fraction",
    "max_rss_fraction",
    "max_network_fraction",
    "max_disk_busy_fraction",
    "max_finalization_backpressure_fraction",
    "max_pending_finality_bytes",
    "max_pending_finality_candidates",
    "max_authority_classification_p99_ms",
    "max_finalized_height_stall_ms",
)
ZERO_CRITERIA_FIELDS = (
    "max_unbounded_memory_slope_bytes_per_hour",
    "safety_violations_allowed",
    "process_crashes_allowed",
    "invalid_proofs_accepted",
)

REQUIRED_PATHS: tuple[tuple[str, ...], ...] = (
    ("schema_version",),
    ("run_id",),
    ("mode",),
    ("release_evidence_eligible",),
    ("git_commit",),
    ("git_tree",),
    ("dirty_tree",),
    ("build", "build_type"),
    ("build", "compiler"),
    ("build", "compiler_version"),
    ("build", "linker"),
    ("build", "cmake_options"),
    ("build", "pq_algorithm"),
    ("build", "pq_backend_version"),
    ("build", "n5_carrier_tag"),
    ("build", "n5_format_version"),
    ("host", "os"),
    ("host", "kernel"),
    ("host", "cpu_model"),
    ("host", "physical_cores"),
    ("host", "logical_cpus"),
    ("host", "cpu_affinity"),
    ("host", "cgroup_cpu_quota"),
    ("host", "numa_topology"),
    ("host", "memory_bytes"),
    ("host", "swap_enabled"),
    ("host", "allocator"),
    ("host", "malloc_conf"),
    ("host", "disk_model"),
    ("host", "filesystem"),
    ("host", "mount_options"),
    ("host", "network_nic"),
    ("host", "network_link_speed"),
    ("chain", "global_id"),
    ("chain", "node_count"),
    ("chain", "masterchain_committee_count"),
    ("chain", "shard_committee_count"),
    ("chain", "validator_pool_count"),
    ("chain", "config_param_16"),
    ("chain", "config_param_28"),
    ("chain", "config_param_30"),
    ("chain", "block_limits"),
    ("chain", "gas_limits"),
    ("chain", "collated_data_limits"),
    ("network", "profile_name"),
    ("network", "latency_matrix_sha256"),
    ("network", "jitter"),
    ("network", "loss"),
    ("network", "bandwidth_cap"),
    ("workload", "profile"),
    ("workload", "warmup_duration_seconds"),
    ("workload", "measurement_duration_seconds"),
    ("workload", "fault_schedule_sha256"),
    ("resources", "pending_finality", "maximum_boxed_carrier_bytes"),
    ("resources", "pending_finality", "public_pool_bytes"),
    ("resources", "pending_finality", "validator_reserved_pool_bytes"),
    ("resources", "pending_finality", "total_pool_bytes"),
    ("resources", "pending_finality", "sender_across_blocks_bytes"),
    ("resources", "pending_finality", "retention_seconds"),
    ("resources", "pending_finality", "authority_memo_entries"),
    ("acceptance_criteria_sha256",),
    ("test_matrix_sha256",),
)


class ManifestError(RuntimeError):
    pass


def _run_git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise ManifestError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_acceptance_criteria(path: Path, *, release: bool) -> dict[str, Any]:
    try:
        criteria = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"acceptance criteria are unreadable: {exc}") from exc
    if not isinstance(criteria, dict):
        raise ManifestError("acceptance criteria root is not an object")
    if criteria.get("schema_version") != SCHEMA_VERSION:
        raise ManifestError("acceptance criteria schema_version is not 1")
    hardware = criteria.get("release_hardware_profile")
    if not isinstance(hardware, str) or not hardware:
        raise ManifestError("acceptance criteria lack release_hardware_profile")

    for field, required in (
        ("required_scales", REQUIRED_SCALES),
        ("required_network_profiles", REQUIRED_NETWORK_PROFILES),
        ("required_workloads", REQUIRED_WORKLOADS),
    ):
        values = criteria.get(field)
        if not isinstance(values, list) or any(value not in values for value in required):
            raise ManifestError(f"acceptance criteria field {field} lacks required entries")

    for field in POSITIVE_CRITERIA_FIELDS + ZERO_CRITERIA_FIELDS:
        value = criteria.get(field)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise ManifestError(f"acceptance criteria field {field} is not a non-negative number")
    for field in (
        "max_cpu_fraction",
        "max_rss_fraction",
        "max_network_fraction",
        "max_disk_busy_fraction",
        "max_finalization_backpressure_fraction",
    ):
        if criteria[field] > 1:
            raise ManifestError(f"acceptance criteria field {field} exceeds 1.0")
    for field in ZERO_CRITERIA_FIELDS:
        if criteria[field] != 0:
            raise ManifestError(f"acceptance criteria field {field} must be zero")
    if release:
        if hardware == "OWNER_REVIEW_REQUIRED":
            raise ManifestError("release-grade measurement refuses an unreviewed hardware profile")
        for field in POSITIVE_CRITERIA_FIELDS:
            if criteria[field] == 0:
                raise ManifestError(f"release-grade measurement refuses zero threshold {field}")
    return criteria


def validate_manifest_inputs(
    manifest: dict[str, Any], criteria_path: Path, matrix_path: Path
) -> None:
    for field, path in (
        ("acceptance_criteria_sha256", criteria_path),
        ("test_matrix_sha256", matrix_path),
    ):
        actual = sha256_file(path)
        if manifest.get(field) != actual:
            raise ManifestError(f"manifest {field} does not match {path.name}")


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _memory_and_swap() -> tuple[int, bool]:
    values: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            name, raw = line.split(":", 1)
            values[name] = int(raw.strip().split()[0]) * 1024
    except OSError, ValueError:
        return 0, False
    return values.get("MemTotal", 0), values.get("SwapTotal", 0) != 0


def observed_host() -> dict[str, Any]:
    memory_bytes, swap_enabled = _memory_and_swap()
    affinity = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else []
    logical = os.cpu_count() or 0
    # physical core topology is platform-specific.  Release profiles override
    # this observed fallback with their reviewed hardware inventory.
    physical = len(affinity) if affinity else logical
    return {
        "os": platform.platform(),
        "kernel": platform.release(),
        "cpu_model": _cpu_model(),
        "physical_cores": physical,
        "logical_cpus": logical,
        "cpu_affinity": affinity,
        "cgroup_cpu_quota": "unknown",
        "numa_topology": "unknown",
        "memory_bytes": memory_bytes,
        "swap_enabled": swap_enabled,
        "allocator": "unknown",
        "malloc_conf": os.environ.get("MALLOC_CONF", "unset"),
        "disk_model": "unknown",
        "filesystem": "unknown",
        "mount_options": "unknown",
        "network_nic": "unknown",
        "network_link_speed": "unknown",
    }


def validate_n5_closure(path: Path, commit: str) -> None:
    try:
        closure = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"N5 closure artifact is unreadable: {exc}") from exc
    if closure.get("status") != "CLOSED":
        raise ManifestError("N5 closure artifact does not say CLOSED")
    if closure.get("commit") != commit:
        raise ManifestError("N5 closure artifact does not name the measured commit")
    gaps = closure.get("gaps", {})
    if gaps.get("validator_manager_actor") is not True:
        raise ManifestError("N5 closure artifact lacks ValidatorManager actor integration")
    if gaps.get("crash_restart_cuts") != 5:
        raise ManifestError("N5 closure artifact lacks all five crash/restart cuts")
    if gaps.get("check_proof_actor") is not True:
        raise ManifestError("N5 closure artifact lacks production CheckProof actor coverage")


def validate_open_correctness_questions(path: Path, *, release: bool) -> None:
    try:
        registry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"correctness-question registry is unreadable: {exc}") from exc
    if not isinstance(registry, dict) or registry.get("schema_version") != SCHEMA_VERSION:
        raise ManifestError("correctness-question registry schema_version is not 1")
    required = registry.get("required_question_ids")
    questions = registry.get("questions")
    if not isinstance(required, list) or not all(isinstance(item, str) and item for item in required):
        raise ManifestError("correctness-question registry has invalid required_question_ids")
    if not isinstance(questions, dict):
        raise ManifestError("correctness-question registry questions is not an object")
    for question_id in REQUIRED_CORRECTNESS_QUESTION_IDS:
        if question_id not in required:
            raise ManifestError(f"correctness-question registry dropped required entry {question_id}")
    if set(required) != set(questions):
        missing = sorted(set(required) - set(questions))
        unrequired = sorted(set(questions) - set(required))
        raise ManifestError(
            "correctness-question registry required ids and entries differ: "
            f"missing_entries={missing} unrequired_entries={unrequired}"
        )

    open_questions: list[str] = []
    for question_id, question in questions.items():
        if not isinstance(question, dict):
            raise ManifestError(f"correctness question {question_id} is not an object")
        for field in ("observation", "observed_commit", "location", "closure_condition", "status"):
            if not isinstance(question.get(field), str) or not question[field]:
                raise ManifestError(f"correctness question {question_id} lacks {field}")
        commit = question["observed_commit"]
        if len(commit) < 9 or len(commit) > 40 or any(ch not in "0123456789abcdef" for ch in commit):
            raise ManifestError(f"correctness question {question_id} has invalid observed_commit")
        status = question["status"]
        if status == "OPEN":
            if question.get("resolved_by") not in (None, ""):
                raise ManifestError(f"open correctness question {question_id} already names resolved_by")
            open_questions.append(question_id)
        elif status == "RESOLVED":
            resolved_by = question.get("resolved_by")
            if (
                not isinstance(resolved_by, str)
                or len(resolved_by) < 9
                or len(resolved_by) > 40
                or any(ch not in "0123456789abcdef" for ch in resolved_by)
            ):
                raise ManifestError(
                    f"resolved correctness question {question_id} has invalid resolved_by commit"
                )
        else:
            raise ManifestError(f"correctness question {question_id} has unknown status {status}")
    if release and open_questions:
        raise ManifestError(
            "release-grade measurement refuses open correctness questions: "
            + ", ".join(sorted(open_questions))
        )


def validate_open_measurement_gaps(path: Path, *, release: bool) -> None:
    try:
        registry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"measurement-gap registry is unreadable: {exc}") from exc
    if not isinstance(registry, dict) or registry.get("schema_version") != SCHEMA_VERSION:
        raise ManifestError("measurement-gap registry schema_version is not 1")
    required = registry.get("required_gap_ids")
    gaps = registry.get("gaps")
    if not isinstance(required, list) or not all(isinstance(item, str) and item for item in required):
        raise ManifestError("measurement-gap registry has invalid required_gap_ids")
    if not isinstance(gaps, dict):
        raise ManifestError("measurement-gap registry gaps is not an object")
    for gap_id in REQUIRED_MEASUREMENT_GAP_IDS:
        if gap_id not in required:
            raise ManifestError(f"measurement-gap registry dropped required entry {gap_id}")
    if set(required) != set(gaps):
        raise ManifestError("measurement-gap registry required ids and entries differ")

    open_gaps: list[str] = []
    for gap_id, gap in gaps.items():
        if not isinstance(gap, dict):
            raise ManifestError(f"measurement gap {gap_id} is not an object")
        for field in ("observation", "reason", "closure_condition", "status"):
            if not isinstance(gap.get(field), str) or not gap[field]:
                raise ManifestError(f"measurement gap {gap_id} lacks {field}")
        status = gap["status"]
        if status == "OPEN":
            if gap.get("resolved_by") not in (None, ""):
                raise ManifestError(f"open measurement gap {gap_id} already names resolved_by")
            open_gaps.append(gap_id)
        elif status == "RESOLVED":
            if not isinstance(gap.get("resolved_by"), str) or not gap["resolved_by"]:
                raise ManifestError(f"resolved measurement gap {gap_id} lacks resolved_by evidence")
            resolution_kind = gap.get("resolution_kind")
            if resolution_kind == "INHERITED_SIMPLEX_WITH_ENFORCED_CAP":
                if gap.get("depends_on") != INHERITED_SIMPLEX_DEPENDENCIES:
                    raise ManifestError(
                        f"resolved measurement gap {gap_id} does not pin the inherited Simplex dependencies"
                    )
                if gap.get("fork_point_evidence") != INHERITED_SIMPLEX_FORK_POINT:
                    raise ManifestError(
                        f"resolved measurement gap {gap_id} does not pin the Simplex fork-point evidence"
                    )
                evidence = gap.get("evidence")
                if evidence != INHERITED_SIMPLEX_GAP_EVIDENCE[gap_id]:
                    raise ManifestError(
                        f"resolved measurement gap {gap_id} has stale inherited-production evidence"
                    )
            elif resolution_kind not in (None, "MEASURED_RELEASE_RESULT"):
                raise ManifestError(
                    f"measurement gap {gap_id} has unknown resolution_kind {resolution_kind}"
                )
            elif gap_id == "release-scale-matrix-unmeasured":
                evidence_results = gap.get("evidence_results")
                if (
                    not isinstance(evidence_results, list)
                    or not evidence_results
                    or not all(isinstance(item, str) and item for item in evidence_results)
                ):
                    raise ManifestError(
                        "resolved measurement gap release-scale-matrix-unmeasured lacks evidence_results"
                    )
                measured_scales: set[int] = set()
                for raw_result in evidence_results:
                    result_path = Path(raw_result)
                    if not result_path.is_absolute():
                        result_path = path.parent / result_path
                    try:
                        result = json.loads(result_path.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError) as exc:
                        raise ManifestError(
                            f"release-scale evidence result {raw_result} is unreadable: {exc}"
                        ) from exc
                    if result.get("local_colocation_diagnostic_override") is True:
                        raise ManifestError(
                            "release-scale-matrix-unmeasured cannot be resolved by "
                            "local_colocation_diagnostic_override evidence"
                        )
                    if result.get("local_colocation_diagnostic_override") is not False:
                        raise ManifestError(
                            "release-scale evidence does not state local_colocation_diagnostic_override=false"
                        )
                    if result.get("release_evidence_eligible") is not True:
                        raise ManifestError(
                            "release-scale-matrix-unmeasured evidence is not release_evidence_eligible"
                        )
                    scales = result.get("required_release_scales_measured")
                    if not isinstance(scales, list) or any(
                        isinstance(scale, bool) or not isinstance(scale, int) for scale in scales
                    ):
                        raise ManifestError("release-scale evidence has invalid measured scales")
                    measured_scales.update(scales)
                if measured_scales != set(REQUIRED_SCALES):
                    raise ManifestError(
                        "release-scale evidence does not cover required scales "
                        + "/".join(str(scale) for scale in REQUIRED_SCALES)
                    )
        else:
            raise ManifestError(f"measurement gap {gap_id} has unknown status {status}")
    if release and open_gaps:
        raise ManifestError(
            "release-grade measurement refuses open measurement gaps: "
            + ", ".join(sorted(open_gaps))
        )


def _lookup(manifest: dict[str, Any], path: tuple[str, ...]) -> Any:
    value: Any = manifest
    for component in path:
        if not isinstance(value, dict) or component not in value:
            raise ManifestError(f"manifest missing required field {'.'.join(path)}")
        value = value[component]
    return value


def validate_manifest(manifest: dict[str, Any]) -> None:
    for path in REQUIRED_PATHS:
        value = _lookup(manifest, path)
        if value is None or value == "":
            raise ManifestError(f"manifest has empty required field {'.'.join(path)}")
    for field in ("acceptance_criteria_sha256", "test_matrix_sha256"):
        value = manifest[field]
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(ch not in "0123456789abcdef" for ch in value)
        ):
            raise ManifestError(f"manifest field {field} is not a SHA-256 digest")
    if manifest["mode"] == "release" and manifest["dirty_tree"]:
        raise ManifestError("release-grade measurement refuses a dirty git tree")
    if manifest["mode"] != "release" and manifest["release_evidence_eligible"]:
        raise ManifestError("diagnostic manifest cannot claim release eligibility")


def create_manifest(
    *,
    repo: Path,
    config: dict[str, Any],
    criteria_path: Path,
    matrix_path: Path,
    mode: str,
    n5_closure_path: Path | None,
    correctness_questions_path: Path | None = None,
    measurement_gaps_path: Path | None = None,
) -> dict[str, Any]:
    if mode not in ("diagnostic", "release"):
        raise ManifestError(f"unknown measurement mode {mode}")
    commit = _run_git(repo, "rev-parse", "HEAD")
    tree = _run_git(repo, "rev-parse", "HEAD^{tree}")
    dirty = bool(_run_git(repo, "status", "--porcelain", "--untracked-files=all"))
    if mode == "release":
        if correctness_questions_path is None:
            raise ManifestError("release-grade measurement requires a correctness-question registry")
        validate_open_correctness_questions(correctness_questions_path, release=True)
        if measurement_gaps_path is None:
            raise ManifestError("release-grade measurement requires a measurement-gap registry")
        validate_open_measurement_gaps(measurement_gaps_path, release=True)
        if n5_closure_path is None:
            raise ManifestError(
                f"release-grade measurement refuses commit {commit}: "
                "no N5 closure artifact was supplied for that exact commit"
            )
        validate_n5_closure(n5_closure_path, commit)
        if dirty:
            raise ManifestError("release-grade measurement refuses a dirty git tree")
    elif correctness_questions_path is not None:
        validate_open_correctness_questions(correctness_questions_path, release=False)
    if mode != "release" and measurement_gaps_path is not None:
        validate_open_measurement_gaps(measurement_gaps_path, release=False)

    load_acceptance_criteria(criteria_path, release=mode == "release")

    host = observed_host()
    host.update(config.get("host", {}))
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "run_id": config.get("run_id") or str(uuid.uuid4()),
        "mode": mode,
        "release_evidence_eligible": mode == "release",
        "git_commit": commit,
        "git_tree": tree,
        "dirty_tree": dirty,
        "build": config.get("build", {}),
        "host": host,
        "chain": config.get("chain", {}),
        "network": config.get("network", {}),
        "workload": config.get("workload", {}),
        "resources": config.get("resources", {}),
        "acceptance_criteria_sha256": sha256_file(criteria_path),
        "test_matrix_sha256": sha256_file(matrix_path),
    }
    validate_manifest(manifest)
    validate_manifest_inputs(manifest, criteria_path, matrix_path)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--acceptance-criteria", type=Path, required=True)
    parser.add_argument("--test-matrix", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("diagnostic", "release"), required=True)
    parser.add_argument("--n5-closure", type=Path)
    parser.add_argument("--correctness-questions", type=Path)
    parser.add_argument("--measurement-gaps", type=Path)
    args = parser.parse_args()
    try:
        config = json.loads(args.config.read_text(encoding="utf-8"))
        manifest = create_manifest(
            repo=args.repo.resolve(),
            config=config,
            criteria_path=args.acceptance_criteria,
            matrix_path=args.test_matrix,
            mode=args.mode,
            n5_closure_path=args.n5_closure,
            correctness_questions_path=args.correctness_questions,
            measurement_gaps_path=args.measurement_gaps,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (OSError, json.JSONDecodeError, ManifestError) as exc:
        print(f"MEASUREMENT_MANIFEST_FAILURE: {exc}", file=sys.stderr)
        return 1
    print(f"MEASUREMENT_MANIFEST_OK: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
