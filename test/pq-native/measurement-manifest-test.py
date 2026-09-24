#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def fail(message: str) -> None:
    print(f"N6_MANIFEST_FAILURE: {message}", file=sys.stderr)
    raise SystemExit(1)


repo_root = Path(__file__).resolve().parents[2]
module_path = repo_root / "scripts" / "pq_measurement_manifest.py"
spec = importlib.util.spec_from_file_location("pq_measurement_manifest", module_path)
if spec is None or spec.loader is None:
    fail("could not load manifest module")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def run(*args: str, cwd: Path) -> None:
    subprocess.run(
        args, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )


def complete_config() -> dict[str, object]:
    return {
        "run_id": "manifest-contract-test",
        "build": {
            "build_type": "RelWithDebInfo",
            "compiler": "test-compiler",
            "compiler_version": "1",
            "linker": "test-linker",
            "cmake_options": ["TOS_USE_ROCKSDB=ON"],
            "pq_algorithm": "ML-DSA-44",
            "pq_backend_version": "test-backend",
            "n5_carrier_tag": 19,
            "n5_format_version": 1,
        },
        "host": {
            "cgroup_cpu_quota": "unlimited",
            "numa_topology": "node0",
            "allocator": "system",
            "disk_model": "test-disk",
            "filesystem": "ext4",
            "mount_options": "rw",
            "network_nic": "test0",
            "network_link_speed": "1Gbps",
        },
        "chain": {
            "global_id": -239,
            "node_count": 4,
            "masterchain_committee_count": 4,
            "shard_committee_count": 4,
            "validator_pool_count": 4,
            "config_param_16": {
                "max_validators": 400,
                "max_main_validators": 100,
                "min_validators": 4,
            },
            "config_param_28": {"shard_validators_num": 100},
            "config_param_30": {"protocol_version": 2},
            "block_limits": {"bytes": 1},
            "gas_limits": {"gas": 1},
            "collated_data_limits": {"bytes": 1},
        },
        "network": {
            "profile_name": "fixture",
            "latency_matrix_sha256": "a" * 64,
            "jitter": "0ms",
            "loss": "0%",
            "bandwidth_cap": "1Gbps",
        },
        "workload": {
            "profile": "consensus-isolation",
            "warmup_duration_seconds": 1,
            "measurement_duration_seconds": 1,
            "fault_schedule_sha256": "b" * 64,
        },
        "resources": {
            "pending_finality": {
                "maximum_boxed_carrier_bytes": 984_260,
                "public_pool_bytes": 15_748_160,
                "validator_reserved_pool_bytes": 393_704_000,
                "total_pool_bytes": 409_452_160,
                "sender_across_blocks_bytes": 3_937_040,
                "retention_seconds": 60,
                "authority_memo_entries": 8,
            }
        },
    }


def complete_criteria() -> dict[str, object]:
    return {
        "schema_version": 1,
        "release_hardware_profile": "test-hardware",
        "required_scales": [21],
        "required_network_profiles": ["baseline", "launch-wan", "degraded"],
        "required_workloads": ["consensus-isolation", "target-load", "high-load"],
        "max_p99_persisted_finality_ms": 1,
        "max_p99_block_signature_verify_ms": 1,
        "max_p99_lite_verify_ms": 1,
        "max_cpu_fraction": 0.5,
        "max_rss_fraction": 0.5,
        "max_network_fraction": 0.5,
        "max_disk_busy_fraction": 0.5,
        "max_finalization_backpressure_fraction": 0.5,
        "max_pending_finality_bytes": 1,
        "max_pending_finality_candidates": 1,
        "max_authority_classification_p99_ms": 1,
        "max_unbounded_memory_slope_bytes_per_hour": 0,
        "max_finalized_height_stall_ms": 1,
        "safety_violations_allowed": 0,
        "process_crashes_allowed": 0,
        "invalid_proofs_accepted": 0,
    }


with tempfile.TemporaryDirectory(prefix="measurement-manifest-") as raw:
    root = Path(raw)
    run("git", "init", "-q", cwd=root)
    run("git", "config", "user.email", "measurement@example.invalid", cwd=root)
    run("git", "config", "user.name", "Measurement Test", cwd=root)
    (root / "tracked").write_text("clean\n", encoding="utf-8")
    run("git", "add", "tracked", cwd=root)
    run("git", "commit", "-q", "-m", "fixture", cwd=root)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    criteria = root / "criteria.json"
    matrix = root / "matrix.json"
    criteria.write_text(json.dumps(complete_criteria()) + "\n", encoding="utf-8")
    matrix.write_text('{"schema_version":1}\n', encoding="utf-8")
    closure = root / "closure.json"
    closure.write_text(
        json.dumps(
            {
                "status": "CLOSED",
                "commit": commit,
                "gaps": {
                    "validator_manager_actor": True,
                    "crash_restart_cuts": 5,
                    "check_proof_actor": True,
                },
            }
        ),
        encoding="utf-8",
    )
    # Criteria/matrix are measurement inputs, so commit them before the clean
    # release-grade creation.
    run("git", "add", "criteria.json", "matrix.json", "closure.json", cwd=root)
    run("git", "commit", "-q", "-m", "measurement inputs", cwd=root)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    closure.write_text(
        json.dumps(
            {
                "status": "CLOSED",
                "commit": commit,
                "gaps": {
                    "validator_manager_actor": True,
                    "crash_restart_cuts": 5,
                    "check_proof_actor": True,
                },
            }
        ),
        encoding="utf-8",
    )
    run("git", "add", "closure.json", cwd=root)
    run("git", "commit", "-q", "-m", "bind closure", cwd=root)
    # The artifact commits to HEAD, so amend is deliberately avoided: make the
    # final fixture artifact untracked outside the repository and bind to the
    # actual clean commit.
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    closure_external = Path(raw).parent / f"closure-{Path(raw).name}.json"
    closure_external.write_text(
        json.dumps(
            {
                "status": "CLOSED",
                "commit": commit,
                "gaps": {
                    "validator_manager_actor": True,
                    "crash_restart_cuts": 5,
                    "check_proof_actor": True,
                },
            }
        ),
        encoding="utf-8",
    )
    resolved_questions = Path(raw).parent / f"correctness-{Path(raw).name}.json"
    resolved_questions.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "required_question_ids": list(module.REQUIRED_CORRECTNESS_QUESTION_IDS),
                "questions": {
                    "classical-config-vote-tooling-incompatible-with-pq-contract": {
                        "observation": "fixture classical config vote observation",
                        "observed_commit": "7533ab5d9",
                        "location": "fixture-vote.py:1",
                        "closure_condition": "fixture PQ config vote closure condition",
                        "status": "RESOLVED",
                        "resolved_by": "444444444",
                    },
                    "classical-e2e-fixtures-incompatible-with-pq-consensus": {
                        "observation": "fixture classical E2E observation",
                        "observed_commit": "0d9452838",
                        "location": "fixture.py:1",
                        "closure_condition": "fixture PQ E2E closure condition",
                        "status": "RESOLVED",
                        "resolved_by": "111111111",
                    },
                    "classical-stake-producers-incompatible-with-pq-elector": {
                        "observation": "fixture classical stake producer observation",
                        "observed_commit": "5d69c798c",
                        "location": "fixture-stake.py:1",
                        "closure_condition": "fixture PQ stake producer closure condition",
                        "status": "RESOLVED",
                        "resolved_by": "222222222",
                    },
                    "pq-validator-set-installation-parity": {
                        "observation": "fixture validator-set admission mismatch",
                        "observed_commit": "a500f88b0",
                        "location": "fixture-config.fc:1",
                        "closure_condition": "fixture PQ set installation parity closure condition",
                        "status": "RESOLVED",
                        "resolved_by": "666666666",
                    },
                    "pq-unsafe-session-rotation": {
                        "observation": "fixture unsafe rotation observation",
                        "observed_commit": "19f5b3406",
                        "location": "fixture-manager.cpp:1",
                        "closure_condition": "fixture rotation closure condition",
                        "status": "RESOLVED",
                        "resolved_by": "777777777",
                    },
                    "pool-first-stake-birth-witness-missing": {
                        "observation": "fixture pool witness observation",
                        "observed_commit": "717e2879e",
                        "location": "fixture-pool.rs:1",
                        "closure_condition": "fixture first-stake witness closure condition",
                        "status": "RESOLVED",
                        "resolved_by": "555555555",
                    },
                    "merkle-base-state-mismatch": {
                        "observation": "fixture observation",
                        "observed_commit": "efd22ce46",
                        "location": "fixture.cpp:1",
                        "closure_condition": "fixture closure condition",
                        "status": "RESOLVED",
                        "resolved_by": "333333333",
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    resolved_gaps = Path(raw).parent / f"measurement-gaps-{Path(raw).name}.json"
    open_gaps = Path(raw).parent / f"open-measurement-gaps-{Path(raw).name}.json"
    scale_result = Path(raw).parent / f"scale-result-{Path(raw).name}.json"

    invalid_resolution = Path(raw).parent / f"invalid-resolution-{Path(raw).name}.json"
    invalid_resolution_registry = json.loads(resolved_questions.read_text(encoding="utf-8"))
    invalid_resolution_registry["questions"][
        "classical-e2e-fixtures-incompatible-with-pq-consensus"
    ]["resolved_by"] = "trust me"
    invalid_resolution.write_text(json.dumps(invalid_resolution_registry), encoding="utf-8")
    try:
        module.validate_open_correctness_questions(invalid_resolution, release=True)
        fail("a correctness question was resolved without a commit-backed evidence identity")
    except module.ManifestError as exc:
        expected = (
            "resolved correctness question "
            "classical-e2e-fixtures-incompatible-with-pq-consensus has invalid resolved_by commit"
        )
        if expected not in str(exc):
            fail(f"invalid correctness resolution reported the wrong refusal: {exc}")

    open_gaps.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "required_gap_ids": list(module.REQUIRED_MEASUREMENT_GAP_IDS),
                "gaps": {
                    gap_id: {
                        "observation": "fixture observation",
                        "reason": "fixture reason",
                        "closure_condition": "fixture closure condition",
                        "status": "OPEN",
                    }
                    for gap_id in module.REQUIRED_MEASUREMENT_GAP_IDS
                },
            }
        ),
        encoding="utf-8",
    )

    def write_scale_result(*, local_override: bool, release_eligible: bool, scales: list[int]) -> None:
        scale_result.write_text(
            json.dumps(
                {
                    "local_colocation_diagnostic_override": local_override,
                    "release_evidence_eligible": release_eligible,
                    "required_release_scales_measured": scales,
                }
            ),
            encoding="utf-8",
        )

    resolved_gaps.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "required_gap_ids": [
                    "release-scale-matrix-unmeasured",
                    "carrier-scale-transport-unmeasured",
                    "sustained-finality-distribution-unmeasured",
                ],
                "gaps": {
                    "release-scale-matrix-unmeasured": {
                        "observation": "fixture observation",
                        "reason": "fixture reason",
                        "closure_condition": "fixture closure condition",
                        "status": "RESOLVED",
                        "resolved_by": "fixture run evidence",
                        "evidence_results": [str(scale_result)],
                    },
                    "carrier-scale-transport-unmeasured": {
                        "observation": "fixture observation",
                        "reason": "fixture reason",
                        "closure_condition": "fixture closure condition",
                        "status": "RESOLVED",
                        "resolved_by": "fixture run evidence",
                    },
                    "sustained-finality-distribution-unmeasured": {
                        "observation": "fixture observation",
                        "reason": "fixture reason",
                        "closure_condition": "fixture closure condition",
                        "status": "RESOLVED",
                        "resolved_by": "fixture run evidence",
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    try:
        # This branch has a live correctness question.  Check it before every
        # other release precondition so neither a missing N5 artifact nor a dirty
        # developer tree can make this refusal pass for the wrong reason.
        live_questions = repo_root / "doc/pq-native/N6-OPEN-CORRECTNESS-QUESTIONS.json"
        live_gaps = repo_root / "doc/pq-native/N6-OPEN-MEASUREMENT-GAPS.json"
        try:
            module.create_manifest(
                repo=repo_root,
                config=complete_config(),
                criteria_path=criteria,
                matrix_path=matrix,
                mode="release",
                n5_closure_path=None,
                correctness_questions_path=live_questions,
                measurement_gaps_path=live_gaps,
            )
            fail("current branch with an open correctness question was release eligible")
        except module.ManifestError as exc:
            expected = (
                "release-grade measurement refuses open correctness questions: "
                "classical-config-vote-tooling-incompatible-with-pq-contract, "
                "classical-e2e-fixtures-incompatible-with-pq-consensus, "
                "classical-stake-producers-incompatible-with-pq-elector, "
                "merkle-base-state-mismatch"
            )
            if expected not in str(exc):
                fail(f"open correctness registry reported the wrong release refusal: {exc}")

        # With the correctness question resolved, open measurement work is an
        # independent refusal.
        try:
            module.create_manifest(
                repo=repo_root,
                config=complete_config(),
                criteria_path=criteria,
                matrix_path=matrix,
                mode="release",
                n5_closure_path=None,
                correctness_questions_path=resolved_questions,
                measurement_gaps_path=open_gaps,
            )
            fail("current branch with open measurement gaps was release eligible")
        except module.ManifestError as exc:
            expected = (
                "release-grade measurement refuses open measurement gaps: "
                "carrier-scale-transport-unmeasured, release-scale-matrix-unmeasured, "
                "sustained-finality-distribution-unmeasured"
            )
            if expected not in str(exc):
                fail(f"open measurement gaps reported the wrong release refusal: {exc}")

        # A human cannot close the release scale gap by citing the explicit
        # co-located diagnostic escape hatch.
        write_scale_result(local_override=True, release_eligible=False, scales=[4, 7])
        try:
            module.create_manifest(
                repo=repo_root,
                config=complete_config(),
                criteria_path=criteria,
                matrix_path=matrix,
                mode="release",
                n5_closure_path=None,
                correctness_questions_path=resolved_questions,
                measurement_gaps_path=resolved_gaps,
            )
            fail("co-located diagnostic evidence closed the release scale gap")
        except module.ManifestError as exc:
            expected = (
                "release-scale-matrix-unmeasured cannot be resolved by "
                "local_colocation_diagnostic_override evidence"
            )
            if expected not in str(exc):
                fail(f"co-located release-scale evidence reported the wrong refusal: {exc}")

        # Removing the override marker is not sufficient: the result must also
        # be independently eligible for release evidence.
        write_scale_result(local_override=False, release_eligible=False, scales=[21])
        try:
            module.create_manifest(
                repo=repo_root,
                config=complete_config(),
                criteria_path=criteria,
                matrix_path=matrix,
                mode="release",
                n5_closure_path=None,
                correctness_questions_path=resolved_questions,
                measurement_gaps_path=resolved_gaps,
            )
            fail("diagnostic evidence without the override closed the release scale gap")
        except module.ManifestError as exc:
            expected = "release-scale-matrix-unmeasured evidence is not release_evidence_eligible"
            if expected not in str(exc):
                fail(f"diagnostic release-scale evidence reported the wrong refusal: {exc}")

        # Resolving all registered measurement gaps with eligible evidence
        # exposes the next independent refusal, the exact-commit N5 closure.
        write_scale_result(local_override=False, release_eligible=True, scales=[21])
        try:
            module.create_manifest(
                repo=repo_root,
                config=complete_config(),
                criteria_path=criteria,
                matrix_path=matrix,
                mode="release",
                n5_closure_path=None,
                correctness_questions_path=resolved_questions,
                measurement_gaps_path=resolved_gaps,
            )
            fail("current branch without an N5 closure artifact was release eligible")
        except module.ManifestError as exc:
            expected = "no N5 closure artifact was supplied for that exact commit"
            if expected not in str(exc):
                fail(f"current N5-open branch reported the wrong release refusal: {exc}")

        stale_inherited_gaps = Path(raw).parent / f"stale-inherited-gaps-{Path(raw).name}.json"
        stale_registry = json.loads(live_gaps.read_text(encoding="utf-8"))
        stale_registry["gaps"]["carrier-scale-transport-unmeasured"]["depends_on"][
            "tos_enforced_launch_cap"
        ] = 22
        stale_inherited_gaps.write_text(json.dumps(stale_registry), encoding="utf-8")
        try:
            module.create_manifest(
                repo=repo_root,
                config=complete_config(),
                criteria_path=criteria,
                matrix_path=matrix,
                mode="release",
                n5_closure_path=None,
                correctness_questions_path=resolved_questions,
                measurement_gaps_path=stale_inherited_gaps,
            )
            fail("stale inherited-consensus facts closed a measurement gap")
        except module.ManifestError as exc:
            expected = (
                "carrier-scale-transport-unmeasured does not pin the inherited Simplex dependencies"
            )
            if expected not in str(exc):
                fail(f"stale inherited gap evidence reported the wrong refusal: {exc}")

        # The live registry uses the separately reviewed inherited-Simplex
        # closure. It must likewise expose the independent N5 refusal rather
        # than retaining a decorative measurement-gap block.
        try:
            module.create_manifest(
                repo=repo_root,
                config=complete_config(),
                criteria_path=criteria,
                matrix_path=matrix,
                mode="release",
                n5_closure_path=None,
                correctness_questions_path=resolved_questions,
                measurement_gaps_path=live_gaps,
            )
            fail("live inherited evidence bypassed the exact-commit N5 closure")
        except module.ManifestError as exc:
            expected = "no N5 closure artifact was supplied for that exact commit"
            if expected not in str(exc):
                fail(f"live inherited gap closure reported the wrong next refusal: {exc}")

        diagnostic = module.create_manifest(
            repo=repo_root,
            config=complete_config(),
            criteria_path=criteria,
            matrix_path=matrix,
            mode="diagnostic",
            n5_closure_path=None,
            correctness_questions_path=live_questions,
            measurement_gaps_path=live_gaps,
        )
        if diagnostic["release_evidence_eligible"]:
            fail("diagnostic scaffolding claimed release eligibility")

        manifest = module.create_manifest(
            repo=root,
            config=complete_config(),
            criteria_path=criteria,
            matrix_path=matrix,
            mode="release",
            n5_closure_path=closure_external,
            correctness_questions_path=resolved_questions,
            measurement_gaps_path=resolved_gaps,
        )
        module.validate_manifest(manifest)

        missing_commit = dict(manifest)
        missing_commit.pop("git_commit")
        try:
            module.validate_manifest(missing_commit)
            fail("manifest without git_commit was accepted")
        except module.ManifestError as exc:
            if "git_commit" not in str(exc):
                fail(f"missing git commit reported the wrong reason: {exc}")

        missing_criteria = dict(manifest)
        missing_criteria.pop("acceptance_criteria_sha256")
        try:
            module.validate_manifest(missing_criteria)
            fail("manifest without acceptance criteria hash was accepted")
        except module.ManifestError as exc:
            if "acceptance_criteria_sha256" not in str(exc):
                fail(f"missing criteria hash reported the wrong reason: {exc}")

        (root / "dirty-untracked").write_text("dirty\n", encoding="utf-8")
        try:
            module.create_manifest(
                repo=root,
                config=complete_config(),
                criteria_path=criteria,
                matrix_path=matrix,
                mode="release",
                n5_closure_path=closure_external,
                correctness_questions_path=resolved_questions,
                measurement_gaps_path=resolved_gaps,
            )
            fail("release-grade run accepted a dirty tree")
        except module.ManifestError as exc:
            if "dirty git tree" not in str(exc):
                fail(f"dirty tree reported the wrong reason: {exc}")
    finally:
        closure_external.unlink(missing_ok=True)
        resolved_questions.unlink(missing_ok=True)
        resolved_gaps.unlink(missing_ok=True)
        scale_result.unlink(missing_ok=True)

print("N6_MANIFEST_OK: complete manifest and independent correctness, measurement-gap, N5 closure, hash, and dirty-tree refusals")
