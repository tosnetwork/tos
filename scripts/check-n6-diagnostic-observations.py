#!/usr/bin/env python3
"""Keep open N6 diagnostic observations durable without making them release gates."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REQUIRED_OBSERVATION_IDS = frozenset(
    {
        "colocated-lite-query-timeouts",
        "colocated-launch-committee-finalcert-tail",
        "colocated-launch-committee-skip-runs",
    }
)
REQUIRED_FIELDS = {
    "status",
    "observation",
    "observed_at",
    "diagnostic_question",
    "closure_condition",
}


def fail(message: str) -> None:
    raise RuntimeError(f"N6_DIAGNOSTIC_OBSERVATION_FAILURE: {message}")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    path = root / "doc/pq-native/N6-OPEN-DIAGNOSTIC-OBSERVATIONS.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        fail("schema_version must be 1")
    declared = set(payload.get("required_observation_ids", []))
    observations = payload.get("observations")
    if not isinstance(observations, dict):
        fail("observations must be an object")
    present = set(observations)
    if declared != present:
        fail(
            "required ids and observations differ; "
            f"missing={sorted(declared - present)} unexpected={sorted(present - declared)}"
        )
    if declared != REQUIRED_OBSERVATION_IDS:
        fail(
            "compiled required observation set changed; "
            f"missing={sorted(REQUIRED_OBSERVATION_IDS - declared)} "
            f"unexpected={sorted(declared - REQUIRED_OBSERVATION_IDS)}"
        )
    for observation_id, entry in observations.items():
        if not isinstance(entry, dict):
            fail(f"{observation_id} must be an object")
        missing_fields = REQUIRED_FIELDS - set(entry)
        if missing_fields:
            fail(f"{observation_id} is missing fields {sorted(missing_fields)}")
        if entry["status"] not in {"OPEN", "RESOLVED"}:
            fail(f"{observation_id} has invalid status {entry['status']!r}")
        for field in ("observation", "diagnostic_question", "closure_condition"):
            if not isinstance(entry[field], str) or not entry[field].strip():
                fail(f"{observation_id}.{field} must be a non-empty string")
        if entry["status"] == "RESOLVED" and not entry.get("resolved_by"):
            fail(f"resolved observation {observation_id} does not name resolved_by evidence")

    finalcert = observations["colocated-launch-committee-finalcert-tail"]["observed_at"]
    expected_finalcert = {
        "exact_commit": "e586c9dc7",
        "artifact_sha256": "6ccb0fd0c9e4b5f3f6c4d652c7fb6ea42033d23df165e4164d735f4310182cf6",
        "from_height": 698,
        "to_height": 699,
        "observation_interval_ms": 2826.8,
        "first_finalcert_interval_ms": 2751.8,
        "lite_transport_retries": 0,
        "all_nodes_agreed_full_block_id": True,
    }
    for field, expected in expected_finalcert.items():
        if finalcert.get(field) != expected:
            fail(
                "colocated-launch-committee-finalcert-tail changed field "
                f"{field}: expected={expected!r} actual={finalcert.get(field)!r}"
            )

    skip_observation = observations["colocated-launch-committee-skip-runs"]
    observed_at = skip_observation.get("observed_at", {})
    discrepancy = observed_at.get("text_structured_discrepancy_follow_up", {})
    if (
        discrepancy.get("measurement_status") != "AMBIGUOUS_TEXT_VS_STRUCTURED"
        or discrepancy.get("masterchain_skip_vote_text_lines") != 576
        or discrepancy.get("structured_skip_vote_events") != 0
        or len(discrepancy.get("possible_readings", [])) != 2
    ):
        fail(
            "colocated-launch-committee-skip-runs no longer retains the unresolved "
            "576-text-versus-zero-structured-event discrepancy and both possible readings"
        )
    committee_follow_up = observed_at.get("committee_wide_structured_follow_up", {})
    if (
        committee_follow_up.get("slow_intervals_coincident_with_skip_run") != 0
        or committee_follow_up.get("ordinary_intervals_coincident_with_skip_run") != 3
        or committee_follow_up.get("skip_run_lengths") != [1, 2, 3]
    ):
        fail(
            "colocated-launch-committee-skip-runs no longer records that measured "
            "skip runs and slow intervals were disjoint"
        )
    semantics = observed_at.get("text_semantics_follow_up", {})
    expected_semantics = {
        "status": "LOCAL_CAST_INVARIANT_CONFIRMED_ON_FRESH_RUN",
        "result_artifact_sha256": "6ccb0fd0c9e4b5f3f6c4d652c7fb6ea42033d23df165e4164d735f4310182cf6",
        "site_audit_sha256": "f77311000a3303a58578fc9abb4ccecaea5b6cd8a945592ad1f6ca1c0e25ff83",
        "text_lines_by_site": {
            "local_broadcast_vote_request": 233,
            "local_cast_trace_event": 233,
            "local_vote_persistence": 466,
            "certificate_or_other_diagnostic": 561,
        },
        "structured_local_cast_events": 222,
        "local_casts_after_structured_horizon": 11,
        "local_cast_to_structured_one_to_one_within_horizon": True,
        "raw_skipvote_substring_count_eligible_as_vote_evidence": False,
    }
    for field, expected in expected_semantics.items():
        if semantics.get(field) != expected:
            fail(
                "colocated-launch-committee-skip-runs changed SkipVote evidence field "
                f"{field}: expected={expected!r} actual={semantics.get(field)!r}"
            )
    if "LOST_TO_ENVIRONMENT_CLEANUP" not in semantics.get("original_soak3_artifact", ""):
        fail("the lost soak3 source artifact is no longer disclosed")
    print(
        "N6_DIAGNOSTIC_OBSERVATIONS_OK: "
        f"validated {len(observations)} durable diagnostic observation"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
