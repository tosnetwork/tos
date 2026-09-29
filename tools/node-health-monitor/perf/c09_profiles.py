"""Frozen A–F C09 run plans and conservative evidence classification."""

from __future__ import annotations

import hashlib
import json
from typing import Any


PROFILES = {
    "A": {"core": False, "collection": False, "diagnostics": False, "ai": False, "colocated_ai": False},
    "B": {"core": True, "collection": False, "diagnostics": False, "ai": False, "colocated_ai": False},
    "C": {"core": True, "collection": True, "diagnostics": False, "ai": False, "colocated_ai": False},
    "D": {"core": True, "collection": True, "diagnostics": True, "ai": False, "colocated_ai": False},
    "E": {"core": True, "collection": True, "diagnostics": None, "ai": True, "colocated_ai": False},
    "F": {"core": True, "collection": True, "diagnostics": None, "ai": True, "colocated_ai": True},
}
WORKLOADS = ("normal", "high", "maximum_approved")
NATIVE_STAGES = ("proposal_generation", "vote_intent_commit", "vote_sign", "signed_vote_commit",
                 "vote_local_apply", "vote_broadcast_enqueue", "finality_verify", "storage_ack")
REQUIRED_HASHES = ("source", "binary", "config", "dependencies", "genesis", "workload")


def freeze_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Validate a proposed plan and return its content hash before any run."""
    if set(plan) != {"profiles", "workloads", "warmup_seconds", "window_seconds", "rounds",
                     "order", "population", "hashes", "roles", "effective_quotas", "method"}:
        raise ValueError("missing or unknown plan field")
    if plan["profiles"] != PROFILES or tuple(plan["workloads"]) != WORKLOADS:
        raise ValueError("A-F profiles or workloads changed")
    if type(plan["warmup_seconds"]) is not int or plan["warmup_seconds"] <= 0:
        raise ValueError("warmup must be frozen positive seconds")
    if type(plan["window_seconds"]) is not int or plan["window_seconds"] < 1800:
        raise ValueError("measurement window below 30 minutes")
    if type(plan["rounds"]) is not int or plan["rounds"] < 3:
        raise ValueError("fewer than three rounds")
    order = plan["order"]
    if not isinstance(order, list) or len(order) != len(WORKLOADS) * plan["rounds"] * len(PROFILES):
        raise ValueError("incomplete run order")
    for workload in WORKLOADS:
        previous_group = None
        for round_index in range(plan["rounds"]):
            group = [row["profile"] for row in order if row.get("workload") == workload and row.get("round") == round_index]
            if sorted(group) != sorted(PROFILES):
                raise ValueError("missing profile in workload round")
            if group == previous_group:
                raise ValueError("rounds are not alternating")
            previous_group = group
    hashes = plan["hashes"]
    if set(hashes) != set(REQUIRED_HASHES) or any(not isinstance(v, str) or len(v) != 64 or
                                                   any(c not in "0123456789abcdef" for c in v) for v in hashes.values()):
        raise ValueError("missing or malformed source/config hashes")
    if not isinstance(plan["population"], dict) or not plan["population"].get("nodes") or not plan["population"].get("scopes"):
        raise ValueError("missing population")
    if not isinstance(plan["roles"], dict) or not isinstance(plan["effective_quotas"], dict) or not plan["effective_quotas"]:
        raise ValueError("missing roles or effective quotas")
    method = plan["method"]
    if not isinstance(method, dict) or not all(method.get(k) for k in ("sample_policy", "noise_rule", "instrument_cost", "comparison")):
        raise ValueError("incomplete statistical method")
    body = json.dumps(plan, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return {"plan_sha256": hashlib.sha256(body).hexdigest(), "plan": plan}


def empty_run_evidence(profile: str) -> dict[str, Any]:
    if profile not in PROFILES:
        raise ValueError("unknown profile")
    return {"profile": profile, "gate": "not_run", "native_stages": {stage: "not_run" for stage in NATIVE_STAGES},
            "raw_duration": "not_run", "cpu_regression": "not_run", "p99_regression": "not_run",
            "completed_work": "not_run", "deadline_exceeded": "not_run", "oldest_queue_age": "not_run",
            "typed_progress": "not_run", "max_actor_occupancy": "not_run", "soak_72h": "not_run"}


def classify_comparison(*, real_node: bool, rounds: int, window_seconds: int,
                        samples: int, dropped: int, resolution_sufficient: bool,
                        noise_sufficient: bool, cpu_regression: float | None,
                        p99_regression: float | None, native_stage_verified: bool,
                        resources_complete: bool, work_complete: bool) -> str:
    if not real_node:
        return "not_run"
    if (rounds < 3 or window_seconds < 1800 or samples <= 0 or dropped or
            not resolution_sufficient or not noise_sufficient or not native_stage_verified or
            not resources_complete or not work_complete):
        return "inconclusive"
    if cpu_regression is None or p99_regression is None:
        return "inconclusive"
    if not all(isinstance(v, (int, float)) and v == v and abs(v) != float("inf")
               for v in (cpu_regression, p99_regression)):
        return "inconclusive"
    if cpu_regression > 0.01 or p99_regression > 0.03:
        return "fail"
    return "eligible_for_supervisor_review"
