"""Freeze C09 A–F run identity. This module makes no acceptance decision."""

from __future__ import annotations

import hashlib
import json
from typing import Any

WORKLOADS = ("normal", "high", "maximum_approved")
NATIVE_STAGES = ("proposal_generation", "vote_intent_commit", "vote_sign", "signed_vote_commit",
                 "vote_local_apply", "vote_broadcast_enqueue", "finality_verify", "storage_ack")
REQUIRED_HASHES = ("source", "binary", "config", "dependencies", "genesis", "workload")
PLAN_FIELDS = {"profiles", "workloads", "warmup_seconds", "window_seconds", "rounds", "order",
               "population", "hashes", "roles", "effective_quotas", "method", "cache_only_path"}
MAX_PLAN_BYTES = 256 * 1024


def expected_profiles(diagnostics: bool) -> dict[str, dict[str, bool]]:
    if type(diagnostics) is not bool:
        raise ValueError("effective diagnostics toggle required")
    return {
        "A": dict(core=False, collection=False, diagnostics=False, ai=False, colocated_ai=False),
        "B": dict(core=True, collection=False, diagnostics=False, ai=False, colocated_ai=False),
        "C": dict(core=True, collection=True, diagnostics=False, ai=False, colocated_ai=False),
        "D": dict(core=True, collection=True, diagnostics=True, ai=False, colocated_ai=False),
        "E": dict(core=True, collection=True, diagnostics=diagnostics, ai=True, colocated_ai=False),
        "F": dict(core=True, collection=True, diagnostics=diagnostics, ai=True, colocated_ai=True),
    }


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 512


def freeze_plan(plan: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(plan, dict) or set(plan) != PLAN_FIELDS:
        raise ValueError("missing or unknown plan field")
    profiles = plan["profiles"]
    if not isinstance(profiles, dict) or set(profiles) != set("ABCDEF"):
        raise ValueError("A-F profiles required")
    try:
        diagnostics = profiles["E"]["diagnostics"]
    except (KeyError, TypeError):
        raise ValueError("E diagnostics toggle required") from None
    if profiles != expected_profiles(diagnostics):
        raise ValueError("profile toggles must be effective and fixed")
    if plan["workloads"] != list(WORKLOADS):
        raise ValueError("workloads changed")
    if type(plan["warmup_seconds"]) is not int or not 1 <= plan["warmup_seconds"] <= 3600:
        raise ValueError("invalid warmup")
    if type(plan["window_seconds"]) is not int or not 1800 <= plan["window_seconds"] <= 3600:
        raise ValueError("invalid 30-minute window")
    if type(plan["rounds"]) is not int or not 3 <= plan["rounds"] <= 10:
        raise ValueError("invalid round count")
    order = plan["order"]
    if not isinstance(order, list) or len(order) != len(WORKLOADS) * plan["rounds"] * 6:
        raise ValueError("incomplete order")
    expected_order = []
    for workload in WORKLOADS:
        previous = None
        for index in range(plan["rounds"]):
            group = [r["profile"] for r in order if isinstance(r, dict) and
                     set(r) == {"profile", "round", "workload"} and
                     r["workload"] == workload and type(r["round"]) is int and r["round"] == index]
            if sorted(group) != sorted(profiles) or group == previous:
                raise ValueError("missing or nonalternating profile round")
            expected_order.extend({"workload": workload, "round": index, "profile": name} for name in group)
            previous = group
    if any(not isinstance(r, dict) or set(r) != {"profile", "round", "workload"} or
           r["workload"] not in WORKLOADS or type(r["round"]) is not int or
           not 0 <= r["round"] < plan["rounds"] or r["profile"] not in profiles for r in order):
        raise ValueError("unexpected schedule entry")
    if order != expected_order:
        raise ValueError("round schedule is not contiguous")
    hashes = plan["hashes"]
    if not isinstance(hashes, dict) or set(hashes) != set(REQUIRED_HASHES) or any(
            type(v) is not str or len(v) != 64 or any(c not in "0123456789abcdef" for c in v)
            for v in hashes.values()):
        raise ValueError("missing or malformed hashes")
    population = plan["population"]
    if not isinstance(population, dict) or set(population) != {"nodes", "scopes"} or any(
            not isinstance(population[k], list) or not population[k] or
            len(population[k]) > 64 or any(not _text(v) for v in population[k])
            for k in ("nodes", "scopes")):
        raise ValueError("invalid population")
    if not isinstance(plan["roles"], dict) or not plan["roles"] or any(
            not _text(k) or not _text(v) for k, v in plan["roles"].items()):
        raise ValueError("missing roles")
    if not isinstance(plan["effective_quotas"], dict) or not plan["effective_quotas"]:
        raise ValueError("missing effective quotas")
    method = plan["method"]
    if not isinstance(method, dict) or set(method) != {"sample_policy", "noise_rule", "instrument_cost", "comparison", "outcome_policy"} or any(not _text(v) for v in method.values()):
        raise ValueError("incomplete method")
    path = plan["cache_only_path"]
    if not isinstance(path, str) or not path.startswith("/") or not 1 < len(path) <= 128 or "?" in path or "#" in path or any(ord(c) < 33 or ord(c) > 126 for c in path):
        raise ValueError("invalid fixed cache-only path")
    body = json.dumps(plan, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(body) > MAX_PLAN_BYTES:
        raise ValueError("plan exceeds bound")
    return {"plan_sha256": hashlib.sha256(body).hexdigest(), "plan": plan}


def empty_run_evidence(profile: str) -> dict[str, Any]:
    if profile not in "ABCDEF" or len(profile) != 1:
        raise ValueError("unknown profile")
    return {"profile": profile, "gate": "not_run", "native_stages": {s: "not_run" for s in NATIVE_STAGES},
            "raw_duration": "not_run", "cpu_regression": "not_run", "p99_regression": "not_run",
            "completed_work": "not_run", "deadline_exceeded": "not_run", "oldest_queue_age": "not_run",
            "typed_progress": "not_run", "max_actor_occupancy": "not_run", "soak_72h": "not_run",
            "resources": {role: "not_run" for role in ("V", "edge", "M", "O", "A")}}
