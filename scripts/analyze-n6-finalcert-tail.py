#!/usr/bin/env python3
"""Join one agreed-block FinalCert tail to Simplex stages and node resources."""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path


def stage(event: dict, slot: int, previous_slot: int, final_slot: int) -> str | None:
    kind = event.get("@type")
    vote = event.get("vote", {})
    event_slot = event.get("id", {}).get("slot") if isinstance(event.get("id"), dict) else None
    if isinstance(vote, dict) and vote:
        event_slot = vote.get("id", {}).get("slot") if isinstance(vote.get("id"), dict) else vote.get("slot")
    if kind == "consensus.simplex.stats.certObserved" and vote.get("@type") == "consensus.simplex.finalizeVote":
        if event_slot == previous_slot:
            return "previous_finalcert"
        if event_slot == final_slot:
            return "target_finalcert"
    if event_slot == slot:
        if kind in {"consensus.stats.candidateReceived", "consensus.stats.validationStarted", "consensus.stats.validationFinished", "consensus.stats.blockAccepted"}:
            return kind.rsplit(".", 1)[-1]
        if kind == "consensus.simplex.stats.voted" and vote.get("@type") == "consensus.simplex.notarizeVote":
            return "notarize_vote_attempt"
        if kind == "consensus.simplex.stats.certObserved" and vote.get("@type") == "consensus.simplex.notarizeVote":
            return "notarize_certificate"
    return None


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, round((len(ordered) - 1) * fraction))], 3)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--height", type=int, required=True)
    args = parser.parse_args()
    root = args.artifact
    result = json.loads((root / "result.json").read_text())
    heights = result["sustained_observation"]["timing_split"]["per_height"]
    prior = heights[str(args.height - 1)]["consensus"]
    target = heights[str(args.height)]["consensus"]
    if prior["session_id"] != target["session_id"]:
        raise RuntimeError("FinalCert tail crosses Simplex sessions")
    session = target["session_id"]
    per_node: dict[str, dict[str, float]] = {}
    skip_certificates: dict[str, dict[int, float]] = {}
    resources: dict[str, dict[str, float | int | None]] = {}
    for node_dir in sorted((root / "network").glob("node*")):
        log = node_dir / "session-logs"
        if not log.is_file():
            continue
        stages: dict[str, float] = {}
        node_skips: dict[int, float] = {}
        for line in log.read_text().splitlines():
            batch = json.loads(line)
            if batch.get("@type") != "consensus.stats.events" or batch.get("id") != session:
                continue
            for item in batch.get("events", []):
                event = item.get("event", {})
                vote = event.get("vote", {})
                if (event.get("@type") == "consensus.simplex.stats.certObserved"
                        and isinstance(vote, dict)
                        and vote.get("@type") == "consensus.simplex.skipVote"
                        and isinstance(vote.get("slot"), int)
                        and isinstance(item.get("ts"), (int, float))
                        and target["candidate_slot"] <= vote["slot"] <= target["finalizing_candidate_slot"]):
                    node_skips[vote["slot"]] = min(float(item["ts"]), node_skips.get(vote["slot"], float("inf")))
                name = stage(event, target["candidate_slot"], prior["finalizing_candidate_slot"], target["finalizing_candidate_slot"])
                if name is not None and isinstance(item.get("ts"), (int, float)):
                    stages[name] = min(float(item["ts"]), stages.get(name, float("inf")))
        if not stages:
            continue
        per_node[node_dir.name] = stages
        skip_certificates[node_dir.name] = node_skips
        sample_path = node_dir / "n6-resource.jsonl"
        if sample_path.is_file() and "previous_finalcert" in stages and "target_finalcert" in stages:
            low, high = stages["previous_finalcert"], stages["target_finalcert"]
            samples = [json.loads(line) for line in sample_path.read_text().splitlines() if line]
            samples = [sample for sample in samples if low <= sample.get("wall_unix_ns", 0) / 1e9 <= high]
            if len(samples) >= 2:
                resources[node_dir.name] = {
                    "samples": len(samples),
                    "cpu_ticks_delta": samples[-1]["cpu_ticks"] - samples[0]["cpu_ticks"],
                    "rss_kib_max": max(int(sample["status"]["VmRSS"].split()[0]) for sample in samples),
                    "write_bytes_delta": int(samples[-1]["io"].split("write_bytes: ")[1].splitlines()[0]) - int(samples[0]["io"].split("write_bytes: ")[1].splitlines()[0]),
                }
    transitions = [
        ("previous_finalcert", "candidateReceived"),
        ("candidateReceived", "validationStarted"),
        ("validationStarted", "validationFinished"),
        ("validationFinished", "notarize_vote_attempt"),
        ("notarize_vote_attempt", "notarize_certificate"),
        ("notarize_certificate", "target_finalcert"),
    ]
    stage_deltas = {}
    for before, after in transitions:
        values = [(stages[after] - stages[before]) * 1000 for stages in per_node.values() if before in stages and after in stages]
        stage_deltas[f"{before}_to_{after}_ms"] = {
            "nodes": len(values), "min": percentile(values, 0),
            "median": round(statistics.median(values), 3) if values else None,
            "max": percentile(values, 1),
        }
    output = {
        "evidence_class": "COLOCATED_DIAGNOSTIC_ONLY",
        "height": args.height,
        "session_id": session,
        "candidate_slot": target["candidate_slot"],
        "finalizing_candidate_slot": target["finalizing_candidate_slot"],
        "stage_deltas": stage_deltas,
        "node_2_stages_unix_s": per_node.get("node2"),
        "skip_certificate_slots": sorted({slot for slots in skip_certificates.values() for slot in slots}),
        "skip_certificate_observers_per_slot": {
            str(slot): sum(slot in slots for slots in skip_certificates.values())
            for slot in sorted({slot for slots in skip_certificates.values() for slot in slots})
        },
        "resource_window": {
            "nodes_sampled": len(resources),
            "cpu_ticks_delta_range": [min((v["cpu_ticks_delta"] for v in resources.values()), default=None), max((v["cpu_ticks_delta"] for v in resources.values()), default=None)],
            "rss_kib_max": max((v["rss_kib_max"] for v in resources.values()), default=None),
            "write_bytes_delta_range": [min((v["write_bytes_delta"] for v in resources.values()), default=None), max((v["write_bytes_delta"] for v in resources.values()), default=None)],
            "node_2": resources.get("node2"),
        },
    }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
