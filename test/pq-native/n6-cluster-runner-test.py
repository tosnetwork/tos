#!/usr/bin/env python3
"""Fast contract gate for the N6.3 orchestrator and backend format."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/tostester/src"))

from tostester.n6_cluster import (  # noqa: E402
    ObservedBlock,
    SustainedObservationConfig,
    _is_lite_transport_error,
    _masterchain_heights,
    _resource_monitor,
    _simplex_session_log_paths,
    _structured_masterchain_timing,
    _sustained_timing_split,
    _wait_all_heights,
    analyze_consensus_milestones,
    analyze_live_finality,
    analyze_simplex_skip_runs,
    block_id_text,
    load_latency_profile,
    observe_sustained_consensus,
    require_agreed_masterchain_block,
    summarize_sustained_observation,
    validate_latency_backend,
    validate_lite_transport_source,
    validate_node_isolation,
)
from tostester.process_backend import LocalProcessBackend, RemoteCommandBackend  # noqa: E402


class ToslibError(Exception):
    __module__ = "toslib.toslibjson"

    def __init__(self, result):
        super().__init__()
        self.result = result

    @property
    def code(self):
        return self.result.code

    def __str__(self):
        return self.result.message


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def event(node: str, trace: str, stage: str, monotonic: int, wall: int, size: int | None = None):
    result = {
        "kind": "trace",
        "node_id": node,
        "trace_id": trace,
        "stage": stage,
        "monotonic_ns": monotonic,
        "wall_unix_ns": wall,
    }
    if size is not None:
        result["exact_bytes"] = size
    return result


async def check_backends(directory: Path) -> None:
    local = LocalProcessBackend()
    process = await local.spawn(
        "node-1", "/bin/sh", ["-c", "printf local"], directory, os.environ, capture_stdout=True
    )
    stdout, _ = await process.communicate()
    require(
        process.returncode == 0 and stdout == b"local",
        "local process backend did not execute the requested command",
    )
    remote = RemoteCommandBackend({"node-1": [sys.executable, "-m", "tostester.remote_process"]})
    process = await remote.spawn(
        "node-1", "/bin/sh", ["-c", "printf remote"], directory, os.environ, capture_stdout=True
    )
    stdout, _ = await process.communicate()
    require(
        process.returncode == 0 and stdout == b"remote",
        "remote-command backend did not execute the requested command",
    )
    require(
        local.manifest() == {"kind": "local-process"},
        "local process backend manifest changed",
    )
    require(
        remote.manifest()
        == {
            "kind": "remote-command",
            "nodes": ["node-1"],
            "provisioning": "external",
        },
        "remote-command backend manifest changed",
    )


class FakeBlockClient:
    def __init__(
        self,
        root_hash: bytes,
        *,
        height: int = 7,
        info_transport_failures: int | None = 0,
    ):
        self.root_hash = root_hash
        self.height = height
        self.info_transport_failures = info_transport_failures
        self.info_calls = 0
        self.lookup_calls = 0

    def _transport_failure(self):
        return ToslibError(
            SimpleNamespace(
                code=500,
                message="LITE_SERVER_NETWORKtimeout for adnl query query",
            )
        )

    async def get_masterchain_info(self):
        self.info_calls += 1
        if self.info_transport_failures is None:
            raise self._transport_failure()
        if self.info_transport_failures > 0:
            self.info_transport_failures -= 1
            raise self._transport_failure()
        return SimpleNamespace(last=SimpleNamespace(seqno=self.height))

    async def lookup_block(self, *, workchain: int, shard: int, seqno: int):
        self.lookup_calls += 1
        return SimpleNamespace(
            workchain=workchain,
            shard=shard,
            seqno=seqno,
            root_hash=self.root_hash,
            file_hash=bytes([seqno]) * 32,
        )


class ScriptedBlockClient(FakeBlockClient):
    def __init__(self, root_hash: bytes, height_outcomes: list[int | None]):
        super().__init__(root_hash)
        self.height_outcomes = iter(height_outcomes)

    async def get_masterchain_info(self):
        self.info_calls += 1
        outcome = next(self.height_outcomes)
        if outcome is None:
            raise self._transport_failure()
        return SimpleNamespace(last=SimpleNamespace(seqno=outcome))


class FakeNode:
    def __init__(self, name: str, client: FakeBlockClient):
        self.name = name
        self.client = client

    async def toslib_client(self):
        return self.client


async def check_sustained_agreement() -> None:
    canonical = bytes.fromhex("11" * 32)
    clients = {name: FakeBlockClient(canonical) for name in ("node-a", "node-b", "node-c")}
    block_id = await require_agreed_masterchain_block(clients, 7)
    require(",7):" in block_id, "agreed block id does not identify the requested height")

    clients["node-c"] = FakeBlockClient(bytes.fromhex("22" * 32))
    calls_before_disagreement = {name: client.lookup_calls for name, client in clients.items()}
    try:
        await require_agreed_masterchain_block(clients, 7)
    except RuntimeError as error:
        require(
            "block-id disagreement at height 7" in str(error),
            "block disagreement refusal does not name its height",
        )
        require(
            "node-a=" in str(error) and "node-c=" in str(error),
            "block disagreement refusal does not name the conflicting nodes",
        )
    else:
        raise AssertionError("nodes on different masterchain blocks were reported as agreeing")
    require(
        all(
            client.lookup_calls == calls_before_disagreement[name] + 1
            for name, client in clients.items()
        ),
        "block-id disagreement was retried instead of failing immediately",
    )


async def check_sustained_transport_retry() -> None:
    flaky = FakeBlockClient(bytes.fromhex("11" * 32), info_transport_failures=1)
    healthy = FakeBlockClient(bytes.fromhex("11" * 32))
    retry_counts: dict[str, dict[str, int]] = {}
    heights = await _masterchain_heights(
        {"flaky-node": flaky, "healthy-node": healthy},
        transport_retry_counts=retry_counts,
        transport_retry_budget_seconds=1.0,
        transport_retry_delay_seconds=0,
    )
    require(
        heights == {"flaky-node": 7, "healthy-node": 7} and flaky.info_calls == 2,
        "one transport timeout did not recover inside the retry budget",
    )
    require(
        retry_counts == {"flaky-node": {"get_masterchain_info": 1}},
        "recovered transport timeout was not counted by node and operation",
    )

    wrong_code = ToslibError(
        SimpleNamespace(code=400, message="LITE_SERVER_NETWORKtimeout for adnl query query")
    )
    require(
        not _is_lite_transport_error(wrong_code),
        "lite transport classifier ignored the production status code",
    )

    silent = FakeBlockClient(bytes.fromhex("11" * 32), info_transport_failures=None)
    try:
        await _masterchain_heights(
            {"silent-node": silent},
            transport_retry_budget_seconds=0,
            transport_retry_delay_seconds=0,
        )
    except TimeoutError as error:
        require("silent-node" in str(error), "transport exhaustion did not name the silent node")
        require(
            "transport retry budget" in str(error),
            "transport exhaustion was not classified as a transport failure",
        )
    else:
        raise AssertionError("persistent lite transport failure was accepted")

    class InvalidReplyClient:
        def __init__(self):
            self.calls = 0

        async def get_masterchain_info(self):
            self.calls += 1
            raise ValueError("invalid lite reply")

    invalid = InvalidReplyClient()
    try:
        await _masterchain_heights(
            {"invalid-node": invalid},
            transport_retry_budget_seconds=1.0,
            transport_retry_delay_seconds=0,
        )
    except ValueError as error:
        require(str(error) == "invalid lite reply", "non-transport error identity changed")
        require(invalid.calls == 1, "non-transport error was retried")
    else:
        raise AssertionError("non-transport lite error was accepted")


async def check_startup_transport_retry() -> None:
    client = FakeBlockClient(bytes.fromhex("11" * 32), info_transport_failures=1)
    retry_counts = {"startup-node": {"get_masterchain_info": 0}}
    heights = await _wait_all_heights(
        [FakeNode("startup-node", client)],
        minimum=7,
        timeout=1.0,
        transport_retry_counts=retry_counts,
        transport_retry_budget_seconds=1.0,
        transport_retry_delay_seconds=0,
    )
    require(heights == [7], "startup height wait did not recover from a transport timeout")
    require(
        retry_counts == {"startup-node": {"get_masterchain_info": 1}},
        "startup height wait did not expose its transport retry",
    )


async def check_resource_monitor_terminal_record(directory: Path) -> None:
    output = directory / "resource-monitor.jsonl"
    node = SimpleNamespace(name="node-a", process_id=12345)
    with patch.object(Path, "read_text", side_effect=PermissionError("proc io denied")):
        await _resource_monitor(node, output, asyncio.Event())
    records = [json.loads(line) for line in output.read_text().splitlines()]
    require(
        len(records) == 1,
        "resource monitor did not write exactly one terminal record",
    )
    require(
        records[0]["kind"] == "resource_monitor_stopped"
        and records[0]["reason"] == "PermissionError"
        and records[0]["detail"] == "proc io denied"
        and isinstance(records[0]["monotonic_ns"], int)
        and isinstance(records[0]["wall_unix_ns"], int),
        "resource monitor did not record why proc sampling stopped",
    )


async def check_observer_retry_window_composition() -> None:
    config = SustainedObservationConfig(
        blocks=2,
        seconds=None,
        target_block_rate_ms=400,
        slow_interval_factor=3.0,
    )

    async def observe(outcomes: list[int | None]):
        client = ScriptedBlockClient(bytes.fromhex("11" * 32), outcomes)
        return await observe_sustained_consensus(
            [FakeNode("observer-node", client)], config, "zerostate-block-id"
        )

    pre_window = await observe([None, 5, 6, 7])
    require(
        pre_window["lite_transport_retries"]["total"] == 1,
        "pre-window observer retry was not retained in the total",
    )
    require(
        not pre_window["observation_interval_distribution_ms"][
            "includes_catch_up_after_transport_retry"
        ],
        "pre-window observer retry leaked into the interval catch-up flag",
    )

    in_window = await observe([5, None, 6, 7])
    require(
        in_window["lite_transport_retries"]["total"] == 1,
        "in-window observer retry was not retained in the total",
    )
    require(
        in_window["observation_interval_distribution_ms"][
            "includes_catch_up_after_transport_retry"
        ],
        "in-window observer retry did not set the interval catch-up flag",
    )


def check_sustained_summary() -> None:
    config = SustainedObservationConfig(
        blocks=2,
        seconds=None,
        target_block_rate_ms=400,
        slow_interval_factor=3.0,
    )
    summary = summarize_sustained_observation(
        config=config,
        start_height=5,
        observed=[
            ObservedBlock(5, "block-5", 0),
            ObservedBlock(6, "block-6", 400_000_000),
            ObservedBlock(7, "block-7", 1_700_000_000),
        ],
        per_node_final_height={"node-a": 7, "node-b": 8},
        checked_from_height=0,
        agreed_block_ids={5: "block-5", 6: "block-6", 7: "block-7"},
        transport_retry_counts={
            "node-a": {"get_masterchain_info": 1, "lookup_block": 2},
            "node-b": {"get_masterchain_info": 0, "lookup_block": 0},
        },
    )
    require(summary["masterchain_blocks_produced"] == 2, "produced block count changed")
    require(
        summary["per_node_final_height"] == {"node-a": 7, "node-b": 8},
        "per-node final heights were not retained",
    )
    require(
        summary["lite_transport_retries"]
        == {
            "total": 3,
            "per_node_operation": {
                "node-a": {"get_masterchain_info": 1, "lookup_block": 2},
                "node-b": {"get_masterchain_info": 0, "lookup_block": 0},
            },
        },
        "lite transport retries were not retained by node and operation",
    )
    require(
        summary["agreement"]["same_block_per_height"] is True,
        "same-block-per-height agreement was not recorded",
    )
    require(
        summary["agreement"]["checked_through_height"] == 7,
        "agreement range does not reach the final observed height",
    )
    require(
        summary["observation_interval_distribution_ms"]
        == {
            "count": 2,
            "minimum": 400.0,
            "p50": 400.0,
            "p95": 1300.0,
            "maximum": 1300.0,
            "transport_retries_during_observation": 3,
            "includes_catch_up_after_transport_retry": True,
        },
        "sustained observation interval distribution changed",
    )
    require(
        summary["slow_observation_intervals"]
        == [{"from_height": 6, "to_height": 7, "observation_interval_ms": 1300.0}],
        "slow observation interval was not retained individually",
    )
    require(
        summary["release_evidence_eligible"] is False,
        "co-located sustained observation became release eligible",
    )
    pre_window_retry_summary = summarize_sustained_observation(
        config=config,
        start_height=5,
        observed=[
            ObservedBlock(5, "block-5", 0),
            ObservedBlock(6, "block-6", 400_000_000),
            ObservedBlock(7, "block-7", 800_000_000),
        ],
        per_node_final_height={"node-a": 7},
        checked_from_height=0,
        transport_retry_counts={"node-a": {"get_masterchain_info": 3}},
        interval_retry_baseline=3,
    )
    require(
        pre_window_retry_summary["lite_transport_retries"]["total"] == 3
        and not pre_window_retry_summary["observation_interval_distribution_ms"][
            "includes_catch_up_after_transport_retry"
        ],
        "a pre-window retry incorrectly marked the interval distribution as catch-up",
    )


def check_simplex_skip_run_correlation(directory: Path) -> None:
    session_id = "simplex-masterchain-session"
    candidates = ((10, 100), (11, 113), (12, 114), (13, 120))
    validator_names = ["node-a", "node-b", "node-c", "node-d"]
    selected_logs = _simplex_session_log_paths(
        [
            *[
                SimpleNamespace(name=name, session_log_path=directory / f"{name}-session.jsonl")
                for name in validator_names
            ],
            SimpleNamespace(name="observer", session_log_path=directory / "missing-observer-log"),
        ],
        validator_names,
    )
    require(
        set(selected_logs) == set(validator_names) and "observer" not in selected_logs,
        "non-validating verifier was incorrectly required to have a Simplex session log",
    )
    node_skip_slots = {
        "node-a": list(range(101, 113)) + list(range(115, 120)),
        "node-b": list(range(101, 111)) + list(range(115, 119)),
        "node-c": list(range(103, 111)) + list(range(116, 119)),
        "node-d": list(range(105, 111)) + [117],
        "observer": [],
    }

    def candidate_id(slot: int) -> dict[str, object]:
        return {"@type": "consensus.candidateId", "slot": slot, "hash": f"hash-{slot}"}

    def timestamped(event_value: dict[str, object]) -> dict[str, object]:
        return {"@type": "consensus.stats.timestampedEvent", "ts": 1.0, "event": event_value}

    logs: dict[str, Path] = {}
    for index, node_name in enumerate([*validator_names, "observer"]):
        events = [
            timestamped(
                {
                    "@type": "consensus.stats.id",
                    "workchain": -1,
                    "idx": index if node_name != "observer" else -1,
                    "total_validators": 4,
                    "slots_per_leader_window": 4,
                }
            )
        ]
        for height, slot in candidates:
            events.extend(
                (
                    timestamped(
                        {
                            "@type": "consensus.stats.candidateReceived",
                            "id": candidate_id(slot),
                            "block": {
                                "@type": "consensus.stats.block",
                                "id": {"workchain": -1, "seqno": height},
                            },
                        }
                    ),
                    timestamped(
                        {"@type": "consensus.stats.blockAccepted", "id": candidate_id(slot)}
                    ),
                )
            )
        events.extend(
            timestamped(
                {
                    "@type": "consensus.simplex.stats.voted",
                    "vote": {"@type": "consensus.simplex.skipVote", "slot": slot},
                }
            )
            for slot in node_skip_slots[node_name]
        )
        path = directory / f"{node_name}-session.jsonl"
        path.write_text(
            json.dumps({"@type": "consensus.stats.events", "id": session_id, "events": events})
            + "\n",
            encoding="utf-8",
        )
        logs[node_name] = path

    observed = [
        ObservedBlock(10, "block-10", 0),
        ObservedBlock(11, "block-11", 1_300_000_000),
        ObservedBlock(12, "block-12", 2_600_000_000),
        ObservedBlock(13, "block-13", 3_000_000_000),
    ]
    intervals = [
        {
            "from_height": previous.height,
            "to_height": current.height,
            "observation_interval_ms": (
                current.observed_monotonic_ns - previous.observed_monotonic_ns
            )
            / 1_000_000,
        }
        for previous, current in zip(observed, observed[1:], strict=False)
    ]
    evidence = analyze_simplex_skip_runs(logs, intervals, validator_names)
    require(evidence["run_count"] == 2, "structured skip votes were not grouped into two runs")
    require(
        [run["length"] for run in evidence["runs"]] == [12, 5],
        "skip-run lengths did not retain every distinct skipped slot",
    )
    require(
        evidence["skip_votes_per_node"]
        == {"node-a": 17, "node-b": 14, "node-c": 11, "node-d": 7, "observer": 0},
        "per-node skip-vote spread was averaged or lost",
    )
    require(
        [item["slot"] for item in evidence["skip_slots_per_node"]["node-b"]]
        == [*range(101, 111), *range(115, 119)]
        and evidence["skip_slots_per_node"]["observer"] == [],
        "per-node skipped slots were replaced by a committee aggregate",
    )
    require(
        evidence["runs"][0]["leaders"][0]
        == {"slot": 101, "leader_index": 1, "leader_node": "node-b"}
        and evidence["runs"][0]["leaders"][-1]
        == {"slot": 112, "leader_index": 0, "leader_node": "node-a"},
        "skip slots were not attributed to the production leader schedule",
    )
    summary = summarize_sustained_observation(
        config=SustainedObservationConfig(
            blocks=3,
            seconds=None,
            target_block_rate_ms=400,
            slow_interval_factor=3.0,
        ),
        start_height=10,
        observed=observed,
        per_node_final_height={name: 13 for name in logs},
        checked_from_height=0,
        simplex_skip_evidence=evidence,
    )
    slow = summary["slow_observation_intervals"]
    require(
        [(item["from_height"], item["coincides_with_skip_run"]) for item in slow]
        == [(10, True), (11, False)],
        "slow intervals were not independently correlated with committee-wide skip runs",
    )
    require(
        summary["observation_intervals"][2]["coincides_with_skip_run"] is True
        and summary["observation_intervals"][2]["observation_interval_ms"] == 400.0,
        "a skip run without a flagged slow interval was not retained",
    )

    blind_logs: dict[str, Path] = {}
    for node_name, path in logs.items():
        batches = [json.loads(line) for line in path.read_text().splitlines()]
        for batch in batches:
            batch["events"] = [
                timestamped_event
                for timestamped_event in batch["events"]
                if timestamped_event.get("event", {}).get("vote", {}).get("@type")
                != "consensus.simplex.skipVote"
            ]
        blind_path = directory / f"blind-{node_name}-session.jsonl"
        blind_path.write_text(
            "\n".join(json.dumps(batch) for batch in batches) + "\n", encoding="utf-8"
        )
        blind_logs[node_name] = blind_path
    unavailable = analyze_simplex_skip_runs(blind_logs, intervals, validator_names)
    require(
        unavailable["analysis_available"] is False
        and unavailable["run_count"] is None
        and unavailable["skip_votes_per_node"] is None,
        "a skip-blind structured channel reported a measured zero",
    )
    require(
        "consensus.simplex.stats.voted(skipVote)" in unavailable["reason"]
        and "cannot distinguish zero cast skip votes from absent skip telemetry"
        in unavailable["reason"]
        and all(
            item["coincides_with_skip_run"] is None for item in unavailable["interval_correlations"]
        ),
        "skip telemetry blind spot did not name its missing event types",
    )


def check_latency_profile_binding() -> None:
    launch = load_latency_profile(ROOT / "test/pq-native/n6-scale-profiles/launch-default.json")
    for manifest in (
        LocalProcessBackend().manifest(),
        {"kind": "remote-command"},
    ):
        try:
            validate_latency_backend(launch, manifest)
        except ValueError as error:
            if "declares the applied network profile" not in str(error):
                raise AssertionError(
                    f"unbound launch latency profile reported the wrong refusal: {error}"
                ) from error
        else:
            raise AssertionError(
                f"backend without an applied network profile was accepted: {manifest}"
            )
    validate_latency_backend(
        launch,
        {"kind": "remote-command", "network_profile": "launch-default"},
    )


def check_sustained_timing_split(directory: Path) -> None:
    session = "masterchain-session"
    nodes = ("node-a", "node-b")
    agreed: dict[int, str] = {}
    logs: dict[str, Path] = {}

    def candidate_for_height(height: int) -> dict[str, object]:
        return {
            "@type": "consensus.candidateId",
            "slot": height,
            "hash": base64.b64encode(bytes([height + 20]) * 32).decode(),
        }

    for node in nodes:
        events = [
            {
                "ts": 99.0,
                "event": {"@type": "consensus.stats.id", "workchain": -1},
            }
        ]
        for height in (5, 6, 7):
            candidate = candidate_for_height(height)
            parent = (
                {"@type": "consensus.candidateWithoutParents"}
                if height == 5
                else {"@type": "consensus.candidateParent", "id": candidate_for_height(height - 1)}
            )
            block = SimpleNamespace(
                workchain=-1,
                shard=-(2**63),
                seqno=height,
                root_hash=bytes([height]) * 32,
                file_hash=bytes([height + 10]) * 32,
            )
            agreed[height] = block_id_text(block)
            block_data = {
                "workchain": -1,
                "shard": str(block.shard),
                "seqno": height,
                "root_hash": base64.b64encode(block.root_hash).decode(),
                "file_hash": base64.b64encode(block.file_hash).decode(),
            }
            finalized = 100.0 + (height - 5) * 0.4
            events.extend(
                [
                    {
                        "ts": finalized - 0.02,
                        "event": {
                            "@type": "consensus.stats.candidateReceived",
                            "id": candidate,
                            "parent": parent,
                            "block": {"id": block_data},
                        },
                    },
                    {
                        "ts": finalized + (0.02 if node == "node-a" else 0.03),
                        "event": {
                            "@type": "consensus.stats.blockAccepted",
                            "id": candidate,
                        },
                    },
                ]
            )
            finalizing_candidate = candidate
            if height == 6:
                finalizing_candidate = {
                    "@type": "consensus.candidateId",
                    "slot": 60,
                    "hash": base64.b64encode(bytes([90]) * 32).decode(),
                }
                events.append(
                    {
                        "ts": finalized - 0.01,
                        "event": {
                            "@type": "consensus.stats.candidateReceived",
                            "id": finalizing_candidate,
                            "parent": {"@type": "consensus.candidateParent", "id": candidate},
                            "block": {"@type": "consensus.stats.emptyBlock"},
                        },
                    }
                )
            events.append(
                {
                    "ts": finalized,
                    "event": {
                        "@type": "consensus.simplex.stats.certObserved",
                        "vote": {
                            "@type": "consensus.simplex.finalizeVote",
                            "id": finalizing_candidate,
                        },
                    },
                }
            )
        path = directory / f"timing-{node}.jsonl"
        path.write_text(
            json.dumps(
                {
                    "@type": "consensus.stats.events",
                    "id": session,
                    "events": events,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        logs[node] = path

    consensus = _structured_masterchain_timing(logs, agreed)
    require(set(consensus) == {5, 6, 7}, "structured finalization did not join by full block id")
    require(
        consensus[6]["finalization_through_descendant"] is True
        and consensus[6]["finalizing_candidate_slot"] == 60,
        "an empty descendant FinalCert did not finalize its block-bearing parent",
    )

    def info(node: str, height: int, end_ms: int) -> dict[str, object]:
        return {
            "node": node,
            "operation": "get_masterchain_info",
            "start_monotonic_ns": (end_ms - 5) * 1_000_000,
            "end_monotonic_ns": end_ms * 1_000_000,
            "end_wall_unix_ns": (100_000 + end_ms - 10_000) * 1_000_000,
            "reported_height": height,
            "error": None,
        }

    observed = [
        ObservedBlock(5, agreed[5], 10_100_000_000),
        ObservedBlock(6, agreed[6], 10_900_000_000),
        ObservedBlock(7, agreed[7], 11_250_000_000),
    ]
    queries = [
        info("node-a", 5, 10_080),
        info("node-b", 5, 10_090),
        info("node-a", 7, 10_850),
        info("node-b", 6, 10_880),
        info("node-b", 7, 11_200),
        {
            "node": "node-b",
            "operation": "lookup_block",
            "height": 6,
            "start_monotonic_ns": 10_880_000_000,
            "end_monotonic_ns": 10_887_000_000,
            "error": None,
        },
    ]
    barriers = [
        {
            "common_height": 5,
            "node_heights": {"node-a": 5, "node-b": 5},
            "determining_nodes": ["node-a", "node-b"],
            "at_monotonic_ns": 10_100_000_000,
        },
        {
            "common_height": 6,
            "node_heights": {"node-a": 7, "node-b": 6},
            "determining_nodes": ["node-b"],
            "at_monotonic_ns": 10_900_000_000,
        },
        {
            "common_height": 7,
            "node_heights": {"node-a": 7, "node-b": 7},
            "determining_nodes": ["node-a", "node-b"],
            "at_monotonic_ns": 11_250_000_000,
        },
    ]
    split = _sustained_timing_split(
        observed,
        queries,
        consensus,
        list(nodes),
        barriers,
        wall_clocks_comparable=True,
    )
    middle = split["intervals"][0]
    require(
        middle["consensus_finalization_interval_ms"] == 400.0
        and middle["observation_interval_ms"] == 800.0,
        "consensus finalization was conflated with all-node observation latency",
    )
    require(
        split["per_height"]["6"]["common_height_determining_nodes"] == ["node-b"],
        "common-height determinant was inferred from the wrong node",
    )
    require(
        middle["slowest_node_exposure_lag_ms"] == 30.0
        and middle["block_accepted_to_node_exposure_ms"]["node-b"] == 450.0,
        "node exposure lag or accepted-to-exposure latency was not separated",
    )
    require(
        middle["lite_query_latency_ms"]["maximum"] == 7.0,
        "successful lite query latency was not recorded separately",
    )
    remote = _sustained_timing_split(
        observed,
        queries,
        consensus,
        list(nodes),
        barriers,
        wall_clocks_comparable=False,
    )
    require(
        remote["intervals"][0]["consensus_finalization_interval_ms"] is None
        and remote["intervals"][0]["block_accepted_to_node_exposure_ms"]["node-b"] is None,
        "unsynchronised remote node clocks were treated as comparable",
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        trace = "ab" * 32
        first = root / "node-a.jsonl"
        second = root / "node-b.jsonl"
        first.write_text(
            json.dumps(event("node-a", trace, "finality_broadcast_sent", 10, 100, 984260)) + "\n"
        )
        second.write_text(
            "\n".join(
                json.dumps(item)
                for item in (
                    event("node-b", trace, "peer_finality_broadcast_received", 20, 130, 984260),
                    event("node-b", trace, "peer_finality_verification_started", 27, 137),
                    event("node-b", trace, "peer_finality_broadcast_verified", 39, 149),
                )
            )
            + "\n"
        )
        evidence = analyze_live_finality([first, second])
        require(
            evidence.sender_node == "node-a" and evidence.verifier_node == "node-b",
            "live finality evidence does not cross distinct sender and verifier nodes",
        )
        require(evidence.payload_bytes == 984260, "live finality payload size changed")
        require(
            (evidence.propagation_ns, evidence.queueing_ns, evidence.verification_ns)
            == (30, 7, 12),
            "live finality timing stages changed",
        )
        milestones_path = root / "milestones.jsonl"
        milestones_path.write_text(
            "\n".join(
                json.dumps(item)
                for item in (
                    event("node-a", trace, "candidate_generated", 10, 110),
                    event("node-a", trace, "notarization_certificate_observed", 20, 120),
                    event("node-a", trace, "finalization_certificate_observed", 30, 130),
                )
            )
            + "\n"
        )
        milestones = analyze_consensus_milestones([milestones_path], 100)
        require(
            (
                milestones.time_to_first_proposal_ns,
                milestones.time_to_first_notarization_certificate_ns,
                milestones.time_to_first_final_certificate_ns,
            )
            == (10, 20, 30),
            "consensus milestones are not distinct and ordered",
        )
        validate_node_isolation(
            [
                {
                    "db_root": f"db-{index}",
                    "adnl_identity": f"adnl-{index}",
                    "ports": [1000 + index * 3 + offset for offset in range(3)],
                    "log": f"log-{index}",
                    "trace": f"trace-{index}",
                    "resource_monitor": f"resource-{index}",
                }
                for index in range(3)
            ]
        )
        validate_lite_transport_source(ROOT)
        asyncio.run(check_backends(root))
        asyncio.run(check_sustained_agreement())
        asyncio.run(check_sustained_transport_retry())
        asyncio.run(check_startup_transport_retry())
        asyncio.run(check_resource_monitor_terminal_record(root))
        asyncio.run(check_observer_retry_window_composition())
        check_sustained_summary()
        check_simplex_skip_run_correlation(root)
        check_sustained_timing_split(root)
        check_latency_profile_binding()
        no_latency = load_latency_profile(
            ROOT / "test/pq-native/n6-scale-profiles/no-simulated-latency.json"
        )
        launch = load_latency_profile(ROOT / "test/pq-native/n6-scale-profiles/launch-default.json")
        require(
            no_latency.application == "none" and no_latency.one_way_latency_ms == [0.0, 0.0],
            "no-simulated-latency profile changed",
        )
        require(
            launch.application == "external-network-shaping",
            "launch latency profile is no longer externally applied",
        )
    print(
        "N6_CLUSTER_RUNNER_OK: local and remote-command backends share the manifest and evidence contract"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, RuntimeError, ValueError) as error:
        print(f"N6_CLUSTER_RUNNER_FAILURE: {error}", file=sys.stderr)
        raise SystemExit(1) from error
