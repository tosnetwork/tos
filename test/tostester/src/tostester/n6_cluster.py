"""N6 diagnostic cluster orchestration and evidence analysis."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import os
import re
import subprocess
import time
from bisect import bisect_right
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, TypeVar

EVIDENCE_CLASS = "DIAGNOSTIC_SCAFFOLDING_ONLY"
PROOF_BYTES = re.compile(r"got block proof .* \((?P<bytes>[0-9]+) bytes\)")
SUSTAINED_TRANSPORT_RETRY_SECONDS = 30.0
SUSTAINED_TRANSPORT_RETRY_DELAY_SECONDS = 0.1
SUSTAINED_SESSION_LOG_FLUSH_SECONDS = 5.1
T = TypeVar("T")


@dataclass(frozen=True)
class FinalityRouteEvidence:
    trace_id: str
    sender_node: str
    verifier_node: str
    payload_bytes: int
    propagation_ns: int
    queueing_ns: int
    verification_ns: int


@dataclass(frozen=True)
class ConsensusMilestones:
    time_to_first_proposal_ns: int
    time_to_first_notarization_certificate_ns: int
    time_to_first_final_certificate_ns: int


@dataclass(frozen=True)
class SustainedObservationConfig:
    blocks: int | None
    seconds: float | None
    target_block_rate_ms: int
    slow_interval_factor: float


@dataclass(frozen=True)
class ObservedBlock:
    height: int
    block_id: str
    observed_monotonic_ns: int


@dataclass(frozen=True)
class LatencyProfile:
    name: str
    one_way_latency_ms: list[float]
    application: str


def load_latency_profile(path: Path) -> LatencyProfile:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("N6_SCALE_SWEEP_FAILURE: latency profile schema_version is not 1")
    name = value.get("name")
    latency = value.get("one_way_latency_ms")
    application = value.get("application")
    if not isinstance(name, str) or not name:
        raise ValueError("N6_SCALE_SWEEP_FAILURE: latency profile has no name")
    if (
        not isinstance(latency, list)
        or len(latency) != 2
        or any(isinstance(item, bool) or not isinstance(item, (int, float)) for item in latency)
        or latency[0] < 0
        or latency[0] > latency[1]
    ):
        raise ValueError("N6_SCALE_SWEEP_FAILURE: latency profile has an invalid range")
    if application not in ("none", "external-network-shaping"):
        raise ValueError("N6_SCALE_SWEEP_FAILURE: latency profile has an invalid application")
    if application == "none" and latency != [0, 0]:
        raise ValueError(
            "N6_SCALE_SWEEP_FAILURE: an unapplied latency profile must be exactly zero"
        )
    return LatencyProfile(name, [float(item) for item in latency], application)


def validate_latency_backend(profile: LatencyProfile, backend_manifest: dict[str, Any]) -> None:
    if profile.application != "external-network-shaping":
        return
    if (
        backend_manifest["kind"] != "remote-command"
        or backend_manifest.get("network_profile") != profile.name
    ):
        raise ValueError(
            "N6_SCALE_SWEEP_FAILURE: launch latency requires a remote-command backend "
            "that declares the applied network profile"
        )


def read_trace(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def analyze_live_finality(trace_paths: list[Path]) -> FinalityRouteEvidence:
    events = [
        event for path in trace_paths for event in read_trace(path) if event.get("kind") == "trace"
    ]
    traces: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        traces.setdefault(event["trace_id"], []).append(event)
    for trace_id, current in traces.items():
        sent = [event for event in current if event["stage"] == "finality_broadcast_sent"]
        for received in (
            event for event in current if event["stage"] == "peer_finality_broadcast_received"
        ):
            verifier = received["node_id"]
            started = [
                event
                for event in current
                if event["node_id"] == verifier
                and event["stage"] == "peer_finality_verification_started"
            ]
            verified = [
                event
                for event in current
                if event["node_id"] == verifier
                and event["stage"] == "peer_finality_broadcast_verified"
            ]
            sender = next((event for event in sent if event["node_id"] != verifier), None)
            if sender is None or not started or not verified:
                continue
            start = min(started, key=lambda event: event["monotonic_ns"])
            finish = min(
                (event for event in verified if event["monotonic_ns"] >= start["monotonic_ns"]),
                key=lambda event: event["monotonic_ns"],
                default=None,
            )
            if finish is None:
                continue
            sent_bytes = sender.get("exact_bytes")
            received_bytes = received.get("exact_bytes")
            if not isinstance(sent_bytes, int) or sent_bytes <= 0 or sent_bytes != received_bytes:
                continue
            propagation = received["wall_unix_ns"] - sender["wall_unix_ns"]
            queueing = start["monotonic_ns"] - received["monotonic_ns"]
            verification = finish["monotonic_ns"] - start["monotonic_ns"]
            if min(propagation, queueing, verification) < 0:
                continue
            return FinalityRouteEvidence(
                trace_id=trace_id,
                sender_node=sender["node_id"],
                verifier_node=verifier,
                payload_bytes=sent_bytes,
                propagation_ns=propagation,
                queueing_ns=queueing,
                verification_ns=verification,
            )
    raise RuntimeError(
        "N6_LIVE_FINALITY_OVERLAY_FAILURE: no finality payload crossed from one process "
        "through Plumtree to a different process and completed trusted PQ verification"
    )


def analyze_consensus_milestones(
    trace_paths: list[Path], measurement_started_wall_ns: int
) -> ConsensusMilestones:
    events = [
        event for path in trace_paths for event in read_trace(path) if event.get("kind") == "trace"
    ]

    def elapsed(stage: str) -> int:
        timestamps = [event.get("wall_unix_ns") for event in events if event.get("stage") == stage]
        if not timestamps or any(not isinstance(value, int) for value in timestamps):
            raise RuntimeError(f"N6_SCALE_SWEEP_FAILURE: no {stage} milestone was observed")
        result = min(timestamps) - measurement_started_wall_ns
        if result < 0:
            raise RuntimeError(
                f"N6_SCALE_SWEEP_FAILURE: {stage} predates the recorded measurement start; "
                "remote hosts require synchronized clocks"
            )
        return result

    result = ConsensusMilestones(
        time_to_first_proposal_ns=elapsed("candidate_generated"),
        time_to_first_notarization_certificate_ns=elapsed("notarization_certificate_observed"),
        time_to_first_final_certificate_ns=elapsed("finalization_certificate_observed"),
    )
    if not (
        result.time_to_first_proposal_ns
        < result.time_to_first_notarization_certificate_ns
        < result.time_to_first_final_certificate_ns
    ):
        raise RuntimeError(
            "N6_SCALE_SWEEP_FAILURE: proposal, notarization and FinalCert milestones are not distinct"
        )
    return result


def validate_node_isolation(nodes: list[dict[str, Any]]) -> None:
    fields = ("db_root", "adnl_identity", "log", "trace", "resource_monitor")
    for field in fields:
        values = [node[field] for node in nodes]
        if len(values) != len(set(values)):
            raise RuntimeError(f"N6_CLUSTER_ISOLATION_FAILURE: nodes share {field}")
    ports = [port for node in nodes for port in node["ports"]]
    if len(ports) != len(set(ports)):
        raise RuntimeError("N6_CLUSTER_ISOLATION_FAILURE: nodes share transport ports")


def validate_lite_transport_source(source_root: Path) -> None:
    ext_client = " ".join(
        (source_root / "lite-client/ext-client.cpp").read_text(encoding="utf-8").split()
    )
    lite_client = " ".join(
        (source_root / "lite-client/lite-client.cpp").read_text(encoding="utf-8").split()
    )
    if "AdnlExtClient::create" not in ext_client or "AdnlExtClient::send_query" not in ext_client:
        raise RuntimeError(
            "N6_LITE_FRAMED_TCP_FAILURE: release lite-client no longer uses AdnlExtClient"
        )
    if "get_block_proof" not in lite_client or "envelope_send_query" not in lite_client:
        raise RuntimeError(
            "N6_LITE_FRAMED_TCP_FAILURE: block-proof command no longer reaches the external client query route"
        )


def block_id_text(block: Any) -> str:
    shard = block.shard if block.shard >= 0 else block.shard + 2**64
    return (
        f"({block.workchain},{shard:016x},{block.seqno}):"
        f"{block.root_hash.hex()}:{block.file_hash.hex()}"
    )


async def _resource_monitor(node: Any, output: Path, stop: asyncio.Event) -> None:
    pid = node.process_id
    if pid is None:
        raise RuntimeError(f"node {node.name} has no process for resource monitoring")
    with output.open("w") as stream:
        while not stop.is_set():
            status: dict[str, str] = {}
            try:
                for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                    if ":" in line:
                        key, value = line.split(":", 1)
                        if key in {"VmRSS", "VmHWM", "Threads"}:
                            status[key] = value.strip()
                stat = Path(f"/proc/{pid}/stat").read_text().split()
                io = Path(f"/proc/{pid}/io").read_text()
            except (FileNotFoundError, PermissionError) as error:
                stream.write(
                    json.dumps(
                        {
                            "kind": "resource_monitor_stopped",
                            "monotonic_ns": time.monotonic_ns(),
                            "wall_unix_ns": time.time_ns(),
                            "reason": type(error).__name__,
                            "detail": str(error),
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
                stream.flush()
                break
            stream.write(
                json.dumps(
                    {
                        "monotonic_ns": time.monotonic_ns(),
                        "wall_unix_ns": time.time_ns(),
                        "status": status,
                        "cpu_ticks": int(stat[13]) + int(stat[14]),
                        "io": io,
                    },
                    sort_keys=True,
                )
                + "\n"
            )
            stream.flush()
            try:
                await asyncio.wait_for(stop.wait(), timeout=0.2)
            except TimeoutError:
                pass


def _is_lite_transport_error(error: BaseException) -> bool:
    # Keep this source-only gate importable without loading toslib's optional
    # runtime dependencies, while still matching the exact production error
    # type rather than treating arbitrary exceptions as transport failures.
    return (
        type(error).__module__ == "toslib.toslibjson"
        and type(error).__qualname__ == "ToslibError"
        and getattr(error, "code", None) == 500
        and str(error).startswith("LITE_SERVER_NETWORK")
    )


async def _retry_lite_transport(
    node_name: str,
    operation_name: str,
    operation: Callable[[], Awaitable[T]],
    *,
    retry_counts: dict[str, dict[str, int]] | None = None,
    retry_count_operation: str | None = None,
    retry_budget_seconds: float = SUSTAINED_TRANSPORT_RETRY_SECONDS,
    retry_delay_seconds: float = SUSTAINED_TRANSPORT_RETRY_DELAY_SECONDS,
) -> T:
    deadline = time.monotonic() + retry_budget_seconds
    while True:
        try:
            return await operation()
        except Exception as error:
            if not _is_lite_transport_error(error):
                raise
            if retry_counts is not None:
                retry_operation = retry_count_operation or operation_name
                per_operation = retry_counts.setdefault(node_name, {})
                per_operation[retry_operation] = per_operation.get(retry_operation, 0) + 1
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "N6_SUSTAINED_TRANSPORT_FAILURE: "
                    f"node {node_name} stopped answering {operation_name} within the "
                    f"{retry_budget_seconds:g}s transport retry budget; last_error={error}"
                ) from error
            await asyncio.sleep(retry_delay_seconds)


async def _wait_all_heights(
    nodes: list[Any],
    minimum: int,
    timeout: float,
    *,
    transport_retry_counts: dict[str, dict[str, int]] | None = None,
    transport_retry_budget_seconds: float = SUSTAINED_TRANSPORT_RETRY_SECONDS,
    transport_retry_delay_seconds: float = SUSTAINED_TRANSPORT_RETRY_DELAY_SECONDS,
) -> list[int]:
    deadline = time.monotonic() + timeout
    last: list[int] = []
    clients = {node.name: await node.toslib_client() for node in nodes}
    while time.monotonic() < deadline:
        values = await _masterchain_heights(
            clients,
            transport_retry_counts=transport_retry_counts,
            transport_retry_budget_seconds=transport_retry_budget_seconds,
            transport_retry_delay_seconds=transport_retry_delay_seconds,
        )
        last = list(values.values())
        if min(last) >= minimum:
            return last
        await asyncio.sleep(0.25)
    raise TimeoutError(f"nodes did not reach masterchain height {minimum}; last={last}")


async def _masterchain_heights(
    clients: dict[str, Any],
    *,
    query_events: list[dict[str, Any]] | None = None,
    transport_retry_counts: dict[str, dict[str, int]] | None = None,
    transport_retry_budget_seconds: float = SUSTAINED_TRANSPORT_RETRY_SECONDS,
    transport_retry_delay_seconds: float = SUSTAINED_TRANSPORT_RETRY_DELAY_SECONDS,
) -> dict[str, int]:
    async def query(name: str, client: Any) -> Any:
        async def attempt() -> Any:
            started = time.monotonic_ns()
            started_wall = time.time_ns()
            try:
                info = await client.get_masterchain_info()
            except Exception as error:
                if query_events is not None:
                    query_events.append(
                        {
                            "node": name,
                            "operation": "get_masterchain_info",
                            "start_monotonic_ns": started,
                            "end_monotonic_ns": time.monotonic_ns(),
                            "start_wall_unix_ns": started_wall,
                            "end_wall_unix_ns": time.time_ns(),
                            "error": str(error),
                            "reported_height": None,
                        }
                    )
                raise
            if query_events is not None:
                query_events.append(
                    {
                        "node": name,
                        "operation": "get_masterchain_info",
                        "start_monotonic_ns": started,
                        "end_monotonic_ns": time.monotonic_ns(),
                        "start_wall_unix_ns": started_wall,
                        "end_wall_unix_ns": time.time_ns(),
                        "error": None,
                        "reported_height": info.last.seqno,
                    }
                )
            return info

        return await _retry_lite_transport(
            name,
            "get_masterchain_info",
            attempt,
            retry_counts=transport_retry_counts,
            retry_count_operation="get_masterchain_info",
            retry_budget_seconds=transport_retry_budget_seconds,
            retry_delay_seconds=transport_retry_delay_seconds,
        )

    infos = await asyncio.gather(*(query(name, client) for name, client in clients.items()))
    return {name: info.last.seqno for name, info in zip(clients, infos, strict=True)}


async def require_agreed_masterchain_block(
    clients: dict[str, Any],
    height: int,
    *,
    query_events: list[dict[str, Any]] | None = None,
    transport_retry_counts: dict[str, dict[str, int]] | None = None,
    transport_retry_budget_seconds: float = SUSTAINED_TRANSPORT_RETRY_SECONDS,
    transport_retry_delay_seconds: float = SUSTAINED_TRANSPORT_RETRY_DELAY_SECONDS,
) -> str:
    async def query(name: str, client: Any) -> Any:
        async def attempt() -> Any:
            started = time.monotonic_ns()
            started_wall = time.time_ns()
            try:
                block = await client.lookup_block(workchain=-1, shard=-(2**63), seqno=height)
            except Exception as error:
                if query_events is not None:
                    query_events.append(
                        {
                            "node": name,
                            "operation": "lookup_block",
                            "height": height,
                            "start_monotonic_ns": started,
                            "end_monotonic_ns": time.monotonic_ns(),
                            "start_wall_unix_ns": started_wall,
                            "end_wall_unix_ns": time.time_ns(),
                            "error": str(error),
                        }
                    )
                raise
            if query_events is not None:
                query_events.append(
                    {
                        "node": name,
                        "operation": "lookup_block",
                        "height": height,
                        "start_monotonic_ns": started,
                        "end_monotonic_ns": time.monotonic_ns(),
                        "start_wall_unix_ns": started_wall,
                        "end_wall_unix_ns": time.time_ns(),
                        "error": None,
                    }
                )
            return block

        return await _retry_lite_transport(
            name,
            f"lookup_block(height={height})",
            attempt,
            retry_counts=transport_retry_counts,
            retry_count_operation="lookup_block",
            retry_budget_seconds=transport_retry_budget_seconds,
            retry_delay_seconds=transport_retry_delay_seconds,
        )

    blocks = await asyncio.gather(*(query(name, client) for name, client in clients.items()))
    by_node = {name: block_id_text(block) for name, block in zip(clients, blocks, strict=True)}
    distinct = set(by_node.values())
    if len(distinct) != 1:
        details = ", ".join(f"{name}={block_id}" for name, block_id in by_node.items())
        raise RuntimeError(
            f"N6_SUSTAINED_CONSENSUS_FAILURE: masterchain block-id disagreement "
            f"at height {height}: {details}"
        )
    return next(iter(distinct))


def _nearest_rank(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def _lite_transport_retry_summary(
    retry_counts: dict[str, dict[str, int]],
) -> dict[str, Any]:
    return {
        "total": _lite_transport_retry_total(retry_counts),
        "per_node_operation": retry_counts,
    }


def _lite_transport_retry_total(retry_counts: dict[str, dict[str, int]]) -> int:
    return sum(sum(operations.values()) for operations in retry_counts.values())


def _observation_intervals(observed: list[ObservedBlock]) -> list[dict[str, Any]]:
    return [
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


def _require_structured_finalization(
    observed: list[ObservedBlock], consensus_by_height: dict[int, dict[str, Any]],
) -> None:
    missing = sorted({item.height for item in observed} - set(consensus_by_height))
    if missing:
        raise RuntimeError(
            "N6_SUSTAINED_CONSENSUS_FAILURE: structured finalization is missing "
            f"for agreed masterchain heights {missing}"
        )


def _sustained_timing_split(
    observed: list[ObservedBlock],
    query_events: list[dict[str, Any]],
    consensus_by_height: dict[int, dict[str, Any]],
    node_names: list[str],
    common_height_barriers: list[dict[str, Any]],
    *,
    wall_clocks_comparable: bool,
) -> dict[str, Any]:
    """Keep consensus, node exposure, query, and all-node barrier times separate."""
    per_height: dict[str, dict[str, Any]] = {}
    info_by_node = {
        name: sorted(
            (
                event
                for event in query_events
                if event["node"] == name
                and event["operation"] == "get_masterchain_info"
                and event["error"] is None
            ),
            key=lambda event: event["end_monotonic_ns"],
        )
        for name in node_names
    }
    info_cursor = {name: 0 for name in node_names}
    successful_info = sorted(
        (event for events in info_by_node.values() for event in events),
        key=lambda event: event["end_monotonic_ns"],
    )
    info_end_times = [event["end_monotonic_ns"] for event in successful_info]
    lookup_by_height: dict[int, list[dict[str, Any]]] = {}
    for event in query_events:
        if event["operation"] == "lookup_block" and event["error"] is None:
            lookup_by_height.setdefault(event["height"], []).append(event)
    barrier_cursor = 0
    for current in observed:
        height = current.height
        exposures: dict[str, dict[str, Any]] = {}
        for name in node_names:
            reports = info_by_node[name]
            cursor = info_cursor[name]
            while cursor < len(reports) and reports[cursor]["reported_height"] < height:
                cursor += 1
            info_cursor[name] = cursor
            if cursor == len(reports):
                raise RuntimeError(
                    "N6_SUSTAINED_CONSENSUS_FAILURE: no successful lite query exposed "
                    f"height {height} on {name}"
                )
            first = reports[cursor]
            exposures[name] = {
                "first_reported_at_or_above_height": first["reported_height"],
                "first_exposed_monotonic_ns": first["end_monotonic_ns"],
                "first_exposed_wall_unix_ns": first["end_wall_unix_ns"],
                "first_exposure_query_start_monotonic_ns": first["start_monotonic_ns"],
            }
        slowest = max(
            exposures,
            key=lambda name: (exposures[name]["first_exposed_monotonic_ns"], name),
        )
        earliest = min(item["first_exposed_monotonic_ns"] for item in exposures.values())
        lag_ms = (exposures[slowest]["first_exposed_monotonic_ns"] - earliest) / 1_000_000
        consensus = consensus_by_height.get(height)
        accepted_to_exposure: dict[str, float | None] = {}
        for name in node_names:
            accepted_ns = (consensus or {}).get("block_accepted_wall_unix_ns_by_node", {}).get(name)
            if not wall_clocks_comparable or accepted_ns is None:
                accepted_to_exposure[name] = None
                continue
            delta_ms = (exposures[name]["first_exposed_wall_unix_ns"] - accepted_ns) / 1_000_000
            # BlockAccepted is published after ManagerFacade.accept_block returns.
            # Lite visibility can precede that trace event; retain the signed
            # difference as a diagnostic, without assuming a causal ordering.
            accepted_to_exposure[name] = delta_ms
        while (
            barrier_cursor < len(common_height_barriers)
            and common_height_barriers[barrier_cursor]["common_height"] < height
        ):
            barrier_cursor += 1
        if barrier_cursor == len(common_height_barriers):
            raise RuntimeError(
                "N6_SUSTAINED_CONSENSUS_FAILURE: no all-node barrier exposed "
                f"agreed height {height}"
            )
        barrier = common_height_barriers[barrier_cursor]
        per_height[str(height)] = {
            "per_node_first_exposure": exposures,
            "common_height_determining_nodes": barrier["determining_nodes"],
            "common_height_barrier_monotonic_ns": barrier["at_monotonic_ns"],
            "slowest_node_exposure_lag_ms": lag_ms,
            "block_accepted_to_node_exposure_ms": accepted_to_exposure,
            "exposure_before_block_accepted_trace_nodes": sorted(
                name for name, delta in accepted_to_exposure.items()
                if delta is not None and delta < 0
            ),
            "missing_block_accepted_nodes": sorted(
                name
                for name in node_names
                if name not in (consensus or {}).get("block_accepted_wall_unix_ns_by_node", {})
            ),
            "consensus": consensus,
        }

    intervals = []
    for previous, current in zip(observed, observed[1:], strict=False):
        previous_consensus = consensus_by_height.get(previous.height)
        current_consensus = consensus_by_height.get(current.height)
        finalization_interval = None
        if wall_clocks_comparable and previous_consensus and current_consensus:
            finalization_interval = (
                current_consensus["first_finalize_certificate_wall_unix_ns"]
                - previous_consensus["first_finalize_certificate_wall_unix_ns"]
            ) / 1_000_000
            if finalization_interval < 0:
                raise RuntimeError(
                    "N6_SUSTAINED_CONSENSUS_FAILURE: consensus finalization timestamps "
                    f"regressed between heights {previous.height} and {current.height}"
                )
        lower = bisect_right(info_end_times, previous.observed_monotonic_ns)
        upper = bisect_right(info_end_times, current.observed_monotonic_ns)
        query_latency = [
            (event["end_monotonic_ns"] - event["start_monotonic_ns"]) / 1_000_000
            for event in [*successful_info[lower:upper], *lookup_by_height.get(current.height, [])]
        ]
        intervals.append(
            {
                "from_height": previous.height,
                "to_height": current.height,
                "consensus_finalization_interval_ms": finalization_interval,
                "block_accepted_to_node_exposure_ms": per_height[str(current.height)][
                    "block_accepted_to_node_exposure_ms"
                ],
                "lite_query_latency_ms": {
                    "successful_only": True,
                    "count": len(query_latency),
                    "maximum": max(query_latency) if query_latency else None,
                },
                "slowest_node_exposure_lag_ms": per_height[str(current.height)][
                    "slowest_node_exposure_lag_ms"
                ],
                "observation_interval_ms": (
                    current.observed_monotonic_ns - previous.observed_monotonic_ns
                )
                / 1_000_000,
            }
        )
    return {
        "evidence_class": EVIDENCE_CLASS,
        "wall_clocks_comparable": wall_clocks_comparable,
        "consensus_timestamp_source": "earliest local Simplex certObserved(finalizeVote) for the agreed block",
        "node_exposure_timestamp_source": "first successful get_masterchain_info result at or above height",
        "node_exposure_is_upper_bound_when_height_jumps": True,
        "block_accepted_to_node_exposure_is_signed_diagnostic": True,
        "block_accepted_trace_is_visibility_prerequisite": False,
        "block_accepted_exposure_diagnostic_complete": wall_clocks_comparable and all(
            not item["missing_block_accepted_nodes"] for item in per_height.values()
        ),
        "query_events": query_events,
        "common_height_barriers": common_height_barriers,
        "per_height": per_height,
        "intervals": intervals,
    }


def _simplex_session_log_paths(nodes: list[Any], validator_names: list[str]) -> dict[str, Path]:
    nodes_by_name = {node.name: node for node in nodes}
    if len(nodes_by_name) != len(nodes):
        raise RuntimeError("N6_SUSTAINED_CONSENSUS_FAILURE: observed node names are not unique")
    missing = sorted(set(validator_names) - set(nodes_by_name))
    if missing:
        raise RuntimeError(
            "N6_SUSTAINED_CONSENSUS_FAILURE: Simplex validators are absent from the observed "
            f"node set: {missing}"
        )
    return {
        node_name: Path(nodes_by_name[node_name].session_log_path) for node_name in validator_names
    }


def _structured_masterchain_timing(
    session_logs: dict[str, Path], agreed_block_ids: dict[int, str]
) -> dict[int, dict[str, Any]]:
    """Join local finalization and block acceptance to full agreed block ids."""
    metadata: set[tuple[str, str]] = set()
    candidates: dict[tuple[str, int, str], tuple[int, str]] = {}
    parents: dict[tuple[str, int, str], tuple[str, int, str] | None] = {}
    finalization: dict[tuple[str, int, str], list[tuple[str, float]]] = {}
    accepted: dict[tuple[str, int, str], list[tuple[str, float]]] = {}

    def key(session_id: str, candidate: Any) -> tuple[str, int, str] | None:
        if not isinstance(candidate, dict):
            return None
        slot, digest = candidate.get("slot"), candidate.get("hash")
        if not isinstance(slot, int) or not isinstance(digest, str):
            return None
        return session_id, slot, digest

    for node_name, path in session_logs.items():
        if not path.is_file():
            raise RuntimeError(
                "N6_SUSTAINED_CONSENSUS_FAILURE: structured consensus session log "
                f"is missing for {node_name}: {path}"
            )
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line:
                continue
            try:
                batch = json.loads(line)
            except json.JSONDecodeError as error:
                raise RuntimeError(
                    "N6_SUSTAINED_CONSENSUS_FAILURE: malformed structured consensus "
                    f"log for {node_name} at {path}:{line_number}"
                ) from error
            if batch.get("@type") != "consensus.stats.events":
                continue
            session_id = batch.get("id")
            events = batch.get("events")
            if not isinstance(session_id, str) or not isinstance(events, list):
                raise RuntimeError(
                    "N6_SUSTAINED_CONSENSUS_FAILURE: invalid structured consensus "
                    f"batch for {node_name} at {path}:{line_number}"
                )
            for timestamped in events:
                if not isinstance(timestamped, dict):
                    continue
                event = timestamped.get("event")
                ts = timestamped.get("ts")
                if not isinstance(event, dict) or not isinstance(ts, (int, float)):
                    continue
                event_type = event.get("@type")
                if event_type == "consensus.stats.id" and event.get("workchain") == -1:
                    metadata.add((session_id, node_name))
                elif event_type == "consensus.stats.candidateReceived":
                    candidate_key = key(session_id, event.get("id"))
                    if candidate_key is None:
                        continue
                    parent = event.get("parent")
                    if not isinstance(parent, dict):
                        raise RuntimeError(
                            "N6_SUSTAINED_CONSENSUS_FAILURE: candidate parent is missing "
                            f"for {node_name} at {path}:{line_number}"
                        )
                    if parent.get("@type") == "consensus.candidateWithoutParents":
                        parent_key = None
                    elif parent.get("@type") == "consensus.candidateParent":
                        parent_key = key(session_id, parent.get("id"))
                        if parent_key is None:
                            raise RuntimeError(
                                "N6_SUSTAINED_CONSENSUS_FAILURE: candidate parent id is "
                                f"invalid for {node_name} at {path}:{line_number}"
                            )
                    else:
                        raise RuntimeError(
                            "N6_SUSTAINED_CONSENSUS_FAILURE: unknown candidate parent "
                            f"type for {node_name} at {path}:{line_number}"
                        )
                    if candidate_key in parents and parents[candidate_key] != parent_key:
                        raise RuntimeError(
                            "N6_SUSTAINED_CONSENSUS_FAILURE: candidate parent mapping "
                            f"conflicts for {candidate_key}"
                        )
                    parents[candidate_key] = parent_key
                    block = event.get("block")
                    block_id = block.get("id") if isinstance(block, dict) else None
                    if not isinstance(block_id, dict):
                        continue
                    if block_id.get("workchain") != -1:
                        continue
                    height = block_id.get("seqno")
                    try:
                        root = base64.b64decode(block_id["root_hash"], validate=True)
                        file = base64.b64decode(block_id["file_hash"], validate=True)
                        shard = int(block_id["shard"])
                    except (KeyError, TypeError, ValueError) as error:
                        raise RuntimeError(
                            "N6_SUSTAINED_CONSENSUS_FAILURE: malformed candidate block id "
                            f"for {node_name} at {path}:{line_number}"
                        ) from error
                    if not isinstance(height, int) or len(root) != 32 or len(file) != 32:
                        raise RuntimeError(
                            "N6_SUSTAINED_CONSENSUS_FAILURE: invalid candidate block id "
                            f"for {node_name} at {path}:{line_number}"
                        )
                    shard &= 2**64 - 1
                    block_text = f"(-1,{shard:016x},{height}):{root.hex()}:{file.hex()}"
                    previous = candidates.setdefault(candidate_key, (height, block_text))
                    if previous != (height, block_text):
                        raise RuntimeError(
                            "N6_SUSTAINED_CONSENSUS_FAILURE: candidate block-id mapping "
                            f"conflicts for {candidate_key}"
                        )
                elif event_type == "consensus.simplex.stats.certObserved":
                    vote = event.get("vote")
                    if (
                        isinstance(vote, dict)
                        and vote.get("@type") == "consensus.simplex.finalizeVote"
                    ):
                        candidate_key = key(session_id, vote.get("id"))
                        if candidate_key is not None:
                            finalization.setdefault(candidate_key, []).append(
                                (node_name, float(ts))
                            )
                elif event_type == "consensus.stats.blockAccepted":
                    candidate_key = key(session_id, event.get("id"))
                    if candidate_key is not None:
                        accepted.setdefault(candidate_key, []).append((node_name, float(ts)))

    # A FinalCert for an empty descendant finalizes its parent chain too. A
    # block candidate can therefore be accepted without a direct FinalCert.
    finalized_ancestors: dict[
        tuple[str, int, str], list[tuple[str, float, tuple[str, int, str]]]
    ] = {}
    for finalizing_key, observations in finalization.items():
        for node, ts in observations:
            if (finalizing_key[0], node) not in metadata:
                continue
            ancestor: tuple[str, int, str] | None = finalizing_key
            visited: set[tuple[str, int, str]] = set()
            while ancestor is not None:
                if ancestor in visited:
                    raise RuntimeError(
                        "N6_SUSTAINED_CONSENSUS_FAILURE: candidate parent cycle "
                        f"contains {ancestor}"
                    )
                visited.add(ancestor)
                finalized_ancestors.setdefault(ancestor, []).append((node, ts, finalizing_key))
                ancestor = parents.get(ancestor)

    result: dict[int, dict[str, Any]] = {}
    for candidate_key, (height, block_text) in candidates.items():
        if agreed_block_ids.get(height) != block_text:
            continue
        session_id = candidate_key[0]
        finalized = finalized_ancestors.get(candidate_key, [])
        accepted_by_node = {
            node: min(ts for name, ts in accepted.get(candidate_key, []) if name == node)
            for node in {name for name, _ in accepted.get(candidate_key, [])}
            if (session_id, node) in metadata
        }
        if not finalized:
            continue
        earliest_node, earliest_ts, finalizing_key = min(finalized, key=lambda item: item[1])
        current = {
            "session_id": session_id,
            "candidate_slot": candidate_key[1],
            "candidate_hash": candidate_key[2],
            "first_finalize_certificate_node": earliest_node,
            "finalizing_candidate_slot": finalizing_key[1],
            "finalization_through_descendant": finalizing_key != candidate_key,
            "first_finalize_certificate_wall_unix_ns": round(earliest_ts * 1_000_000_000),
            "block_accepted_wall_unix_ns_by_node": {
                node: round(ts * 1_000_000_000) for node, ts in accepted_by_node.items()
            },
        }
        if height in result:
            raise RuntimeError(
                "N6_SUSTAINED_CONSENSUS_FAILURE: more than one finalized candidate "
                f"maps to agreed masterchain height {height}"
            )
        result[height] = current
    return result


def analyze_simplex_skip_runs(
    session_logs: dict[str, Path],
    observation_intervals: list[dict[str, Any]],
    validator_names: list[str],
) -> dict[str, Any]:
    """Correlate observed SkipCerts with accepted masterchain blocks.

    Voted(skipVote) is an attempt emitted before persistence and signing. It is
    retained as per-node telemetry, never as authority that a skip occurred.
    """
    session_events: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for node_name, path in session_logs.items():
        if not path.is_file():
            raise RuntimeError(
                "N6_SUSTAINED_CONSENSUS_FAILURE: "
                f"structured consensus session log is missing for {node_name}: {path}"
            )
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line:
                continue
            try:
                batch = json.loads(line)
            except json.JSONDecodeError as error:
                raise RuntimeError(
                    "N6_SUSTAINED_CONSENSUS_FAILURE: malformed structured consensus log "
                    f"for {node_name} at {path}:{line_number}"
                ) from error
            if batch.get("@type") != "consensus.stats.events":
                continue
            session_id = batch.get("id")
            events = batch.get("events")
            if not isinstance(session_id, str) or not isinstance(events, list):
                raise RuntimeError(
                    "N6_SUSTAINED_CONSENSUS_FAILURE: invalid consensus event batch "
                    f"for {node_name} at {path}:{line_number}"
                )
            session_events.setdefault(session_id, {}).setdefault(node_name, []).extend(events)

    validator_set = set(validator_names)
    attempted_slots = {node_name: set() for node_name in session_logs}
    certified_slots = {node_name: set() for node_name in session_logs}
    candidate_heights: dict[tuple[str, int, str], int] = {}
    accepted_candidates: set[tuple[str, int, str]] = set()
    session_metadata: dict[str, tuple[int, int]] = {}
    validator_by_session_index: dict[tuple[str, int], str] = {}

    def candidate_key(session_id: str, value: Any) -> tuple[str, int, str] | None:
        if not isinstance(value, dict):
            return None
        slot = value.get("slot")
        candidate_hash = value.get("hash")
        if not isinstance(slot, int) or not isinstance(candidate_hash, str):
            return None
        return session_id, slot, candidate_hash

    for session_id, per_node_events in session_events.items():
        for node_name, timestamped_events in per_node_events.items():
            for timestamped in timestamped_events:
                event = timestamped.get("event") if isinstance(timestamped, dict) else None
                if not isinstance(event, dict):
                    continue
                event_type = event.get("@type")
                if event_type == "consensus.stats.id" and event.get("workchain") == -1:
                    total_validators = event.get("total_validators")
                    slots_per_window = event.get("slots_per_leader_window")
                    validator_index = event.get("idx")
                    if (
                        not isinstance(total_validators, int)
                        or total_validators <= 0
                        or not isinstance(slots_per_window, int)
                        or slots_per_window <= 0
                        or not isinstance(validator_index, int)
                    ):
                        raise RuntimeError(
                            "N6_SUSTAINED_CONSENSUS_FAILURE: invalid masterchain session metadata "
                            f"for {node_name} session {session_id}"
                        )
                    metadata = (total_validators, slots_per_window)
                    previous = session_metadata.setdefault(session_id, metadata)
                    if previous != metadata:
                        raise RuntimeError(
                            "N6_SUSTAINED_CONSENSUS_FAILURE: nodes disagree on Simplex session "
                            f"metadata for {session_id}: {previous} != {metadata}"
                        )
                    if node_name in validator_set and validator_index >= 0:
                        index_key = (session_id, validator_index)
                        previous_name = validator_by_session_index.setdefault(index_key, node_name)
                        if previous_name != node_name:
                            raise RuntimeError(
                                "N6_SUSTAINED_CONSENSUS_FAILURE: validator index disagreement "
                                f"for session {session_id} index {validator_index}: "
                                f"{previous_name} != {node_name}"
                            )
                elif event_type == "consensus.stats.candidateReceived":
                    key = candidate_key(session_id, event.get("id"))
                    block = event.get("block")
                    block_id = block.get("id", {}) if isinstance(block, dict) else {}
                    height = block_id.get("seqno") if block_id.get("workchain") == -1 else None
                    if key is not None and isinstance(height, int):
                        previous_height = candidate_heights.setdefault(key, height)
                        if previous_height != height:
                            raise RuntimeError(
                                "N6_SUSTAINED_CONSENSUS_FAILURE: candidate maps to conflicting "
                                f"masterchain heights: {key} -> {previous_height}, {height}"
                            )
                elif event_type == "consensus.stats.blockAccepted":
                    key = candidate_key(session_id, event.get("id"))
                    if key is not None:
                        accepted_candidates.add(key)
                elif event_type == "consensus.simplex.stats.voted":
                    vote = event.get("vote")
                    if isinstance(vote, dict) and vote.get("@type") == "consensus.simplex.skipVote":
                        slot = vote.get("slot")
                        if isinstance(slot, int):
                            attempted_slots[node_name].add((session_id, slot))
                elif event_type == "consensus.simplex.stats.certObserved":
                    vote = event.get("vote")
                    if isinstance(vote, dict) and vote.get("@type") == "consensus.simplex.skipVote":
                        slot = vote.get("slot")
                        if isinstance(slot, int):
                            certified_slots[node_name].add((session_id, slot))

    accepted_height_slots: dict[int, tuple[str, int]] = {}
    for key in accepted_candidates:
        height = candidate_heights.get(key)
        if height is None:
            continue
        height_slot = (key[0], key[1])
        previous = accepted_height_slots.setdefault(height, height_slot)
        if previous != height_slot:
            raise RuntimeError(
                "N6_SUSTAINED_CONSENSUS_FAILURE: accepted masterchain height maps to "
                f"conflicting Simplex slots: height={height} {previous} != {height_slot}"
            )

    # A node logs shard and masterchain sessions into the same file. Only the
    # sessions whose structured id event says workchain -1 describe the block
    # intervals observed above.
    attempted_slots = {
        node_name: {item for item in slots if item[0] in session_metadata}
        for node_name, slots in attempted_slots.items()
    }
    certified_slots = {
        node_name: {item for item in slots if item[0] in session_metadata}
        for node_name, slots in certified_slots.items()
    }
    if not any(certified_slots.values()):
        interval_correlations = [
            {
                "from_height": interval["from_height"],
                "to_height": interval["to_height"],
                "correlation_available": False,
                "coincides_with_skip_run": None,
                "skip_run_indices": [],
                "from_candidate_slot": (
                    accepted_height_slots.get(interval["from_height"], (None, None))[1]
                ),
                "to_candidate_slot": (
                    accepted_height_slots.get(interval["to_height"], (None, None))[1]
                ),
            }
            for interval in observation_intervals
        ]
        return {
            "analysis_available": False,
            "reason": (
                "no consensus.simplex.stats.certObserved(skipVote) SkipCert appeared in this run; "
                "attempted votes cannot establish a certified skip run"
            ),
            "run_count": None,
            "runs": [],
            "skip_votes_per_node": {
                node_name: len(slots) for node_name, slots in attempted_slots.items()
            },
            "skip_slots_per_node": {
                node_name: [
                    {"session_id": session_id, "slot": slot} for session_id, slot in sorted(slots)
                ]
                for node_name, slots in attempted_slots.items()
            },
            "interval_correlations": interval_correlations,
        }
    all_skip_slots = sorted({slot for slots in certified_slots.values() for slot in slots})
    grouped: list[list[tuple[str, int]]] = []
    for session_slot in all_skip_slots:
        if (
            not grouped
            or grouped[-1][-1][0] != session_slot[0]
            or grouped[-1][-1][1] + 1 != session_slot[1]
        ):
            grouped.append([session_slot])
        else:
            grouped[-1].append(session_slot)

    runs: list[dict[str, Any]] = []
    for run_index, slots in enumerate(grouped):
        session_id = slots[0][0]
        metadata = session_metadata.get(session_id)
        if metadata is None:
            raise RuntimeError(
                "N6_SUSTAINED_CONSENSUS_FAILURE: skip vote has no masterchain session "
                f"metadata: session={session_id} slot={slots[0][1]}"
            )
        validator_count, slots_per_window = metadata
        slot_numbers = [slot for _, slot in slots]
        leaders = []
        for slot in slot_numbers:
            leader_index = slot // slots_per_window % validator_count
            leader_node = validator_by_session_index.get((session_id, leader_index))
            if leader_node is None:
                raise RuntimeError(
                    "N6_SUSTAINED_CONSENSUS_FAILURE: cannot identify scheduled leader "
                    f"for session {session_id} slot {slot} index {leader_index}"
                )
            leaders.append(
                {
                    "slot": slot,
                    "leader_index": leader_index,
                    "leader_node": leader_node,
                }
            )
        runs.append(
            {
                "run_index": run_index,
                "session_id": session_id,
                "first_slot": slot_numbers[0],
                "last_slot": slot_numbers[-1],
                "length": len(slot_numbers),
                "slots": slot_numbers,
                "leaders": leaders,
                "cert_observations_per_node": {
                    node_name: sum((session_id, slot) in node_slots for slot in slot_numbers)
                    for node_name, node_slots in certified_slots.items()
                },
            }
        )

    interval_correlations = []
    for interval in observation_intervals:
        from_height = interval["from_height"]
        to_height = interval["to_height"]
        previous_slot = accepted_height_slots.get(from_height)
        current_slot = accepted_height_slots.get(to_height)
        correlation_available = (
            previous_slot is not None
            and current_slot is not None
            and previous_slot[0] == current_slot[0]
        )
        matching_runs: list[int] = []
        if correlation_available:
            assert previous_slot is not None and current_slot is not None
            matching_runs = [
                run["run_index"]
                for run in runs
                if run["session_id"] == previous_slot[0]
                and run["last_slot"] > previous_slot[1]
                and run["first_slot"] < current_slot[1]
            ]
        interval_correlations.append(
            {
                "from_height": from_height,
                "to_height": to_height,
                "correlation_available": correlation_available,
                "coincides_with_skip_run": bool(matching_runs) if correlation_available else None,
                "skip_run_indices": matching_runs,
                "from_candidate_slot": previous_slot[1] if previous_slot is not None else None,
                "to_candidate_slot": current_slot[1] if current_slot is not None else None,
            }
        )

    return {
        "analysis_available": True,
        "run_count": len(runs),
        "runs": runs,
        "skip_votes_per_node": {
            node_name: len(slots) for node_name, slots in attempted_slots.items()
        },
        "skip_slots_per_node": {
            node_name: [
                {"session_id": session_id, "slot": slot} for session_id, slot in sorted(slots)
            ]
            for node_name, slots in attempted_slots.items()
        },
        "interval_correlations": interval_correlations,
    }


def summarize_sustained_observation(
    *,
    config: SustainedObservationConfig,
    start_height: int,
    observed: list[ObservedBlock],
    per_node_final_height: dict[str, int],
    checked_from_height: int,
    agreed_block_ids: dict[int, str] | None = None,
    transport_retry_counts: dict[str, dict[str, int]] | None = None,
    interval_retry_baseline: int = 0,
    simplex_skip_evidence: dict[str, Any] | None = None,
    timing_split: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if len(observed) < 3:
        raise RuntimeError(
            "N6_SUSTAINED_CONSENSUS_FAILURE: fewer than two masterchain intervals were observed"
        )
    observation_intervals = _observation_intervals(observed)
    if any(item["to_height"] != item["from_height"] + 1 for item in observation_intervals):
        raise RuntimeError(
            "N6_SUSTAINED_CONSENSUS_FAILURE: sustained observation skipped a masterchain height"
        )
    values = [item["observation_interval_ms"] for item in observation_intervals]
    slow_threshold_ms = config.target_block_rate_ms * config.slow_interval_factor
    retry_counts = transport_retry_counts or {}
    retry_summary = _lite_transport_retry_summary(retry_counts)
    interval_retry_total = retry_summary["total"] - interval_retry_baseline
    if interval_retry_total < 0:
        raise ValueError(
            "N6_SUSTAINED_CONSENSUS_FAILURE: interval retry baseline exceeds total retries"
        )
    skip_evidence = simplex_skip_evidence or {
        "analysis_available": False,
        "reason": "structured Simplex session logs were not requested by this caller",
        "run_count": None,
        "runs": [],
        "skip_votes_per_node": None,
        "skip_slots_per_node": None,
        "interval_correlations": [],
    }
    correlations = {
        (item["from_height"], item["to_height"]): item
        for item in skip_evidence["interval_correlations"]
    }
    for interval in observation_intervals:
        correlation = correlations.get((interval["from_height"], interval["to_height"]))
        if correlation is not None:
            interval.update(
                {
                    "skip_correlation_available": correlation["correlation_available"],
                    "coincides_with_skip_run": correlation["coincides_with_skip_run"],
                    "skip_run_indices": correlation["skip_run_indices"],
                }
            )
    return {
        "evidence_class": "COLOCATED_DIAGNOSTIC_ONLY",
        "release_evidence_eligible": False,
        "configured_blocks": config.blocks,
        "configured_seconds": config.seconds,
        "target_block_rate_ms": config.target_block_rate_ms,
        "slow_interval_factor": config.slow_interval_factor,
        "slow_observation_interval_threshold_ms": slow_threshold_ms,
        "start_height": start_height,
        "final_common_height": observed[-1].height,
        "masterchain_blocks_produced": observed[-1].height - start_height,
        "agreement": {
            "same_block_per_height": True,
            "checked_from_height": checked_from_height,
            "checked_through_height": observed[-1].height,
            "block_ids": {
                str(height): block_id for height, block_id in (agreed_block_ids or {}).items()
            },
        },
        "per_node_final_height": per_node_final_height,
        "lite_transport_retries": retry_summary,
        "simplex_skip_runs": skip_evidence,
        "timing_split": timing_split
        or {
            "analysis_available": False,
            "reason": "per-call lite and structured Simplex timing were not requested by this caller",
        },
        "observation_intervals": observation_intervals,
        "observation_interval_distribution_ms": {
            "count": len(values),
            "minimum": min(values),
            "p50": _nearest_rank(values, 0.50),
            "p95": _nearest_rank(values, 0.95),
            "maximum": max(values),
            "transport_retries_during_observation": interval_retry_total,
            "includes_catch_up_after_transport_retry": interval_retry_total > 0,
        },
        "slow_observation_intervals": [
            item
            for item in observation_intervals
            if item["observation_interval_ms"] > slow_threshold_ms
        ],
        "scope": (
            "Co-located diagnostic stability only; block intervals are the times at which all "
            "nodes exposed an agreed block, not release-grade persisted-finality latency."
        ),
    }


async def observe_sustained_consensus(
    nodes: list[Any],
    config: SustainedObservationConfig,
    zerostate_block_id: str,
    *,
    simplex_validator_names: list[str] | None = None,
    wall_clocks_comparable: bool = True,
) -> dict[str, Any]:
    if (config.blocks is None) == (config.seconds is None):
        raise ValueError(
            "N6_SUSTAINED_CONSENSUS_FAILURE: configure exactly one of blocks or seconds"
        )
    if config.blocks is not None and config.blocks < 2:
        raise ValueError("N6_SUSTAINED_CONSENSUS_FAILURE: blocks must be at least two")
    if config.seconds is not None and config.seconds <= 0:
        raise ValueError("N6_SUSTAINED_CONSENSUS_FAILURE: seconds must be positive")
    if config.target_block_rate_ms <= 0 or config.slow_interval_factor <= 1:
        raise ValueError(
            "N6_SUSTAINED_CONSENSUS_FAILURE: target rate and slow-interval factor are invalid"
        )

    clients = {node.name: await node.toslib_client() for node in nodes}
    transport_retry_counts = {
        name: {"get_masterchain_info": 0, "lookup_block": 0} for name in clients
    }
    query_events: list[dict[str, Any]] = []
    common_height_barriers: list[dict[str, Any]] = []
    heights = await _masterchain_heights(
        clients, transport_retry_counts=transport_retry_counts, query_events=query_events
    )
    start_height = min(heights.values())
    common_height_barriers.append(
        {
            "common_height": start_height,
            "node_heights": heights,
            "determining_nodes": sorted(
                name for name, height in heights.items() if height == start_height
            ),
            "at_monotonic_ns": time.monotonic_ns(),
        }
    )
    if not zerostate_block_id:
        raise ValueError("N6_SUSTAINED_CONSENSUS_FAILURE: zerostate block id is missing")
    block_ids: dict[int, str] = {0: zerostate_block_id}
    for height in range(1, start_height + 1):
        block_ids[height] = await require_agreed_masterchain_block(
            clients,
            height,
            transport_retry_counts=transport_retry_counts,
            query_events=query_events,
        )

    interval_retry_baseline = _lite_transport_retry_total(transport_retry_counts)
    observed = [ObservedBlock(start_height, block_ids[start_height], time.monotonic_ns())]
    next_height = start_height + 1
    started = time.monotonic()
    expected_seconds = (
        config.blocks * config.target_block_rate_ms / 1000
        if config.blocks is not None
        else config.seconds
    )
    assert expected_seconds is not None
    deadline = started + max(120.0, expected_seconds * config.slow_interval_factor * 4)
    final_heights = heights

    while True:
        final_heights = await _masterchain_heights(
            clients,
            transport_retry_counts=transport_retry_counts,
            query_events=query_events,
        )
        common_height = min(final_heights.values())
        common_height_barriers.append(
            {
                "common_height": common_height,
                "node_heights": final_heights,
                "determining_nodes": sorted(
                    name for name, height in final_heights.items() if height == common_height
                ),
                "at_monotonic_ns": time.monotonic_ns(),
            }
        )
        while next_height <= common_height:
            block_id = await require_agreed_masterchain_block(
                clients,
                next_height,
                transport_retry_counts=transport_retry_counts,
                query_events=query_events,
            )
            block_ids[next_height] = block_id
            observed.append(ObservedBlock(next_height, block_id, time.monotonic_ns()))
            next_height += 1

        elapsed = time.monotonic() - started
        if config.blocks is not None and observed[-1].height - start_height >= config.blocks:
            break
        if config.seconds is not None and elapsed >= config.seconds:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError(
                "N6_SUSTAINED_CONSENSUS_FAILURE: sustained observation did not reach its bound; "
                f"start={start_height} heights={final_heights}"
            )
        await asyncio.sleep(0.05)

    skip_evidence = None
    consensus_by_height: dict[int, dict[str, Any]] = {}
    if simplex_validator_names is not None:
        # TraceCollector flushes structured events every five seconds. Waiting
        # once at the end avoids treating its final buffered batch as no skips.
        await asyncio.sleep(SUSTAINED_SESSION_LOG_FLUSH_SECONDS)
        session_logs = _simplex_session_log_paths(nodes, simplex_validator_names)
        skip_evidence = analyze_simplex_skip_runs(
            session_logs,
            _observation_intervals(observed),
            simplex_validator_names,
        )
        consensus_by_height = _structured_masterchain_timing(session_logs, block_ids)
        _require_structured_finalization(observed, consensus_by_height)

    timing_split = _sustained_timing_split(
        observed,
        query_events,
        consensus_by_height,
        list(clients),
        common_height_barriers,
        wall_clocks_comparable=wall_clocks_comparable,
    )
    timing_split["analysis_available"] = bool(consensus_by_height)
    if not consensus_by_height:
        timing_split["reason"] = "structured Simplex finalization timestamps were not available"

    return summarize_sustained_observation(
        config=config,
        start_height=start_height,
        observed=observed,
        per_node_final_height=final_heights,
        checked_from_height=0,
        agreed_block_ids=block_ids,
        transport_retry_counts=transport_retry_counts,
        interval_retry_baseline=interval_retry_baseline,
        simplex_skip_evidence=skip_evidence,
        timing_split=timing_split,
    )


async def run_cluster(
    install: Any,
    artifact_dir: Path,
    backend: Any,
    validators: int,
    base_port: int,
    require_lite: bool,
    latency_profile_path: Path | None = None,
    sustained: SustainedObservationConfig | None = None,
) -> dict[str, Any]:
    from .network import Network, StartOptions

    if validators < 4:
        raise ValueError("N6.3 diagnostic Genesis requires at least four PQ validators")
    latency_profile = load_latency_profile(
        latency_profile_path
        or install.source_dir / "test/pq-native/n6-scale-profiles/no-simulated-latency.json"
    )
    validate_latency_backend(latency_profile, backend.manifest())
    artifact_dir.mkdir(parents=True, exist_ok=False)
    network_dir = artifact_dir / "network"
    network_dir.mkdir()
    trace_paths: list[Path] = []
    resource_paths: list[Path] = []
    monitor_stop = asyncio.Event()
    monitors: list[asyncio.Task[None]] = []
    commit = subprocess.check_output(
        ["git", "-C", install.source_dir, "rev-parse", "HEAD"], text=True
    ).strip()
    criteria = install.source_dir / "doc/pq-native/N6-ACCEPTANCE-CRITERIA.json"
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "evidence_class": EVIDENCE_CLASS,
        "release_evidence_eligible": False,
        "git_commit": commit,
        "acceptance_criteria_sha256": hashlib.sha256(criteria.read_bytes()).hexdigest(),
        "backend": backend.manifest(),
        "validators": validators,
        "base_port": base_port,
        "latency_profile": asdict(latency_profile),
        "clock_domain": {
            "queueing_and_verification": "per-process monotonic",
            "local_propagation": "same-host wall clock",
            "remote_propagation": "requires externally synchronized host clocks",
        },
        "n5_closure": "PARKED_GAPS_PREVENT_RELEASE_EVIDENCE",
        "sustained_observation": asdict(sustained) if sustained is not None else None,
    }
    (artifact_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    validate_lite_transport_source(install.source_dir)

    async with Network(
        install, network_dir, base_port=base_port, process_backend=backend
    ) as network:
        network.config.shard_validators = validators
        if sustained is not None:
            consensus = network.config.mc_consensus
            if (
                consensus is None
                or consensus.target_block_rate_ms != sustained.target_block_rate_ms
            ):
                raise ValueError(
                    "N6_SUSTAINED_CONSENSUS_FAILURE: observation target does not match "
                    "the Genesis masterchain target block rate"
                )
        dht = network.create_dht_node()
        validator_nodes: list[Any] = []
        for index in range(validators):
            node = network.create_full_node()
            node.make_initial_pq_validator(
                hashlib.sha256(f"n6-validator-id-{index}".encode()).digest(),
                hashlib.sha256(f"n6-validator-seed-{index}".encode()).digest(),
            )
            node.announce_to(dht)
            validator_nodes.append(node)
        verifier = network.create_full_node()
        verifier.announce_to(dht)
        all_nodes = [*validator_nodes, verifier]
        for key_file in network_dir.glob("node*/keyring/*"):
            key_file.chmod(0o600)
        measurement_started_wall_ns = time.time_ns()
        await dht.run(StartOptions(threads=1, verbosity=3))
        for node in all_nodes:
            trace_path = node.directory / "n6-trace.jsonl"
            resource_path = node.directory / "n6-resource.jsonl"
            trace_paths.append(trace_path)
            resource_paths.append(resource_path)
            await node.run(
                StartOptions(
                    threads=2,
                    verbosity=4,
                    env={"TOS_N6_RESOURCE_JSONL": str(resource_path)},
                    args=(
                        "--measurement-jsonl",
                        str(trace_path),
                        "--measurement-node-id",
                        node.name,
                    ),
                )
            )
            if backend.manifest()["kind"] == "local-process":
                monitors.append(
                    asyncio.create_task(_resource_monitor(node, resource_path, monitor_stop))
                )

        startup_transport_retry_counts = {
            node.name: {"get_masterchain_info": 0} for node in all_nodes
        }
        await _wait_all_heights(
            all_nodes,
            3,
            120.0,
            transport_retry_counts=startup_transport_retry_counts,
        )
        sustained_result = (
            await observe_sustained_consensus(
                all_nodes,
                sustained,
                block_id_text(network.zerostate.as_block()),
                simplex_validator_names=[node.name for node in validator_nodes],
                wall_clocks_comparable=backend.manifest()["kind"] == "local-process",
            )
            if sustained is not None
            else None
        )
        deadline = time.monotonic() + 60.0
        evidence: FinalityRouteEvidence | None = None
        while time.monotonic() < deadline:
            try:
                evidence = analyze_live_finality(trace_paths)
                break
            except RuntimeError:
                await asyncio.sleep(0.25)
        if evidence is None:
            evidence = analyze_live_finality(trace_paths)
        milestones = analyze_consensus_milestones(trace_paths, measurement_started_wall_ns)

        lite: dict[str, Any] | None = None
        if require_lite:
            config_path = verifier.directory / "n6-lite-client.json"
            config_path.write_text(verifier.liteserver_config.to_json())
            command = f"blkproofchain {block_id_text(network.zerostate.as_block())}"
            started_ns = time.monotonic_ns()
            process = await backend.spawn(
                verifier.name,
                install.lite_client_exe,
                ["-C", str(config_path), "-r", "-t", "30", "-c", command],
                verifier.directory,
                os.environ.copy(),
                capture_stdout=True,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=45.0)
            elapsed_ns = time.monotonic_ns() - started_ns
            output = (stdout or b"").decode(errors="replace") + (stderr or b"").decode(
                errors="replace"
            )
            (artifact_dir / "lite-client.log").write_text(output)
            match = PROOF_BYTES.search(output)
            if (
                process.returncode != 0
                or match is None
                or "valid complete proof chain" not in output
            ):
                raise RuntimeError(
                    "N6_LITE_FRAMED_TCP_FAILURE: release lite-client did not fetch and verify a proof "
                    "over its ADNL external framed-TCP route"
                )
            lite = {
                "route": "AdnlExtClient/AdnlExtServer framed TCP",
                "proof_bytes": int(match.group("bytes")),
                "query_and_verification_ns": elapsed_ns,
                "verified": True,
            }

        node_results = [
            {
                "name": node.name,
                "role": "validator" if index < validators else "non-validator-verifier",
                "db_root": str(node.directory),
                "adnl_identity": node.adnl_identity.hex(),
                "ports": list(node.transport_ports),
                "log": str(node.log_path),
                "trace": str(trace_paths[index]),
                "resource_monitor": str(resource_paths[index]),
            }
            for index, node in enumerate(all_nodes)
        ]
        validate_node_isolation(node_results)
        if any(not path.is_file() or path.stat().st_size == 0 for path in resource_paths):
            raise RuntimeError(
                "N6_CLUSTER_ISOLATION_FAILURE: a node has no resource-monitor output"
            )
        result = {
            "schema_version": 1,
            "evidence_class": EVIDENCE_CLASS,
            "release_evidence_eligible": False,
            "backend": backend.manifest(),
            "nodes": node_results,
            "live_finality": asdict(evidence),
            "consensus_milestones": asdict(milestones),
            "startup_lite_transport_retries": _lite_transport_retry_summary(
                startup_transport_retry_counts
            ),
            "sustained_observation": sustained_result,
            "lite": lite,
            "consensus_correctness_verdict": "NOT_MADE_MERKLE_DIAGNOSIS_OPEN",
        }
        (artifact_dir / "result.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n"
        )
        monitor_stop.set()
        await asyncio.gather(*monitors)
        return result


async def run_scale_sweep(
    install: Any,
    artifact_dir: Path,
    backend: Any,
    scales: list[int],
    profile_path: Path,
    base_port: int,
    allow_local_diagnostic_scales: bool = False,
) -> dict[str, Any]:
    if not scales or len(scales) != len(set(scales)) or any(scale < 4 for scale in scales):
        raise ValueError("N6_SCALE_SWEEP_FAILURE: scales must be unique integers of at least four")
    profile = load_latency_profile(profile_path)
    local_multi_scale = backend.manifest()["kind"] == "local-process" and scales != [4]
    if local_multi_scale and not allow_local_diagnostic_scales:
        raise ValueError(
            "N6_SCALE_SWEEP_FAILURE: this local host is restricted to the 4-validator minimum-BFT tier"
        )
    criteria = json.loads(
        (install.source_dir / "doc/pq-native/N6-ACCEPTANCE-CRITERIA.json").read_text(
            encoding="utf-8"
        )
    )
    required_release_scales = criteria.get("required_scales")
    if required_release_scales != [21]:
        raise ValueError(
            "N6_SCALE_SWEEP_FAILURE: the precommitted release scale requirement changed"
        )
    artifact_dir.mkdir(parents=True, exist_ok=False)
    points: list[dict[str, Any]] = []
    for index, scale in enumerate(scales):
        point = await run_cluster(
            install,
            artifact_dir / f"validators-{scale}",
            backend,
            scale,
            base_port + index * 1000,
            False,
            profile_path,
        )
        booted_validators = sum(1 for node in point["nodes"] if node["role"] == "validator")
        if booted_validators != scale:
            raise RuntimeError(
                f"N6_SCALE_SWEEP_FAILURE: requested scale {scale} booted {booted_validators} validators"
            )
        points.append(
            {
                "requested_validators": scale,
                "booted_validators": booted_validators,
                "fault_tolerance": (scale - 1) // 3,
                **point["consensus_milestones"],
            }
        )
    result = {
        "schema_version": 1,
        "evidence_class": "MINIMUM_BFT_FUNCTIONAL_DIAGNOSTIC",
        "release_evidence_eligible": False,
        "latency_profile": asdict(profile),
        "scale_points": points,
        "required_release_scales": required_release_scales,
        "required_release_scales_measured": [],
        "full_required_matrix_executed": False,
        "local_colocation_diagnostic_override": local_multi_scale,
        "consensus_correctness_verdict": "NOT_MADE_MERKLE_DIAGNOSIS_OPEN",
    }
    (artifact_dir / "scale-sweep-result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result
