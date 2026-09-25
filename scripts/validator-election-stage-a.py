#!/usr/bin/env python3
"""Run a validator-election launch-gate rehearsal on a local network.

Stage A is an accelerated, opt-in, throwaway integration exercise. Stage B
uses the unmodified production election periods and initial validator-set
lifetime. Both preserve the production candidate's contracts,
validator-count rules, stake limits, rewards, and message paths.

The script starts one DHT node and four validator processes on loopback,
deploys four admitted PQ controllers, four pools and five masterchain wallets,
submits two target elections and a rollover through node-authorized pool
orders, recovers both target rounds to their pools, injects restart/quorum
faults, and writes JSONL metrics plus a final JSON report under the selected
stage's test/integration output directory.

The opt-in ``experiment`` mode keeps the same accelerated Stage-A protocol
profile, but runs a stable four-validator network beside a longer application
experiment.  It exposes one loopback JSON-RPC endpoint per validator, publishes
a readiness manifest without private key material, continuously participates
in elections and recovers matured stakes, and emits validator reward/election
allocation evidence.  The default remains the finite launch-gate rehearsal.

``fixture-check`` is a deliberately narrower diagnostic: four real PQ
controllers and four single-nominator pools are deployed, and the Genesis
ConfigParam 47 policy is read back from the live chain. It makes no claim that
an election occurred; the launch-gate path is converted in the next unit.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import random
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Awaitable, Callable, TypeVar

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "test/tostester/src"))
sys.path.insert(0, str(REPO / "scripts"))

from contract import WalletV1, WalletV1Blueprint  # noqa: E402
from contract.pq_auth import byte_chain  # noqa: E402
from pytosiq_core import (  # noqa: E402
    Address,
    Builder,
    Cell,
    CurrencyCollection,
    InternalMsgInfo,
    MessageAny,
    WalletMessage,
)
from pytosiq_core.tlb.config import ConfigParam8  # noqa: E402
from tosapi import tos_api, toslib_api  # noqa: E402
from toslib.errors import LocalError, RemoteError  # noqa: E402
from tostester.install import Install  # noqa: E402
from tostester.network import FullNode, Network, NetworkConfig, StartOptions  # noqa: E402
from tostester.f01_stage_a_evidence import (  # noqa: E402
    config34_hash, extract_finalized_log, locate_transition, write_manifest,
)
from x01_window_evidence import validate as validate_x01_window  # noqa: E402
from tostester.pq_initial_validator import (  # noqa: E402
    make_deterministic_pq_initial_validator,
)
from tostester.pq_election_fixture import (  # noqa: E402
    ControllerFixture,
    PoolFixture,
    assert_controller_identity,
    build_production_pool_stake_order,
    elector_reply,
    compile_controller_code,
    make_controller_fixture,
    make_pool_fixture,
    parse_past_elections_list,
    participant_ids_from_runmethod,
    require_pq_stake_authorization_binding,
)

NANO = 1_000_000_000
VALIDATOR_COUNT = 4
ELECTOR = Address((-1, bytes.fromhex("33" * 32)))
EFFECTIVE_STAKE = 10_000 * NANO
PQ_STAKE_MESSAGE_VALUE = 11_000 * NANO  # sandbox-tested margin above the 10,000 TOS floor
VALIDATOR_WALLET_FUNDING = 20_020 * NANO
EXPERIMENT_CONCURRENT_STAKE_CAPACITY = 3
PQ_EXPERIMENT_POOL_CAPITAL = (
    EXPERIMENT_CONCURRENT_STAKE_CAPACITY * (PQ_STAKE_MESSAGE_VALUE + 20 * NANO)
)
EXPERIMENT_OPERATOR_FEE_RESERVE = 1_000 * NANO
EXPERIMENT_VALIDATOR_WALLET_FUNDING = (
    PQ_EXPERIMENT_POOL_CAPITAL + EXPERIMENT_OPERATOR_FEE_RESERVE
)
NEGATIVE_WALLET_FUNDING = 15_000 * NANO
EXPERIMENT_FAUCET_FEE_RESERVE = 1_000 * NANO
EXPERIMENT_GENESIS_FAUCET_FUNDING = (
    VALIDATOR_COUNT * EXPERIMENT_VALIDATOR_WALLET_FUNDING
    + NEGATIVE_WALLET_FUNDING
    + VALIDATOR_COUNT * 10 * NANO  # admitted controller deployment
    + EXPERIMENT_FAUCET_FEE_RESERVE
)
PQ_FULL_FOLLOWUP_FAUCET_CAPITAL = (
    2 * VALIDATOR_COUNT * (PQ_STAKE_MESSAGE_VALUE + 40 * NANO)
)
PQ_FULL_FAUCET_FEE_RESERVE = 1_000 * NANO
PQ_FULL_GENESIS_FAUCET_FUNDING = (
    VALIDATOR_COUNT * VALIDATOR_WALLET_FUNDING
    + NEGATIVE_WALLET_FUNDING
    + VALIDATOR_COUNT * 10 * NANO  # controller deployment from the faucet
    + PQ_FULL_FOLLOWUP_FAUCET_CAPITAL
    + 2 * PQ_FULL_FAUCET_FEE_RESERVE  # fees before read-back, then retained reserve
)
MAX_FACTOR = 1 << 16
MAX_ARCHIVE_FDS = 512
ROCKSDB_CACHE_BYTES = 256 * 1024 * 1024
DEFAULT_EXPERIMENT_DURATION = 3 * 60 * 60
DEFAULT_SETTLEMENT_TAIL = 15 * 60
DEFAULT_RPC_BASE_PORT = 8111
# Masterchain full-shard prefix (0x8000000000000000) as the signed-int64 string the
# JSON-RPC block-lookup methods expect.
MASTERCHAIN_SHARD_STR = "-9223372036854775808"
# A restarted node's own log (truncated to its post-restart run) must contain no fault.
_FATAL_RE = re.compile(
    r"\b(FATAL|PANIC|CHECK failed|LOG_CHECK failed|AddressSanitizer|UndefinedBehaviorSanitizer|Aborted)\b"
)
T = TypeVar("T")


@dataclass(frozen=True)
class RehearsalProfile:
    stage: str
    label: str
    elected_for: int
    elect_start_before: int
    elect_end_before: int
    stakes_frozen_for: int
    initial_set_valid: int
    accelerated: bool


@dataclass(frozen=True)
class ExperimentProfile:
    """Runtime-only settings for the parallel validator experiment."""

    duration_seconds: float
    settlement_tail_seconds: float
    rpc_host: str
    rpc_base_port: int

    def __post_init__(self) -> None:
        if self.duration_seconds <= 0:
            raise ValueError("experiment duration must be positive")
        if self.settlement_tail_seconds < 0:
            raise ValueError("settlement tail must not be negative")
        try:
            host = ip_address(self.rpc_host)
        except ValueError as error:
            raise ValueError("experiment RPC host must be an IP address") from error
        if host.version != 4 or not host.is_loopback:
            raise ValueError("experiment JSON-RPC must bind to an IPv4 loopback address")
        last_port = self.rpc_base_port + VALIDATOR_COUNT - 1
        if self.rpc_base_port <= 0 or last_port > 65_535:
            raise ValueError("experiment RPC base port must reserve four valid consecutive ports")

    @property
    def rpc_addresses(self) -> list[str]:
        return [f"{self.rpc_host}:{self.rpc_base_port + index}" for index in range(VALIDATOR_COUNT)]


PROFILES = {
    "a": RehearsalProfile(
        stage="a",
        label="Stage A",
        elected_for=300,
        elect_start_before=180,
        elect_end_before=60,
        stakes_frozen_for=180,
        initial_set_valid=600,
        accelerated=True,
    ),
    "b": RehearsalProfile(
        stage="b",
        label="Stage B",
        elected_for=65_536,
        elect_start_before=32_768,
        elect_end_before=8_192,
        stakes_frozen_for=32_768,
        initial_set_valid=131_072,
        accelerated=False,
    ),
}


def f01_profile(profile: RehearsalProfile, enabled: bool) -> RehearsalProfile:
    """Give only the opt-in F01 Stage-A run time for four serial stake receipts."""
    if not enabled:
        return profile
    if profile.stage != "a":
        raise ValueError("F01 extended election window requires Stage A")
    return replace(profile, label="Stage A F01 extended window", elect_start_before=240)


@dataclass
class Config34:
    utime_since: int
    utime_until: int
    total: int
    main: int
    total_weight: int
    validator_ids: list[str]
    public_keys: list[str]
    adnl_ids: list[str]
    validator_adnl_pairs: list[tuple[str, str]]
    raw: str


def parse_pq_validator_adnl_pairs(output: str) -> list[tuple[str, str]]:
    """Bind identity and ADNL from the same decoded ConfigParam 34 record."""
    markers = list(re.finditer(r"\bvalidator_pq\b", output))
    identities = list(re.finditer(
        r"\bvalidator_pq\s+validator_id:x([0-9A-Fa-f]{64})", output
    ))
    if len(markers) != len(identities):
        raise ValueError(
            "ConfigParam 34 has a PQ validator record without a 256-bit validator_id"
        )
    pairs = []
    for index, identity in enumerate(identities):
        end = identities[index + 1].start() if index + 1 < len(identities) else len(output)
        section = output[identity.end():end]
        adnl = re.findall(r"\badnl_addr:x([0-9A-Fa-f]{64})", section)
        if len(adnl) != 1:
            raise ValueError(
                f"ConfigParam 34 PQ validator {identity.group(1)} has {len(adnl)} ADNL IDs, expected one"
            )
        pairs.append((identity.group(1).upper(), adnl[0].upper()))
    if len({identity for identity, _ in pairs}) != len(pairs):
        raise ValueError("ConfigParam 34 repeats a PQ validator ID")
    if len({adnl for _, adnl in pairs}) != len(pairs):
        raise ValueError("ConfigParam 34 repeats a PQ validator ADNL ID")
    return pairs


def require_pq_config34_associations(
    config: Config34, expected: dict[str, str]
) -> None:
    actual = dict(config.validator_adnl_pairs)
    if len(config.validator_adnl_pairs) != len(expected) or actual != expected:
        raise AssertionError(
            "PQ elected ConfigParam 34 controller-to-ADNL association differs: "
            f"expected={expected} actual={actual}"
        )


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def utc_at(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).isoformat()


def raw_address(address: Address) -> str:
    return f"{address.wc}:{address.hash_part.hex()}"


def recovery_attribution(election_ids: list[int]) -> dict[str, str]:
    """Describe what an Elector credit proves without splitting aggregate rewards."""

    if not election_ids:
        raise ValueError("recovery attribution requires at least one election")
    if len(election_ids) == 1:
        return {
            "attribution_status": "exact-single-election",
            "pool_aggregate_attribution_status": "EXACT",
            "per_election_reward_attribution_status": "EXACT",
        }
    return {
        "attribution_status": "pool-exact-multi-election-aggregate",
        "pool_aggregate_attribution_status": "EXACT",
        "per_election_reward_attribution_status": "NOT_ATTRIBUTABLE",
    }


def write_json_atomic(path: Path, value: Any) -> None:
    """Publish machine-consumed evidence without exposing a partial JSON file."""

    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def json_rpc_call(
    address: str,
    method: str,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    ).encode()
    request = urllib.request.Request(
        f"http://{address}/jsonRPC",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=8) as response:
        result = json.loads(response.read().decode())
    if result.get("error") is not None or result.get("result") is None:
        raise RuntimeError(f"JSON-RPC {address} {method} failed: {result}")
    return result


def internal_message(
    src: Address,
    dest: Address,
    amount: int,
    body: Cell,
    *,
    init=None,
) -> WalletMessage:
    return WalletMessage(
        send_mode=3,
        message=MessageAny(
            info=InternalMsgInfo(
                ihr_disabled=True,
                bounce=False,
                bounced=False,
                src=src,
                dest=dest,
                value=CurrencyCollection(tomis=amount),
                ihr_fee=0,
                fwd_fee=0,
                created_lt=0,
                created_at=0,
            ),
            init=init,
            body=body,
        ),
    )


class ValidatorElectionRehearsal:
    def __init__(
        self,
        *,
        run_dir: Path,
        base_port: int,
        build_dir: Path,
        sample_interval: float,
        profile: RehearsalProfile,
        experiment: ExperimentProfile | None = None,
        enable_consensus_cleanup: bool = False,
        consensus_cleanup_state_ttl: int = 0,
        consensus_cleanup_archive_ttl: int = 0,
        measure_live_rejoin: bool = False,
        live_rejoin_only: bool = False,
        soak_mode: bool = False,
        soak_duration: float = 600.0,
        soak_min_interval: float = 1.0,
        soak_max_interval: float = 5.0,
        soak_wallet_funding_tos: int = 2000,
        fixture_only: bool = False,
        pq_election: bool = False,
        pq_full: bool = False,
    ):
        self.run_dir = run_dir
        self.network_dir = run_dir / "network"
        self.artifacts_dir = run_dir / "artifacts"
        # ACCEPTANCE-ONLY opt-in: after readiness, restart a non-zero validator while its
        # peers keep producing and prove it rejoins live consensus (syncs the blocks it
        # missed and tracks the advancing tip). live_rejoin_only returns right after, for
        # a fast dedicated rejoin run instead of the full election window. Default off.
        self.measure_live_rejoin = measure_live_rejoin
        self.live_rejoin_only = live_rejoin_only
        self.live_rejoin_result: dict[str, Any] | None = None
        # transfer-soak mode: randomized A/B/C transfers under real block production, with
        # cross-node balance (到账) consistency checks. Leak monitoring is external
        # (scripts/soak-mem-monitor.py).
        self.soak_mode = soak_mode
        self.soak_duration = soak_duration
        self.soak_min_interval = soak_min_interval
        self.soak_max_interval = soak_max_interval
        self.soak_wallet_funding = soak_wallet_funding_tos * NANO
        self.fixture_only = fixture_only
        # The long-running election experiment also places real stakes. It
        # must use the same PQ Genesis, controller identities and pool route
        # as the finite launch gate; transfer-soak does not place stakes.
        self.pq_election = pq_election or (experiment is not None and not soak_mode)
        self.pq_full = pq_full
        if pq_full and not self.pq_election:
            raise ValueError("the full PQ rehearsal requires the PQ election fixture")
        if pq_full and not profile.accelerated:
            raise ValueError("the full PQ diagnostic faucet is defined only for Stage A")
        self.controller_code: Cell | None = None
        self.pool_code: Cell | None = None
        self.controllers: list[ControllerFixture] = []
        self.pools: list[PoolFixture] = []
        # ACCEPTANCE-ONLY opt-in: arm the gated validator consensus-DB cleanup on every
        # validator engine and shrink state/archive TTLs so the GC floor can advance
        # once the election produces a post-genesis key block. Default off leaves the
        # rehearsal's behaviour byte-for-byte unchanged.
        self.enable_consensus_cleanup = enable_consensus_cleanup
        self.consensus_cleanup_state_ttl = consensus_cleanup_state_ttl
        self.consensus_cleanup_archive_ttl = consensus_cleanup_archive_ttl
        self.base_port = base_port
        self.original_build_dir = build_dir.absolute()
        self.install = Install(self.original_build_dir, REPO)
        self.sample_interval = sample_interval
        self.profile = profile
        self.experiment = experiment
        self.long_poll_interval = 1.0 if profile.accelerated else 30.0
        self.events: list[dict[str, Any]] = []
        self.failures: list[str] = []
        self.metrics_path = run_dir / "metrics.jsonl"
        self.report_path = run_dir / "report.json"
        self.f01_directory = self.artifacts_dir / "f01-finality"
        self.f01_segments: dict[str, list[dict[str, Any]]] = {}
        self.f01_process_generations: dict[str, list[dict[str, Any]]] = {}
        self.f01_transitions: list[dict[str, Any]] = []
        self.f01_previous_config_height: int | None = None
        self.f01_previous_config_hash: str | None = None
        self.f01_capture_provenance: dict[str, Any] | None = None
        self.x01_directory = self.artifacts_dir / "x01-fault-window"
        self.x01_policy: dict[str, Any] | None = None
        self.x01_trace: dict[str, Any] = {"faults": [], "restarts": [], "phases": {}}
        self.x01_policy_sha256: str | None = None
        self.x01_capture_provenance: dict[str, Any] | None = None
        self.lite_config = run_dir / "lite-client.json"
        self.network: Network | None = None
        self.nodes: list[FullNode] = []
        self.client = None
        self.monitor_task: asyncio.Task[None] | None = None
        self._monitor_stop = asyncio.Event()
        self.first_election_id = 0
        self.second_election_id = 0
        self.rollover_election_id = 0
        self.first_credits: list[int] = []
        self.second_credits: list[int] = []
        self.initial_config34: Config34 | None = None
        self.first_config34: Config34 | None = None
        self.second_config34: Config34 | None = None
        self.rollover_config34: Config34 | None = None
        self.wallets: list[WalletV1] = []
        self.negative_wallet: WalletV1 | None = None
        self.wallet_balance_history: dict[str, list[dict[str, Any]]] = {}
        self.provenance: dict[str, Any] = {}
        self.readiness_path = run_dir / "readiness-manifest.json"
        self.allocation_evidence_path = run_dir / "reward-election-allocation-evidence-v4.json"
        self.experiment_started_at: str | None = None
        self.experiment_deadline_at: str | None = None
        self.settlement_deadline_at: str | None = None
        self.experiment_final_status: str | None = None
        self.experiment_last_chain_timestamp: int | None = None
        self.experiment_current_config34_since: int | None = None
        self.experiment_current_config34_hash: int | None = None
        self.experiment_past_elections: dict[int, dict[str, int]] | None = None
        self.election_allocations: dict[int, dict[str, Any]] = {}
        self.recovery_records: list[dict[str, Any]] = []
        self.rpc_readiness: list[dict[str, Any]] = []

    def validator_wallet_funding(self) -> int:
        if self.experiment is not None:
            return EXPERIMENT_VALIDATOR_WALLET_FUNDING
        return VALIDATOR_WALLET_FUNDING

    def configure_network_profile(self, config: NetworkConfig) -> None:
        config.shard_validators = VALIDATOR_COUNT
        config.validator_economics_profile = True
        config.validator_election_stage_a_profile = self.profile.accelerated
        if self.profile.stage == "a" and self.profile.elect_start_before != PROFILES["a"].elect_start_before:
            config.validator_election_stage_a_start_before = self.profile.elect_start_before
        if self.fixture_only or self.pq_election:
            if self.controller_code is None:
                raise AssertionError("PQ controller code was not compiled before Genesis")
            # This is an explicitly diagnostic fixture while canonical production
            # genesis stays at v14 pending its coordinated v16 activation.
            config.global_version = 16
            config.validator_controller_code_hash = self.controller_code.hash
        if self.pq_full:
            config.validator_election_experiment_faucet_balance_nanotos = (
                PQ_FULL_GENESIS_FAUCET_FUNDING
            )
        elif self.experiment is not None:
            config.validator_election_experiment_faucet_balance_nanotos = (
                EXPERIMENT_GENESIS_FAUCET_FUNDING
            )
        else:
            config.validator_election_experiment_faucet_balance_nanotos = None

    def validator_start_options(self, validator_index: int | None = None) -> StartOptions:
        # Keep archive RocksDB/package handles bounded during the multi-day
        # Stage B run. The engine has the same safe default; spelling it out
        # here makes the rehearsal invariant explicit in its provenance.
        args = [
            "--max-archive-fd",
            str(MAX_ARCHIVE_FDS),
            # CellDB V2 otherwise raises its independent RocksDB cache to
            # cache_size_max * 5000 (5 GB with the default entry count).
            # Both values are required: cache-size alone is raised to the
            # computed minimum during CellDB initialization.
            "--celldb-cache-size",
            str(ROCKSDB_CACHE_BYTES),
            "--celldb-cache-min-size",
            str(ROCKSDB_CACHE_BYTES),
        ]
        if self.experiment is not None:
            if validator_index is None:
                raise ValueError("experiment validator start requires an index")
            args += [
                "--json-rpc-address",
                self.experiment.rpc_addresses[validator_index],
                # Loopback JSON-RPC in this harness: expose the read-only consensus-status
                # admin method so the acceptance probe can cross-check nodes for divergence.
                "--json-rpc-expose-consensus-status",
            ]
        elif self.pq_full:
            if validator_index is None or self.base_port + 500 + validator_index > 65_535:
                raise ValueError("F01 Stage A per-validator RPC port is unavailable")
            args += ["--json-rpc-address", f"127.0.0.1:{self.base_port + 500 + validator_index}"]
        if self.enable_consensus_cleanup:
            args += ["--enable-validator-consensus-cleanup"]
            if self.consensus_cleanup_state_ttl > 0:
                args += ["--state-ttl", str(self.consensus_cleanup_state_ttl)]
            if self.consensus_cleanup_archive_ttl > 0:
                args += ["--archive-ttl", str(self.consensus_cleanup_archive_ttl)]
        return StartOptions(
            args=tuple(args),
            env={
                # Use the repository's documented low-memory canary profile.
                # Critical and background databases have independent budgets
                # so archive flush pressure cannot stall consensus writes.
                "TOS_ROCKSDB_BLOCK_CACHE_SIZE": str(ROCKSDB_CACHE_BYTES),
                "TOS_ROCKSDB_WRITE_BUFFER_SIZE": str(16 * 1024 * 1024),
                "TOS_ROCKSDB_TRANSACTION_HISTORY_SIZE": str(16 * 1024 * 1024),
                "TOS_ROCKSDB_GLOBAL_WRITE_BUFFER_SIZE": str(256 * 1024 * 1024),
                "TOS_ROCKSDB_GLOBAL_WRITE_BUFFER_ALLOW_STALL": "1",
                "TOS_ROCKSDB_CRITICAL_WRITE_BUFFER_SIZE": str(256 * 1024 * 1024),
                "TOS_ROCKSDB_CRITICAL_WRITE_BUFFER_ALLOW_STALL": "1",
                "MALLOC_CONF": ("background_thread:true,dirty_decay_ms:10000,muzzy_decay_ms:10000"),
                "TOS_MEMORY_DIAGNOSTICS": "1",
            },
            threads=4,
            verbosity=3,
        )

    @staticmethod
    def file_provenance(path: Path) -> dict[str, Any]:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        stat = path.stat()
        return {
            "path": str(path),
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "sha256": digest.hexdigest(),
        }

    @staticmethod
    def config34_evidence(config: Config34 | None) -> dict[str, Any] | None:
        if config is None:
            return None
        return {
            "utime_since": config.utime_since,
            "utime_until": config.utime_until,
            "total": config.total,
            "main": config.main,
            "total_weight": config.total_weight,
            "public_keys": config.public_keys,
            "adnl_ids": config.adnl_ids,
            "raw_sha256": hashlib.sha256(config.raw.encode()).hexdigest(),
        }

    def zero_state_evidence(self) -> dict[str, Any]:
        assert self.network is not None
        zero_state = self.network.zerostate
        return {
            "masterchain": {
                "workchain": -1,
                "root_hash_hex": zero_state.masterchain.root_hash.hex(),
                "file_hash_hex": zero_state.masterchain.file_hash.hex(),
                "boc": self.file_provenance(zero_state.masterchain.file),
            },
            "basechain": {
                "workchain": 0,
                "root_hash_hex": zero_state.shardchain.root_hash.hex(),
                "file_hash_hex": zero_state.shardchain.file_hash.hex(),
                "boc": self.file_provenance(zero_state.shardchain.file),
            },
        }

    def validator_identity_evidence(self, index: int) -> dict[str, Any]:
        node = self.nodes[index]
        wallet = self.wallets[index]
        controller = self.controllers[index]
        pool = self.pools[index]
        rpc_address = self.experiment.rpc_addresses[index] if self.experiment is not None else None
        peer_port = node.transport_ports[0]
        if rpc_address is not None and int(rpc_address.rsplit(":", 1)[1]) in node.transport_ports:
            raise ValueError(f"validator {index + 1} RPC port overlaps peer transport")
        return {
            "validator_index": index + 1,
            "node_name": node.name,
            "controller_id_hex": controller.address.hash_part.hex(),
            "consensus_key_id_hex": controller.consensus.key_id.hex(),
            "adnl_id_hex": node.validator_key.id.hex(),
            "peer_transport": {"protocol": "udp", "ip": "127.0.0.1", "port": peer_port},
            "node_data_dir": str(node.directory.resolve()),
            "process_id": node.process_id,
            "operator_wallet_raw": raw_address(wallet.address),
            "operator_wallet_role": "funds pool capital and sends node-authorized pool orders",
            "pool_stake_owner_raw": raw_address(pool.address),
            "recovery_destination_raw": raw_address(pool.address),
            "rpc_address": rpc_address,
            "rpc_url": f"http://{rpc_address}/jsonRPC" if rpc_address else None,
        }

    def ensure_experiment_rpc_ports_available(self) -> None:
        if self.experiment is None:
            return
        reservations: list[socket.socket] = []
        try:
            for address in self.experiment.rpc_addresses:
                host, port = address.rsplit(":", 1)
                reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                reservation.bind((host, int(port)))
                reservations.append(reservation)
        except OSError as error:
            raise RuntimeError(
                f"experiment JSON-RPC port reservation failed at {address}: {error}"
            ) from error
        finally:
            for reservation in reservations:
                reservation.close()

    async def wait_json_rpc_readiness(self) -> list[dict[str, Any]]:
        if self.experiment is None:
            return []

        async def wait_one(index: int, address: str) -> dict[str, Any]:
            response = await self.retry(
                lambda: asyncio.to_thread(json_rpc_call, address, "getMasterchainInfo"),
                timeout=120,
                interval=0.5,
                description=f"validator {index + 1} JSON-RPC readiness",
                predicate=lambda value: value.get("result") is not None,
            )
            result = response["result"]
            assert self.network is not None
            expected_root = base64.b64encode(
                self.network.zerostate.masterchain.root_hash
            ).decode()
            expected_file = base64.b64encode(
                self.network.zerostate.masterchain.file_hash
            ).decode()
            init = result.get("init") or {}
            if (
                init.get("root_hash") != expected_root
                or init.get("file_hash") != expected_file
            ):
                raise AssertionError(
                    f"validator {index + 1} JSON-RPC zero-state mismatch"
                )
            return {
                "validator_index": index + 1,
                "address": address,
                "url": f"http://{address}/jsonRPC",
                "method": "getMasterchainInfo",
                "ready": True,
                "observed_at": utc_now(),
                "last": result.get("last"),
                "state_root_hash": result.get("state_root_hash"),
                "init": init,
            }

        return list(
            await asyncio.gather(
                *(
                    wait_one(index, address)
                    for index, address in enumerate(self.experiment.rpc_addresses)
                )
            )
        )

    async def rpc_config34_consensus(self, expected_since: int) -> dict[str, Any]:
        """Read the decoded validator allocation independently from all nodes."""

        assert self.experiment is not None

        async def read_one(address: str) -> dict[str, Any]:
            response = await asyncio.to_thread(
                json_rpc_call,
                address,
                "getConfigParam",
                {"param": 34},
            )
            result = response["result"]
            validator_set = result.get("validator_set")
            if not isinstance(validator_set, dict):
                raise RuntimeError(f"JSON-RPC {address} did not decode ConfigParam 34")
            config_bytes = result.get("config", {}).get("bytes")
            return {
                "address": address,
                "observed_at": utc_now(),
                "validator_set": validator_set,
                "config_boc_base64_sha256": (
                    hashlib.sha256(config_bytes.encode()).hexdigest()
                    if isinstance(config_bytes, str)
                    else None
                ),
            }

        async def read_all() -> list[dict[str, Any]]:
            return list(
                await asyncio.gather(
                    *(read_one(address) for address in self.experiment.rpc_addresses)
                )
            )

        def converged(observations: list[dict[str, Any]]) -> bool:
            canonical = json.dumps(
                observations[0]["validator_set"],
                sort_keys=True,
                separators=(",", ":"),
            )
            return all(
                int(item["validator_set"]["utime_since"]) == expected_since
                and json.dumps(
                    item["validator_set"],
                    sort_keys=True,
                    separators=(",", ":"),
                )
                == canonical
                for item in observations
            )

        observations = await self.retry(
            read_all,
            timeout=60,
            interval=1,
            description=f"four-node JSON-RPC ConfigParam 34 at {expected_since}",
            predicate=converged,
        )
        canonical = json.dumps(
            observations[0]["validator_set"], sort_keys=True, separators=(",", ":")
        )
        if any(
            json.dumps(item["validator_set"], sort_keys=True, separators=(",", ":")) != canonical
            for item in observations[1:]
        ):
            raise AssertionError("four JSON-RPC nodes disagree on ConfigParam 34")
        return {
            "status": "four-node-consensus",
            "validator_set_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
            "observations": observations,
        }

    def readiness_manifest(self) -> dict[str, Any]:
        if self.experiment is None:
            raise RuntimeError("readiness manifest is only defined in experiment mode")
        return {
            "schema": "tos.validator-election-experiment-readiness.v2",
            "schema_version": 2,
            "status": "ready",
            "ready_at": utc_now(),
            "mode": "experiment",
            "run_dir": str(self.run_dir),
            "network": {
                "topology": "single-host-four-process-local-network",
                "validator_count": VALIDATOR_COUNT,
                "internal_base_port": self.base_port,
                "genesis_faucet_funding_nanotos": EXPERIMENT_GENESIS_FAUCET_FUNDING,
                "pool_capital_per_validator_nanotos": PQ_EXPERIMENT_POOL_CAPITAL,
                "lite_client_config": str(self.lite_config),
                "zero_state": self.zero_state_evidence(),
                "initial_config34": self.config34_evidence(self.initial_config34),
            },
            "rpc": {
                "transport": "loopback-http-json-rpc",
                "base_port": self.experiment.rpc_base_port,
                "endpoints": self.rpc_readiness,
            },
            "validators": [
                self.validator_identity_evidence(index) for index in range(VALIDATOR_COUNT)
            ],
            "election": {
                "elector_raw": raw_address(ELECTOR),
                "profile": asdict(self.profile),
                "minimum_stake_nanotos": EFFECTIVE_STAKE,
                "stake_message_value_nanotos": PQ_STAKE_MESSAGE_VALUE,
                "operator_wallet_funding_nanotos": self.validator_wallet_funding(),
                "supported_concurrent_unrecovered_stakes": (
                    EXPERIMENT_CONCURRENT_STAKE_CAPACITY
                ),
                "mapping_status": "declared-before-first-election",
                "mapping_becomes_on_chain": (
                    "when each node-authorized pool order is accepted and ConfigParam 34 activates"
                ),
            },
            "window": {
                "started_at": self.experiment_started_at,
                "deadline_at": self.experiment_deadline_at,
                "settlement_deadline_at": self.settlement_deadline_at,
                "duration_seconds": self.experiment.duration_seconds,
                "settlement_tail_seconds": (self.experiment.settlement_tail_seconds),
            },
            "allocation_evidence": str(self.allocation_evidence_path),
            "metrics": str(self.metrics_path),
            "manifest_contains_private_key_material": False,
            "run_directory_contains_private_runtime_keys": True,
            "provenance": {
                "source_commit": self.provenance.get("source_commit"),
                "artifact_snapshot": str(self.run_dir / "artifact-snapshot"),
            },
        }

    def experiment_retention_state(self, election_id: int) -> str:
        """Classify a retained stake from the live set and Elector's true clock.

        The initial election schedule is not an unfreeze promise: when a set
        retires, Elector resets its unfreeze time to now + stake_held, and it
        never unfreezes the current active set.
        """
        current = self.experiment_current_config34_since
        current_hash = self.experiment_current_config34_hash
        past = self.experiment_past_elections
        now = self.experiment_last_chain_timestamp
        if current is None or current_hash is None or past is None or now is None:
            return "unmeasured"
        entry = past.get(election_id)
        recorded_hash = self.election_allocations[election_id].get("config34_cell_hash")
        if recorded_hash is None or (entry is not None and entry["vset_hash"] != recorded_hash):
            return "unmeasured"
        if election_id == current:
            if entry is None or entry["vset_hash"] != current_hash:
                return "unmeasured"
            return "active-retained"
        if entry is not None and now < entry["unfreeze_at"]:
            return "retired-frozen"
        return "matured-unrecovered"

    def allocation_evidence(self, status: str) -> dict[str, Any]:
        validators: list[dict[str, Any]] = []
        missing_primary_allocations: list[dict[str, Any]] = []
        for index in range(VALIDATOR_COUNT):
            identity = self.validator_identity_evidence(index)
            allocations: list[dict[str, Any]] = []
            validator_missing_primary: list[dict[str, Any]] = []
            for election_id in sorted(self.election_allocations):
                allocation = self.election_allocations[election_id]
                candidate = allocation.get("validators", {}).get(str(index + 1))
                if candidate is None:
                    if allocation.get("purpose") == "primary-window":
                        missing = {
                            "election_id": election_id,
                            "purpose": "primary-window",
                            "validator_index": index + 1,
                            "operator_wallet_raw": identity["operator_wallet_raw"],
                            "pool_stake_owner_raw": identity["pool_stake_owner_raw"],
                            "candidate_status": "NOT_RECORDED",
                            "selection_status": "NOT_ATTRIBUTABLE",
                            "recovery_status": "OUTSTANDING",
                            "reward_attribution_status": "NOT_ATTRIBUTABLE",
                            "reason": (
                                "no accepted candidate record exists for this primary-window "
                                "validator slot"
                            ),
                        }
                        validator_missing_primary.append(missing)
                        missing_primary_allocations.append(missing)
                    continue
                rendered_candidate = {
                    "election_id": election_id,
                    "purpose": allocation["purpose"],
                    **candidate,
                }
                if candidate.get("recovery_status") == "retained-settlement-rollover":
                    rendered_candidate["retention_state"] = self.experiment_retention_state(
                        election_id
                    )
                allocations.append(rendered_candidate)
            recovered = [
                record for record in self.recovery_records if record["validator_index"] == index + 1
            ]
            identity.update(
                {
                    "elections": allocations,
                    "missing_primary_allocations": validator_missing_primary,
                    "recovery_records": recovered,
                    "aggregate": {
                        "candidate_count": len(allocations),
                        "missing_primary_candidate_count": len(validator_missing_primary),
                        "selected_count": sum(
                            1 for item in allocations if item.get("selection_status") == "selected"
                        ),
                        "recovered_principal_nanotos": sum(
                            item["principal_nanotos"] for item in recovered
                        ),
                        "credited_nanotos": sum(item["credit_nanotos"] for item in recovered),
                        "reward_nanotos": sum(item["reward_nanotos"] for item in recovered),
                    },
                }
            )
            validators.append(identity)

        recovered_statuses = {"recovered", "recovered-in-aggregate"}
        outstanding_recorded = sum(
            1
            for validator in validators
            for allocation in validator["elections"]
            if allocation.get("purpose") == "primary-window"
            and (
                allocation.get("selection_status") != "selected"
                or allocation.get("recovery_status") not in recovered_statuses
            )
        )
        retained_by_state: dict[str, list[dict[str, int]]] = {
            name: [] for name in (
                "active-retained", "retired-frozen", "matured-unrecovered", "unmeasured"
            )
        }
        for election_id, allocation in self.election_allocations.items():
            for index in range(VALIDATOR_COUNT):
                candidate = allocation.get("validators", {}).get(str(index + 1))
                if candidate is None or candidate.get("recovery_status") != "retained-settlement-rollover":
                    continue
                retained_by_state[self.experiment_retention_state(election_id)].append(
                    {"election_id": election_id, "validator_index": index + 1}
                )
        matured_retained_unrecovered = retained_by_state["matured-unrecovered"]
        outstanding = (
            outstanding_recorded + len(missing_primary_allocations)
            + len(matured_retained_unrecovered) + len(retained_by_state["unmeasured"])
        )
        retained_rollover = sum(
            1
            for validator in validators
            for allocation in validator["elections"]
            if allocation.get("recovery_status") == "retained-settlement-rollover"
        )
        rendered_elections: list[dict[str, Any]] = []
        for election_id in sorted(self.election_allocations):
            allocation = self.election_allocations[election_id]
            rendered = dict(allocation)
            on_chain = (self.experiment_past_elections or {}).get(election_id)
            rendered["current_config34_active"] = (
                election_id == self.experiment_current_config34_since
            )
            rendered["on_chain_unfreeze_at"] = (
                on_chain["unfreeze_at"] if on_chain is not None else None
            )
            rendered["on_chain_vset_hash"] = (
                on_chain["vset_hash"] if on_chain is not None else None
            )
            if allocation.get("purpose") == "primary-window":
                missing_indices = [
                    index
                    for index in range(1, VALIDATOR_COUNT + 1)
                    if str(index) not in allocation.get("validators", {})
                ]
                rendered["expected_validator_count"] = VALIDATOR_COUNT
                rendered["missing_validator_indices"] = missing_indices
                rendered["missing_candidate_attribution_status"] = (
                    "NOT_ATTRIBUTABLE" if missing_indices else "NOT_APPLICABLE"
                )
            rendered_elections.append(rendered)
        evidence_status = (
            "partial-settlement" if status == "complete" and outstanding != 0 else status
        )
        return {
            "schema": "tos.validator-reward-election-allocation-evidence.v4",
            "schema_version": 4,
            "status": evidence_status,
            "generated_at": utc_now(),
            "mode": "experiment",
            "run_dir": str(self.run_dir),
            "network": {
                "topology": "single-host-four-process-local-network",
                "genesis_faucet_funding_nanotos": EXPERIMENT_GENESIS_FAUCET_FUNDING,
                "zero_state": self.zero_state_evidence(),
                "rpc_endpoints": self.rpc_readiness,
            },
            "window": {
                "started_at": self.experiment_started_at,
                "deadline_at": self.experiment_deadline_at,
                "settlement_deadline_at": self.settlement_deadline_at,
                "requested_duration_seconds": (
                    self.experiment.duration_seconds if self.experiment else None
                ),
                "requested_settlement_tail_seconds": (
                    self.experiment.settlement_tail_seconds if self.experiment else None
                ),
            },
            "elector": {
                "address_raw": raw_address(ELECTOR),
                "minimum_stake_nanotos": EFFECTIVE_STAKE,
                "operator_wallet_funding_nanotos": self.validator_wallet_funding(),
                "pool_capital_per_validator_nanotos": PQ_EXPERIMENT_POOL_CAPITAL,
                "supported_concurrent_unrecovered_stakes": (
                    EXPERIMENT_CONCURRENT_STAKE_CAPACITY
                ),
                "allocation_basis": (
                    "node-authorized controller/pool/ADNL mapping plus exact pool-level Elector "
                    "compute_returned_stake credit and elector-observed accepted principal; "
                    "per-election reward is exact only for a "
                    "single mapped election, multi-election reward remains NOT_ATTRIBUTABLE, "
                    "and equal-share inference is never used"
                ),
            },
            "elections": rendered_elections,
            "validators": validators,
            "reconciliation": {
                "candidate_allocations": sum(
                    validator["aggregate"]["candidate_count"] for validator in validators
                ),
                "expected_primary_candidate_allocations": sum(
                    VALIDATOR_COUNT
                    for allocation in self.election_allocations.values()
                    if allocation.get("purpose") == "primary-window"
                ),
                "missing_primary_candidate_allocations": missing_primary_allocations,
                "missing_primary_candidate_count": len(missing_primary_allocations),
                "matured_retained_unrecovered_allocations": matured_retained_unrecovered,
                "active_retained_allocations": retained_by_state["active-retained"],
                "retired_frozen_retained_allocations": retained_by_state["retired-frozen"],
                "unmeasured_retained_allocations": retained_by_state["unmeasured"],
                "current_config34_since": self.experiment_current_config34_since,
                "current_config34_cell_hash": self.experiment_current_config34_hash,
                "past_elections_on_chain": self.experiment_past_elections,
                "recovery_transactions": len(self.recovery_records),
                "recovered_allocations": sum(
                    len(record["candidate_election_ids"])
                    if "candidate_election_ids" in record
                    else 1
                    for record in self.recovery_records
                ),
                "outstanding_recorded_allocations": outstanding_recorded,
                "outstanding_allocations": outstanding,
                "retained_settlement_rollover_allocations": retained_rollover,
                "total_principal_nanotos": sum(
                    validator["aggregate"]["recovered_principal_nanotos"]
                    for validator in validators
                ),
                "total_credit_nanotos": sum(
                    validator["aggregate"]["credited_nanotos"] for validator in validators
                ),
                "total_reward_nanotos": sum(
                    validator["aggregate"]["reward_nanotos"] for validator in validators
                ),
            },
            "artifacts": {
                "readiness_manifest": str(self.readiness_path),
                "metrics": str(self.metrics_path),
                "events_in_report": str(self.report_path),
            },
            "evidence_contains_private_key_material": False,
            "run_directory_contains_private_runtime_keys": True,
            "provenance": {
                "source_commit": self.provenance.get("source_commit"),
                "artifact_snapshot": str(self.run_dir / "artifact-snapshot"),
            },
        }

    def publish_allocation_evidence(self, status: str) -> None:
        write_json_atomic(
            self.allocation_evidence_path,
            self.allocation_evidence(status),
        )

    def set_experiment_final_status(self, outstanding_allocations: int) -> str:
        if outstanding_allocations < 0:
            raise ValueError("outstanding allocation count must not be negative")
        self.experiment_final_status = (
            "complete" if outstanding_allocations == 0 else "partial-settlement"
        )
        return self.experiment_final_status

    def report_status(self) -> str:
        if self.failures:
            return "fail"
        if self.pq_full and not any(
            event.get("event") == "pq_full_launch_gate_passed" for event in self.events
        ):
            return "fail"
        if self.experiment is not None and self.experiment_final_status != "complete":
            return "fail"
        return "pass"

    def completion_exit_code(self) -> int:
        return 0 if self.report_status() == "pass" else 1

    @staticmethod
    def require_complete_experiment_settlement(outstanding_allocations: int) -> None:
        if outstanding_allocations != 0:
            raise RuntimeError(
                "validator experiment ended with "
                f"{outstanding_allocations} outstanding allocations"
            )

    def prepare_artifact_snapshot(self) -> None:
        snapshot_dir = self.run_dir / "artifact-snapshot"
        snapshot_build = snapshot_dir / "build"
        snapshot_source = snapshot_dir / "source"

        binary_paths = [
            "crypto/create-state",
            "crypto/pq/tos-pq-consensus-key",
            "utils/generate-random-id",
            "lite-client/lite-client",
            "validator-engine/validator-engine",
            "dht-server/dht-server",
            "validator-engine-console/validator-engine-console",
            "blockchain-explorer/blockchain-explorer",
        ]
        if self.fixture_only or self.pq_election:
            binary_paths += ["crypto/func", "crypto/fift"]
        binaries: dict[str, dict[str, Any]] = {}
        for relative in binary_paths:
            source = self.original_build_dir / relative
            target = snapshot_build / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            binaries[relative] = self.file_provenance(target)
        if self.pq_election:
            relative = "tosctl/pq_pool_stake_order"
            source = REPO / "tosctl/src/target/debug/examples/pq_pool_stake_order"
            target = snapshot_build / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            binaries[relative] = self.file_provenance(target)

        # The toslib shared library is platform-specific: .dylib on macOS, .so elsewhere
        # (install.py already loads the .dylib on darwin). Snapshot whichever exists.
        toslib_rel = "toslib/libtoslibjson.dylib" if sys.platform == "darwin" else "toslib/libtoslibjson.so"
        toslib_source = (self.original_build_dir / toslib_rel).resolve(strict=True)
        toslib_target = snapshot_build / toslib_rel
        toslib_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(toslib_source, toslib_target)
        binaries[toslib_rel] = self.file_provenance(toslib_target)

        # create-state includes generated contract code from the build tree.
        # Snapshot it with the binaries; source/crypto/smartcont intentionally
        # does not contain these generated ``auto/*.fif`` files.
        generated_contract_source = self.original_build_dir / "crypto/smartcont/auto"
        generated_contract_target = snapshot_build / "crypto/smartcont/auto"
        shutil.copytree(generated_contract_source, generated_contract_target)
        generated_contracts = {
            str(path.relative_to(generated_contract_target)): self.file_provenance(path)
            for path in sorted(generated_contract_target.rglob("*"))
            if path.is_file()
        }

        source_paths = [
            Path("crypto/fift/lib"),
            Path("crypto/smartcont"),
            Path("test/tostester/src"),
        ]
        for relative in source_paths:
            shutil.copytree(REPO / relative, snapshot_source / relative)
        script_target = snapshot_source / "scripts/validator-election-stage-a.py"
        script_target.parent.mkdir(parents=True)
        shutil.copy2(Path(__file__), script_target)
        x01_checker_target = snapshot_source / "scripts/x01_window_evidence.py"
        if self.pq_full:
            shutil.copy2(REPO / "scripts/x01_window_evidence.py", x01_checker_target)
        if self.pq_election:
            relative = Path("tosctl/src/node-control/contracts/examples/pq_pool_stake_order.rs")
            target = snapshot_source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / relative, target)
            schema_relative = Path("tl/generate/scheme/tos_api.tl")
            schema_target = snapshot_source / schema_relative
            schema_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / schema_relative, schema_target)

        source_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        git_status = subprocess.run(
            ["git", "status", "--short"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()
        source_patch = subprocess.run(
            ["git", "diff", "--binary", "HEAD"],
            cwd=REPO,
            capture_output=True,
            check=True,
        ).stdout
        patch_path = snapshot_dir / "working-tree.patch"
        patch_path.write_bytes(source_patch)

        self.provenance = {
            "source_commit": source_commit,
            "git_status_start": git_status,
            "working_tree_patch": self.file_provenance(patch_path),
            "harness": self.file_provenance(script_target),
            "x01_checker": self.file_provenance(x01_checker_target) if self.pq_full else None,
            "binaries": binaries,
            "generated_contracts": generated_contracts,
            "pq_stake_authorization_python_tl": (
                {
                    "schema": self.file_provenance(
                        schema_target
                    ),
                    "generated_binding": self.file_provenance(
                        snapshot_source / "test/tostester/src/tosapi/tos_api.py"
                    ),
                }
                if self.pq_election else None
            ),
        }
        (snapshot_dir / "manifest.json").write_text(
            json.dumps(self.provenance, indent=2, sort_keys=True)
        )
        self.install = Install(snapshot_build, snapshot_source)

    def event(self, name: str, **details: Any) -> None:
        item = {"at": utc_now(), "event": name, **details}
        self.events.append(item)
        rendered = json.dumps(item, sort_keys=True)
        print(rendered, flush=True)

    def fail(self, message: str) -> None:
        self.failures.append(message)
        self.event("failure", message=message)

    async def retry(
        self,
        operation: Callable[[], Awaitable[T]],
        *,
        timeout: float,
        interval: float = 1.0,
        description: str,
        predicate: Callable[[T], bool] = bool,
    ) -> T:
        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        last_value: T | None = None
        while time.monotonic() < deadline:
            try:
                last_value = await operation()
                if predicate(last_value):
                    return last_value
            except Exception as error:  # the network may be between blocks/restarting
                last_error = error
            await asyncio.sleep(interval)
        if last_error is not None:
            raise TimeoutError(f"{description}: last error: {last_error}") from last_error
        raise TimeoutError(f"{description}: last value: {last_value!r}")

    async def lite(self, *commands: str, timeout: float = 30.0) -> str:
        argv = [str(self.install.build_dir / "lite-client/lite-client")]
        argv += ["-C", str(self.lite_config), "-v", "0"]
        for command in commands:
            argv += ["-c", command]
        argv += ["-c", "quit"]

        def run() -> str:
            result = subprocess.run(
                argv,
                cwd=self.run_dir,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            output = result.stdout + result.stderr
            if result.returncode != 0 or "cannot run any queries" in output:
                raise RuntimeError(f"lite-client failed ({result.returncode}): {output[-2000:]}")
            return output

        return await asyncio.to_thread(run)

    async def runmethod(self, method: str, *params: str) -> str:
        command = f"runmethod {raw_address(ELECTOR)} {method}"
        if params:
            command += " " + " ".join(params)
        return await self.lite("time", command)

    async def runmethod_int(self, method: str, *params: str) -> int:
        output = await self.runmethod(method, *params)
        match = re.search(r"result:\s*\[\s*(-?(?:0x[0-9a-fA-F]+|\d+))", output)
        if match is None:
            raise RuntimeError(f"cannot parse {method} result: {output[-2000:]}")
        return int(match.group(1), 0)

    async def get_config34(self) -> Config34:
        output = await self.lite("time", "getconfig 34")

        def required(pattern: str, label: str) -> int:
            match = re.search(pattern, output)
            if match is None:
                raise RuntimeError(f"cannot parse ConfigParam 34 {label}")
            return int(match.group(1))

        return Config34(
            utime_since=required(r"utime_since:(\d+)", "utime_since"),
            utime_until=required(r"utime_until:(\d+)", "utime_until"),
            total=required(r"\btotal:(\d+)", "total"),
            main=required(r"\bmain:(\d+)", "main"),
            total_weight=required(r"total_weight:(\d+)", "total_weight"),
            validator_ids=re.findall(r"validator_id:x([0-9A-Fa-f]{64})", output),
            public_keys=re.findall(r"pubkey:x([0-9A-Fa-f]{64})", output),
            adnl_ids=re.findall(r"adnl_addr:x([0-9A-Fa-f]{64})", output),
            validator_adnl_pairs=parse_pq_validator_adnl_pairs(output),
            raw=output,
        )

    async def masterchain_seqno(self) -> int:
        assert self.client is not None
        info = await self.client.get_masterchain_info()
        if info.last is None:
            raise RuntimeError("masterchain info has no last block")
        return info.last.seqno

    async def balance(self, address: Address) -> int:
        assert self.client is not None
        return (await self.client.raw_get_account_state(address)).balance

    async def wait_pool_capital(self, address: Address, amount: int, label: str) -> int:
        """Wait for the destination shard to expose a funded pool after wallet seqno advances."""
        return await self.retry(
            lambda: self.balance(address), timeout=60,
            description=f"{label} pool capital at least {amount}",
            predicate=lambda value: value >= amount,
        )

    async def wallet_seqno(self, wallet: WalletV1) -> int:
        return (await wallet.current).seqno

    async def wait_wallet_seqno(
        self, wallet: WalletV1, expected: int, *, timeout: float = 60.0
    ) -> None:
        await self.retry(
            lambda: self.wallet_seqno(wallet),
            timeout=timeout,
            description=f"wallet {raw_address(wallet.address)} seqno {expected}",
            predicate=lambda value: value >= expected,
        )

    async def record_balance(self, label: str, wallet: WalletV1) -> int:
        value = await self.balance(wallet.address)
        self.wallet_balance_history.setdefault(label, []).append(
            {"at": utc_now(), "nanotos": value}
        )
        self.event("wallet_balance", wallet=label, nanotos=value)
        return value

    async def send_from_wallet(
        self,
        wallet: WalletV1,
        *,
        dest: Address,
        amount: int,
        body: Cell,
        label: str,
        init=None,
    ) -> None:
        before = await self.wallet_seqno(wallet)
        await wallet.send(
            internal_message(wallet.address, dest, amount, body, init=init),
            seqno=before,
        )
        await self.wait_wallet_seqno(wallet, before + 1)
        self.event(
            "wallet_message_included",
            label=label,
            wallet=raw_address(wallet.address),
            seqno=before + 1,
            amount=amount,
        )

    async def run_fift(self, script: Path, *args: str) -> str:
        argv = [str(self.install.fift_exe)]
        for include in self.install.fift_include_dirs:
            argv += ["-I", str(include)]
        argv += ["-s", str(script), *args]

        def run() -> str:
            result = subprocess.run(
                argv,
                cwd=self.artifacts_dir,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            output = result.stdout + result.stderr
            if result.returncode != 0:
                raise RuntimeError(f"Fift {script.name} failed ({result.returncode}): {output}")
            return output

        return await asyncio.to_thread(run)

    async def recovery_body(self, label: str) -> Cell:
        body_file = self.artifacts_dir / f"{label}-recover.boc"
        await self.run_fift(
            self.install.source_dir / "crypto/smartcont/recover-stake.fif",
            str(body_file),
        )
        return Cell.one_from_boc(body_file.read_bytes())

    async def restart_node(self, index: int, reason: str) -> None:
        self.event("node_restart_begin", node=index + 1, reason=reason)
        await self.nodes[index].stop()
        if self.pq_full:
            self.preserve_f01_log(index)
        await asyncio.sleep(1)
        await self.nodes[index].run(self.validator_start_options(index))
        self.record_f01_process(index)
        self.event("node_restart_complete", node=index + 1, reason=reason)

    def record_f01_process(self, index: int) -> None:
        """Bind each raw log generation to the actual validator process."""
        if not self.pq_full:
            return
        node = self.nodes[index]
        pid = node.process_id
        if pid is None or pid <= 0:
            raise RuntimeError(f"F01 {node.name} has no running validator process")
        proc = Path(f"/proc/{pid}")
        stat_fields = (proc / "stat").read_text().rsplit(") ", 1)[1].split()
        executable = (proc / "exe").resolve(strict=True)
        executable_stat = executable.stat()
        proc_cwd = proc / "cwd"
        cwd_link = proc_cwd.readlink()
        cwd = proc_cwd.resolve(strict=True)
        cwd_stat = proc_cwd.stat()
        node_dir = node.directory.resolve(strict=True)
        node_dir_stat = node_dir.stat()
        stat_fields_after = (proc / "stat").read_text().rsplit(") ", 1)[1].split()
        if stat_fields_after[19] != stat_fields[19]:
            raise RuntimeError(f"F01 {node.name} validator PID changed during cwd capture")
        if (cwd != node_dir or (cwd_stat.st_dev, cwd_stat.st_ino)
                != (node_dir_stat.st_dev, node_dir_stat.st_ino)):
            raise RuntimeError(f"F01 {node.name} validator process cwd differs from its DB root")
        generations = self.f01_process_generations.setdefault(node.name, [])
        generations.append({
            "node_name": node.name,
            "generation": len(generations),
            "pid": pid,
            "proc_start_ticks": int(stat_fields[19]),
            "exe_path": str(executable),
            "exe_device": executable_stat.st_dev,
            "exe_inode": executable_stat.st_ino,
            "node_data_dir": str(node_dir),
            "proc_cwd_link": str(cwd_link),
            "proc_cwd_realpath": str(cwd),
            "proc_cwd_device": cwd_stat.st_dev,
            "proc_cwd_inode": cwd_stat.st_ino,
            "recorded_at": utc_now(),
        })

    def preserve_f01_log(self, index: int) -> None:
        """Copy a stopped validator's raw log before the next run truncates it."""
        node = self.nodes[index]
        self.f01_directory.mkdir(parents=True, exist_ok=True)
        segments = self.f01_segments.setdefault(node.name, [])
        target = self.f01_directory / f"{node.name}-segment-{len(segments):02d}.log"
        shutil.copyfile(node.log_path, target)
        segment = extract_finalized_log(target)
        segment["process"] = dict(self.f01_process_generations[node.name][-1])
        segments.append(segment)

    def x01_endpoint(self, index: int) -> str:
        return f"127.0.0.1:{self.base_port + 500 + index}"

    async def x01_rpc(self, index: int, method: str,
                      params: dict[str, Any] | None = None) -> tuple[dict[str, Any], str]:
        """Keep the response bytes, endpoint and request for each independent node view."""
        self.x01_directory.mkdir(parents=True, exist_ok=True)
        endpoint = self.x01_endpoint(index)
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        request_bytes = json.dumps(payload).encode()

        def call() -> tuple[dict[str, Any], str]:
            request = urllib.request.Request(
                f"http://{endpoint}/jsonRPC", data=request_bytes,
                headers={"Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(request, timeout=8) as response:
                    raw, status = response.read(), response.status
                observed_at = utc_now()
            except Exception as error:
                with (self.x01_directory / "rpc.jsonl").open("a") as output:
                    output.write(json.dumps({
                        "at": utc_now(), "node": self.nodes[index].name,
                        "endpoint": endpoint, "request_base64": base64.b64encode(request_bytes).decode(),
                        "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
                        "transport_error": f"{type(error).__name__}: {error}",
                    }, sort_keys=True) + "\n")
                raise
            with (self.x01_directory / "rpc.jsonl").open("a") as output:
                output.write(json.dumps({
                    "at": observed_at, "node": self.nodes[index].name,
                    "endpoint": endpoint, "request_base64": base64.b64encode(request_bytes).decode(),
                    "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
                    "http_status": status,
                    "response_base64": base64.b64encode(raw).decode(),
                    "response_sha256": hashlib.sha256(raw).hexdigest(),
                }, sort_keys=True) + "\n")
            document = json.loads(raw)
            if status != 200 or document.get("error") is not None or document.get("result") is None:
                raise RuntimeError(f"X01 {self.nodes[index].name} {method} failed")
            return document["result"], observed_at

        return await asyncio.to_thread(call)

    @staticmethod
    def x01_block_id(value: dict[str, Any]) -> dict[str, Any]:
        def digest(field: str) -> str:
            raw = base64.b64decode(value[field], validate=True)
            if len(raw) != 32 or not any(raw):
                raise ValueError(f"X01 {field} is missing or zero")
            return raw.hex()

        if int(value["workchain"]) != -1 or int(value["shard"]) not in (
                -9223372036854775808, 9223372036854775808):
            raise ValueError("X01 RPC returned a non-masterchain block")
        return {"workchain": -1, "shard": "8000000000000000",
                "seqno": int(value["seqno"]),
                "root_hash": digest("root_hash"), "file_hash": digest("file_hash")}

    async def x01_freeze_policy(self) -> None:
        if not self.pq_full or self.x01_policy is not None:
            return
        assert self.network is not None
        self.x01_directory.mkdir(parents=True, exist_ok=True)
        policy_path = self.x01_directory / "policy.json"
        if policy_path.exists():
            raise RuntimeError("X01 policy already exists; refusing to replace a pre-fault policy")
        nodes = {}
        for index, node in enumerate(self.nodes):
            info, _ = await self.x01_rpc(index, "getMasterchainInfo")
            zero = self.x01_block_id(info["init"])
            if zero["seqno"] != 0:
                raise ValueError("X01 RPC zerostate has nonzero height")
            nodes[node.name] = {
                "endpoint": self.x01_endpoint(index), "zerostate": zero,
                "node_data_dir": str(node.directory.resolve()),
                "node_log_path": str(node.log_path.resolve()),
                "pq_key_id_hex": node.pq_initial_validator.key_id.hex(),
                "adnl_id_hex": node.validator_key.id.hex(),
                "initial_pid": node.process_id,
                "validator_engine_exe_path": self.provenance["binaries"]["validator-engine/validator-engine"]["path"],
                "validator_engine_exe_sha256": self.provenance["binaries"]["validator-engine/validator-engine"]["sha256"],
            }
        if len({json.dumps(row["zerostate"], sort_keys=True) for row in nodes.values()}) != 1:
            raise ValueError("X01 independent RPC endpoints do not share zerostate")
        policy = {"schema": "tos.x01.window-policy.v1", "nodes": nodes,
                  "thresholds": {"three_min_delta": 1, "halt_min_samples": 8,
                                 "halt_tail_samples": 4, "recovery_min_delta": 1,
                                 "three_max_seconds": 90, "halt_min_seconds": 30,
                                 "halt_tail_min_seconds": 15, "recovery_max_seconds": 90}}
        write_json_atomic(policy_path, policy)
        self.x01_policy, self.x01_policy_sha256 = policy, hashlib.sha256(policy_path.read_bytes()).hexdigest()
        self.event("x01_policy_frozen", path=str(policy_path), sha256=self.x01_policy_sha256)

    def x01_running_process(self, pid: int) -> tuple[bytes, str, str]:
        proc = Path(f"/proc/{pid}")
        stat = (proc / "stat").read_bytes()
        executable = (proc / "exe").resolve(strict=True)
        provenance = self.file_provenance(proc / "exe")
        expected = self.provenance["binaries"]["validator-engine/validator-engine"]
        if executable != Path(expected["path"]).resolve() or provenance["sha256"] != expected["sha256"]:
            raise ValueError(f"X01 PID {pid} executable differs from snapshotted validator engine")
        return stat, str(executable), provenance["sha256"]

    def x01_process_event(self, phase: str, index: int, *, stopped: bool,
                          old_pid: int, pid: int, proc_stat: bytes,
                          exe_path: str, exe_sha256: str) -> None:
        node = self.nodes[index]
        observation = {
            "schema": "tos.x01.process-stop.v1" if stopped else "tos.x01.process-start.v1",
            "phase": phase, "node": node.name, "pid": pid, "at": utc_now(),
            "running_before": stopped, "running_after": not stopped,
            "proc_stat_base64": base64.b64encode(proc_stat).decode(),
            "exe_path": exe_path, "exe_sha256": exe_sha256,
            "node_data_dir": str(node.directory.resolve()),
            "node_log_path": str(node.log_path.resolve()),
            "pq_key_id_hex": node.pq_initial_validator.key_id.hex(),
            "adnl_id_hex": node.validator_key.id.hex(),
        }
        if not stopped:
            observation["old_pid"] = old_pid
            observation["old_proc_absent"] = True
        else:
            observation["proc_after_absent"] = True
        raw = (json.dumps(observation, sort_keys=True) + "\n").encode()
        kind = "process_stopped" if stopped else "process_started"
        collection = "faults" if stopped else "restarts"
        event = {"phase": phase, "node": node.name, "kind": kind, "hit": True,
                 "raw_evidence_sha256": hashlib.sha256(raw).hexdigest(),
                 "raw_evidence_base64": base64.b64encode(raw).decode()}
        self.x01_trace[collection].append(event)
        path = self.x01_directory / f"{phase}-{node.name}-{kind}.json"
        path.write_bytes(raw)

    async def x01_stop(self, phase: str, index: int) -> None:
        node = self.nodes[index]
        pid = node.process_id
        if pid is None or pid <= 0:
            raise RuntimeError(f"X01 {node.name} had no running PID before stop")
        proc_stat, exe_path, exe_sha256 = self.x01_running_process(pid)
        await node.stop()
        if node.process_id is not None or Path(f"/proc/{pid}/stat").exists():
            raise RuntimeError(f"X01 {node.name} PID {pid} remained after stop")
        self.x01_process_event(phase, index, stopped=True,
                               old_pid=pid, pid=pid, proc_stat=proc_stat,
                               exe_path=exe_path, exe_sha256=exe_sha256)

    async def x01_start(self, phase: str, index: int) -> None:
        node = self.nodes[index]
        stopped = next(row for row in reversed(self.x01_trace["faults"])
                       if row["node"] == node.name)
        old_pid = json.loads(base64.b64decode(stopped["raw_evidence_base64"]))["pid"]
        if Path(f"/proc/{old_pid}/stat").exists():
            raise RuntimeError(f"X01 {node.name} old PID was reused before restart")
        await node.run(self.validator_start_options(index))
        pid = node.process_id
        if pid is None or pid <= 0 or pid == old_pid:
            raise RuntimeError(f"X01 {node.name} restart PID did not change")
        proc_stat, exe_path, exe_sha256 = self.x01_running_process(pid)
        self.x01_process_event(phase, index, stopped=False,
                               old_pid=old_pid, pid=pid, proc_stat=proc_stat,
                               exe_path=exe_path, exe_sha256=exe_sha256)

    async def x01_sample(self, phase: str, indices: tuple[int, ...]) -> dict[str, Any]:
        at = utc_now()  # before any RPC read, so a later stop cannot predate this sample
        initial_tips = {}
        for index in indices:
            info, _ = await self.x01_rpc(index, "getMasterchainInfo")
            initial_tips[self.nodes[index].name] = self.x01_block_id(info["last"])
        height = min(tip["seqno"] for tip in initial_tips.values())
        views = {}
        for index in indices:
            header, _ = await self.x01_rpc(index, "getBlockHeader", {
                "workchain": -1, "shard": MASTERCHAIN_SHARD_STR, "seqno": height,
            })
            views[self.nodes[index].name] = self.x01_block_id(header["id"])
        if any(block["seqno"] != height for block in views.values()) or len({
                json.dumps(block, sort_keys=True) for block in views.values()}) != 1:
            raise AssertionError(f"X01 {phase} full IDs conflict at common height {height}")
        tips, tip_observed_at = {}, {}
        for index in indices:
            info, observed_at = await self.x01_rpc(index, "getMasterchainInfo")
            name = self.nodes[index].name
            tip = self.x01_block_id(info["last"])
            before = initial_tips[name]
            if (tip["seqno"] < before["seqno"]
                    or tip["seqno"] == before["seqno"] and tip != before):
                raise AssertionError(f"X01 {phase} {name} tip regressed during sample")
            tips[name], tip_observed_at[name] = tip, observed_at
        sample = {"at": at, "completed_at": utc_now(), "nodes": views,
                  "initial_tips": initial_tips, "tips": tips,
                  "tip_observed_at": tip_observed_at}
        self.x01_trace["phases"].setdefault(phase, []).append(sample)
        return sample

    async def x01_finish(self) -> None:
        assert self.x01_policy is not None and self.x01_policy_sha256 is not None
        policy_path = self.x01_directory / "policy.json"
        if hashlib.sha256(policy_path.read_bytes()).hexdigest() != self.x01_policy_sha256:
            raise ValueError("X01 pre-fault policy file changed during the run")
        checkpoint_height = self.x01_trace["phases"]["two_of_four"][-1]["nodes"][self.nodes[0].name]["seqno"]
        checkpoint = {}
        for index, node in enumerate(self.nodes):
            header, _ = await self.x01_rpc(index, "getBlockHeader", {
                "workchain": -1, "shard": MASTERCHAIN_SHARD_STR, "seqno": checkpoint_height,
            })
            checkpoint[node.name] = self.x01_block_id(header["id"])
        self.x01_trace["recovery_halt_checkpoint"] = checkpoint
        trace_path = self.x01_directory / "trace.json"
        write_json_atomic(trace_path, self.x01_trace)
        manifest = {"schema": "tos.x01.stage-a-capture.v1",
                    "source_commit": self.provenance["source_commit"],
                    "harness": self.provenance["harness"],
                    "x01_checker": self.provenance["x01_checker"],
                    "binaries": self.provenance["binaries"],
                    "policy": self.file_provenance(self.x01_directory / "policy.json"),
                    "trace": self.file_provenance(trace_path),
                    "rpc_transcript": self.file_provenance(self.x01_directory / "rpc.jsonl"),
                    "process_events": [self.file_provenance(path) for path in sorted(
                        self.x01_directory.glob("*-process_*.json"))],
                    "f01_capture_manifest": str(self.f01_directory / "capture-manifest.json")}
        manifest_path = self.x01_directory / "capture-manifest.json"
        write_json_atomic(manifest_path, manifest)
        self.x01_capture_provenance = self.file_provenance(manifest_path)

    def write_x01_check(self) -> None:
        """Validate the sealed F01 per-node raw logs before publishing X01 PASS."""
        assert self.x01_policy is not None and self.x01_policy_sha256 is not None
        policy_path = self.x01_directory / "policy.json"
        trace_path = self.x01_directory / "trace.json"
        f01_path = self.f01_directory / "capture-manifest.json"
        if hashlib.sha256(policy_path.read_bytes()).hexdigest() != self.x01_policy_sha256:
            raise ValueError("X01 pre-fault policy changed before final F01 log validation")
        f01_bytes = f01_path.read_bytes()
        result = validate_x01_window(self.x01_policy, self.x01_trace,
                                     generation_manifest=json.loads(f01_bytes))
        result.update({"policy_sha256": self.x01_policy_sha256,
                       "trace_sha256": hashlib.sha256(trace_path.read_bytes()).hexdigest(),
                       "f01_capture_manifest_sha256": hashlib.sha256(f01_bytes).hexdigest()})
        write_json_atomic(self.x01_directory / "check.json", result)
        manifest_path = self.x01_directory / "capture-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["f01_capture_manifest"] = self.file_provenance(f01_path)
        manifest["check"] = self.file_provenance(self.x01_directory / "check.json")
        write_json_atomic(manifest_path, manifest)
        self.x01_capture_provenance = self.file_provenance(manifest_path)

    def write_f01_capture(self) -> None:
        """Seal all stopped log segments and the exact harness source snapshot."""
        if not self.pq_full:
            return
        for index in range(len(self.nodes)):
            self.preserve_f01_log(index)
        if len(self.f01_transitions) != 3:
            raise ValueError("F01 Stage A needs three recorded ConfigParam 34 transitions")
        combined_logs = {}
        for node in self.nodes:
            combined = self.f01_directory / f"{node.name}-finalized.log"
            with combined.open("wb") as output:
                for segment in self.f01_segments[node.name]:
                    with Path(segment["path"]).open("rb") as source:
                        shutil.copyfileobj(source, output)
            combined_logs[node.name] = extract_finalized_log(combined)
        source_manifest = self.run_dir / "artifact-snapshot/manifest.json"
        rpc_transcript = self.f01_directory / "config34-rpc.jsonl"
        nodes = [
            {
                "node_name": node.name,
                "node_data_dir": str(node.directory.resolve()),
                "validator_index": index + 1,
                "controller_id_hex": self.controllers[index].address.hash_part.hex(),
                "pq_validator_id_hex": node.pq_initial_validator.validator_id.hex(),
                "pq_key_id_hex": node.pq_initial_validator.key_id.hex(),
                "adnl_id_hex": node.validator_key.id.hex(),
                "rpc_address": f"127.0.0.1:{self.base_port + 500 + index}",
                "process_generations": self.f01_process_generations[node.name],
                "log_segments": self.f01_segments[node.name],
                "combined_log": combined_logs[node.name],
            }
            for index, node in enumerate(self.nodes)
        ]
        path = self.f01_directory / "capture-manifest.json"
        write_manifest(
            path,
            source={
                "source_commit": self.provenance["source_commit"],
                "artifact_snapshot_manifest": self.file_provenance(source_manifest),
                "harness": self.provenance["harness"],
                "binaries": self.provenance["binaries"],
                "config34_raw_rpc_transcript": self.file_provenance(rpc_transcript),
            },
            nodes=nodes, transitions=self.f01_transitions,
        )
        self.f01_capture_provenance = self.file_provenance(path)

    async def capture_f01_transition(self, label: str) -> None:
        """Bind the exact Config34 change height to all four local RPC views."""
        if not self.pq_full:
            return
        assert self.client is not None
        assert self.f01_previous_config_height is not None
        assert self.f01_previous_config_hash is not None
        after_hash = (await self.client.get_config_param(34)).hash.hex()
        upper = await self.masterchain_seqno()
        self.f01_directory.mkdir(parents=True, exist_ok=True)
        transcript = self.f01_directory / "config34-rpc.jsonl"

        async def query(index: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
            address = f"127.0.0.1:{self.base_port + 500 + index}"

            def call() -> dict[str, Any]:
                payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
                request = urllib.request.Request(
                    f"http://{address}/jsonRPC", data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(request, timeout=8) as response:
                    raw = response.read()
                    status = response.status
                document = json.loads(raw)
                with transcript.open("a") as output:
                    output.write(json.dumps({
                        "node_name": self.nodes[index].name, "node_index": index,
                        "address": address, "request": payload, "http_status": status,
                        "response_base64": base64.b64encode(raw).decode(),
                    }, sort_keys=True) + "\n")
                if status != 200 or document.get("error") is not None or document.get("result") is None:
                    raise RuntimeError(f"F01 {self.nodes[index].name} {method} failed")
                return document

            return await asyncio.to_thread(call)

        async def config_at(height: int) -> dict[str, Any]:
            return await query(0, "getConfigParam", {"param": 34, "seqno": height})

        for index, node in enumerate(self.nodes):
            await self.retry(
                lambda index=index: query(index, "getMasterchainInfo", {}),
                timeout=90, interval=1,
                description=f"F01 {node.name} reaches Config34 observation height {upper}",
                predicate=lambda value: int(value["result"]["last"]["seqno"]) >= upper,
            )
        height = await locate_transition(
            config_at, self.f01_previous_config_height, upper,
            self.f01_previous_config_hash, after_hash,
        )
        for index, node in enumerate(self.nodes):
            await self.retry(
                lambda index=index: query(index, "getMasterchainInfo", {}),
                timeout=90, interval=1,
                description=f"F01 {node.name} reaches post-transition height {height + 1}",
                predicate=lambda value: int(value["result"]["last"]["seqno"]) >= height + 1,
            )
        observations = []
        for boundary in (height - 1, height, height + 1):
            block_ids = []
            for index, node in enumerate(self.nodes):
                config = await query(index, "getConfigParam", {"param": 34, "seqno": boundary})
                observed_hash = config34_hash(config)
                expected_hash = self.f01_previous_config_hash if boundary < height else after_hash
                if observed_hash != expected_hash:
                    raise AssertionError(f"F01 {node.name} Config34 differs at height {boundary}")
                header = await query(index, "getBlockHeader", {
                    "workchain": -1, "shard": MASTERCHAIN_SHARD_STR, "seqno": boundary,
                })
                block_id = header["result"]["id"]
                if int(block_id["seqno"]) != boundary or int(block_id["workchain"]) != -1:
                    raise AssertionError(f"F01 {node.name} header has wrong masterchain height")
                block_ids.append(block_id)
                observations.append({"node_name": node.name, "height": boundary,
                                     "block_id": block_id, "config34_cell_hash": observed_hash})
            if any(block_id != block_ids[0] for block_id in block_ids[1:]):
                raise AssertionError(f"F01 per-node block IDs disagree at transition height {boundary}")
        self.f01_transitions.append({
            "label": label, "height": height,
            "before_config34_cell_hash": self.f01_previous_config_hash,
            "after_config34_cell_hash": after_hash,
            "observations": observations,
        })
        self.f01_previous_config_height = height
        self.f01_previous_config_hash = after_hash

    async def chain_time(self) -> int:
        output = await self.lite("time")
        match = re.search(r"server time is\s+(\d+)", output)
        if match:
            return int(match.group(1))
        match = re.search(r"created at\s+(\d+)", output)
        if match:
            return int(match.group(1))
        raise RuntimeError("cannot parse chain time")

    async def wait_until_chain_time(self, timestamp: int, label: str) -> None:
        reached = await self.retry(
            self.chain_time,
            timeout=max(120.0, timestamp - time.time() + 120.0),
            interval=self.long_poll_interval,
            description=label,
            predicate=lambda value: value >= timestamp,
        )
        self.event("chain_time_reached", label=label, target=timestamp, actual=reached)

    async def verify_three_of_four_liveness(self) -> None:
        if self.pq_full:
            await self.x01_freeze_policy()
        before = await self.masterchain_seqno()
        self.event("three_of_four_begin", stopped_node=4, seqno=before)
        if self.pq_full:
            await self.x01_stop("three_of_four", 3)
            self.preserve_f01_log(3)
            await self.x01_sample("three_of_four", (0, 1, 2))
        else:
            await self.nodes[3].stop()
        await asyncio.sleep(15)
        after = await self.masterchain_seqno()
        if after <= before:
            raise AssertionError(f"3-of-4 did not advance: {before} -> {after}")
        if self.pq_full:
            await self.x01_sample("three_of_four", (0, 1, 2))
            await self.x01_start("three_of_four", 3)
            self.record_f01_process(3)
        else:
            await self.nodes[3].run(self.validator_start_options(3))
        self.event("three_of_four_passed", before=before, after=after)

    async def _node_mc_seqno(self, index: int) -> int:
        """Masterchain tip as seen by node <index>'s OWN JSON-RPC endpoint, not the shared
        lite-client. A restarted node's independent catch-up is only observable through its
        own view; the per-run log is truncated on restart, so it cannot serve this."""
        assert self.experiment is not None
        address = self.experiment.rpc_addresses[index]
        response = await asyncio.to_thread(json_rpc_call, address, "getMasterchainInfo")
        last = response["result"].get("last") or {}
        return int(last["seqno"])

    async def _node_mc_block_id(self, index: int, seqno: int) -> tuple[str, str]:
        """The (root_hash, file_hash) of the masterchain block at <seqno> as node <index>'s
        own JSON-RPC getBlockHeader reports it. Comparing this between the target and the
        reference AT THE SAME HEIGHT detects a target that reports a high seqno on a
        divergent chain -- something a seqno-only check would silently accept."""
        assert self.experiment is not None
        address = self.experiment.rpc_addresses[index]
        params = {"workchain": -1, "shard": MASTERCHAIN_SHARD_STR, "seqno": int(seqno)}
        response = await asyncio.to_thread(json_rpc_call, address, "getBlockHeader", params)
        block_id = response["result"].get("id") or {}
        root_hash = block_id.get("root_hash")
        file_hash = block_id.get("file_hash")
        if not root_hash or not file_hash:
            raise RuntimeError(f"node {index + 1} getBlockHeader({seqno}) returned no block-id hashes: {response}")
        return (root_hash, file_hash)

    async def _node_consensus_status(self, index: int) -> dict[str, Any]:
        """The read-only getNodeConsensusStatus admin result from node <index>."""
        assert self.experiment is not None
        address = self.experiment.rpc_addresses[index]
        response = await asyncio.to_thread(json_rpc_call, address, "getNodeConsensusStatus")
        return response["result"]

    async def probe_consensus_status(self) -> dict[str, Any]:
        """Cross-check every node via getNodeConsensusStatus, verifying the admin endpoint on
        a live network (not just that it compiles). On this genesis-validator localnet each
        node must report itself a validator, all must agree on the last key block, and their
        applied masterchain blocks must share the same block id at the lowest common seqno --
        a divergence would disagree there."""
        assert self.experiment is not None
        count = len(self.experiment.rpc_addresses)
        statuses = []
        for i in range(count):
            statuses.append(await self.retry(
                lambda i=i: self._node_consensus_status(i),
                timeout=60, interval=2, description=f"node {i + 1} consensus status",
            ))
        failures = []
        for i, s in enumerate(statuses):
            vset = s.get("validator_set") or {}
            if vset.get("is_validator") is not True:
                failures.append(f"node {i + 1} is_validator={vset.get('is_validator')} (expected true)")
            # P2-1 invariant: a single-turn snapshot can never show served leading applied,
            # so the gap is always >= 0. A negative value would mean the two points were read
            # at different instants (the defect this endpoint was rewritten to avoid).
            gap = s.get("applied_minus_consensus")
            if gap is not None and gap < 0:
                failures.append(f"node {i + 1} applied_minus_consensus={gap} (< 0: inconsistent snapshot)")
        key_blocks = {json.dumps(s.get("last_key_block"), sort_keys=True) for s in statuses}
        if len(key_blocks) != 1:
            failures.append(f"nodes disagree on last_key_block: {key_blocks}")
        applied_seqnos = [int(s["applied_masterchain_block"]["seqno"]) for s in statuses]
        common_height = min(applied_seqnos)
        block_ids = set()
        for i in range(count):
            block_ids.add(await self.retry(
                lambda i=i: self._node_mc_block_id(i, common_height),
                timeout=60, interval=2, description=f"node {i + 1} block id at {common_height}",
            ))
        if len(block_ids) != 1:
            failures.append(f"nodes disagree on masterchain block id at seqno {common_height}: {block_ids}")
        result = {
            "verdict": "passed" if not failures else "failed",
            "nodes": count,
            "common_height": common_height,
            "all_report_is_validator": all((s.get("validator_set") or {}).get("is_validator") is True for s in statuses),
            "agree_on_last_key_block": len(key_blocks) == 1,
            "agree_on_block_id_at_common_height": len(block_ids) == 1,
            "statuses": statuses,
            "failures": failures,
        }
        (self.run_dir / "consensus-status-probe.json").write_text(json.dumps(result, indent=2) + "\n")
        self.event("consensus_status_probe", verdict=result["verdict"], common_height=common_height, failures=failures)
        if failures:
            raise AssertionError(f"consensus-status probe failed: {failures}")
        return result

    async def _node_account_balance(self, index: int, address: Address, seqno: int | None = None) -> int:
        """Account balance (nanotos) as node <index>'s own JSON-RPC reports it, optionally at a
        specific masterchain seqno so all nodes can be compared at the SAME height."""
        assert self.experiment is not None
        params: dict[str, Any] = {"address": raw_address(address)}
        if seqno is not None:
            params["seqno"] = int(seqno)
        resp = await asyncio.to_thread(json_rpc_call, self.experiment.rpc_addresses[index], "getAddressBalance", params)
        return int(resp["result"])

    async def transfer_soak(self, faucet: WalletV1) -> dict[str, Any]:
        """Randomized A/B/C transfer load under real block production, verifying cross-node
        到账 consistency after every transfer: fund three wallets from the faucet, then
        repeatedly move a random amount between two distinct accounts; after each confirmed
        transfer, require EVERY node's JSON-RPC to report identical balances for the three
        accounts AT A COMMON masterchain height (a divergence means a node is out of sync or
        forked), and require the destination to have actually been credited. Per-node RSS/FD
        leak sampling runs in parallel via scripts/soak-mem-monitor.py."""
        assert self.experiment is not None and self.client is not None
        names = ["A", "B", "C"]
        wallets: dict[str, WalletV1] = {}
        for name in names:
            before = await self.wallet_seqno(faucet)
            wallet = await faucet.deploy(
                WalletV1Blueprint(workchain=-1), CurrencyCollection(tomis=self.soak_wallet_funding), seqno=before
            )
            await self.wait_wallet_seqno(faucet, before + 1)
            await self.retry(
                lambda wallet=wallet: self.balance(wallet.address),
                timeout=60, description=f"soak wallet {name} funding",
                predicate=lambda v: v >= self.soak_wallet_funding - NANO,
            )
            wallets[name] = wallet
            self.event("soak_wallet_funded", wallet=name, address=raw_address(wallet.address))

        node_count = len(self.experiment.rpc_addresses)
        transfers = 0
        consistency_checks = 0
        failures: list[str] = []
        started = time.monotonic()
        deadline = started + self.soak_duration
        while time.monotonic() < deadline:
            await asyncio.sleep(random.uniform(self.soak_min_interval, self.soak_max_interval))
            src_name, dst_name = random.sample(names, 2)
            src, dst = wallets[src_name], wallets[dst_name]
            src_balance = await self.balance(src.address)
            if src_balance < 2 * NANO:  # keep something for fees
                continue
            amount = random.randint(1, max(1, (src_balance - NANO) // 4))
            dst_before = await self.balance(dst.address)
            try:
                await self.send_from_wallet(
                    src, dest=dst.address, amount=amount, body=Cell.empty(), label=f"soak-{src_name}->{dst_name}"
                )
            except Exception as error:  # noqa: BLE001
                failures.append(f"transfer {src_name}->{dst_name} amount={amount} failed: {error}")
                continue
            transfers += 1
            # 到账 on the authoritative (node 0) view: the destination must be credited. The
            # node-0 tip AFTER crediting is the confirmed height H -- the transfer is applied
            # by H.
            try:
                await self.retry(
                    lambda: self.balance(dst.address), timeout=60, interval=1,
                    description=f"soak {dst_name} credited", predicate=lambda v: v > dst_before,
                )
            except Exception as error:  # noqa: BLE001
                failures.append(f"{src_name}->{dst_name} not credited on node 1: {error}")
                continue
            confirmed_height = await self._node_mc_seqno(0)
            # Require EVERY node to advance to >= H. Comparing an older common height (min tip)
            # would let a node stuck behind H pass by agreeing on stale state it shares; making
            # each node reach H means a node that has not seen this transfer fails here.
            caught_up = True
            for i in range(node_count):
                try:
                    await self.retry(
                        lambda i=i: self._node_mc_seqno(i), timeout=60, interval=1,
                        description=f"node {i + 1} reaches confirmed height {confirmed_height}",
                        predicate=lambda s: s >= confirmed_height,
                    )
                except Exception as error:  # noqa: BLE001
                    failures.append(f"node {i + 1} did not reach confirmed height {confirmed_height}: {error}")
                    caught_up = False
            if not caught_up:
                continue
            # At H every node must agree on all three balances AND show the destination credited
            # past its pre-transfer value -- i.e. this transfer is visible in every node's chain
            # state at H, not just at an older shared height.
            checked_ok = True
            for name, wallet in wallets.items():
                seen = set()
                for i in range(node_count):
                    try:
                        seen.add(await self._node_account_balance(i, wallet.address, seqno=confirmed_height))
                    except Exception as error:  # noqa: BLE001
                        failures.append(f"node {i + 1} balance {name}@{confirmed_height} query failed: {error}")
                        checked_ok = False
                if len(seen) > 1:
                    failures.append(f"nodes disagree on {name} balance at seqno {confirmed_height}: {sorted(seen)}")
                    checked_ok = False
                if name == dst_name and seen and min(seen) <= dst_before:
                    failures.append(
                        f"{dst_name}@{confirmed_height} not credited on all nodes: {sorted(seen)} <= before {dst_before}"
                    )
                    checked_ok = False
            if checked_ok:
                consistency_checks += 1
            if transfers % 10 == 0:
                self.event("soak_progress", transfers=transfers, consistency_checks=consistency_checks,
                           failures=len(failures))

        result = {
            "verdict": "passed" if not failures else "failed",
            "transfers": transfers,
            "cross_node_consistency_checks": consistency_checks,
            "nodes": node_count,
            "duration_seconds": round(time.monotonic() - started, 1),
            "wallets": {n: raw_address(w.address) for n, w in wallets.items()},
            "failures": failures[:20],
        }
        (self.run_dir / "transfer-soak-analysis.json").write_text(json.dumps(result, indent=2) + "\n")
        self.event("transfer_soak_complete", verdict=result["verdict"], transfers=transfers,
                   consistency_checks=consistency_checks, failures=len(failures))
        if failures:
            raise AssertionError(f"transfer soak failed ({len(failures)} issue(s)): {failures[:5]}")
        return result

    async def verify_post_cleanup_rejoin(self) -> dict[str, Any]:
        """The full post-cleanup rejoin acceptance: pick a NON-ZERO node that has actually
        completed a REAL validator cleanup (a VALCLEANUP erase_ack in its own log, i.e. a real
        obsolete validator DB was deleted and its durable record erased), restart it on the
        SAME db_root, and prove it recovers sync and keeps tracking the same chain. This turns
        post_cleanup_recovery from NOT_EXERCISED into a real result. It proves sync recovery
        after a real cleanup, NOT re-participation in consensus signing."""
        assert self.experiment is not None
        erase_re = re.compile(r"VALCLEANUP erase_ack ")
        candidates = []
        for i in range(1, len(self.nodes)):  # node 0 hosts the shared lite-client -> off limits
            try:
                text = self.nodes[i].log_path.read_text(errors="replace")
            except FileNotFoundError:
                continue
            acks = len(erase_re.findall(text))
            if acks > 0:
                candidates.append((i, acks))
        self.event(
            "post_cleanup_rejoin_candidates",
            candidates=[{"node": i + 1, "erase_acks": n} for i, n in candidates],
        )
        if not candidates:
            # No node completed a real cleanup in this window -> the property genuinely was not
            # exercised. Report it honestly rather than passing a hollow check.
            result = {
                "verdict": "NOT_EXERCISED",
                "reason": "no non-zero node completed a real validator cleanup (VALCLEANUP erase_ack) in this run",
            }
            (self.run_dir / "post-cleanup-rejoin-analysis.json").write_text(json.dumps(result, indent=2) + "\n")
            self.event("post_cleanup_rejoin_not_exercised")
            return result
        # Prefer the node that erased the most (most exercised).
        node_index = max(candidates, key=lambda c: c[1])[0]
        rejoin = await self.verify_live_rejoin(node_index=node_index)
        probe = await self.probe_consensus_status()
        recovered = rejoin.get("post_cleanup_recovery")
        result = {
            "verdict": "passed" if recovered == "passed" else "failed",
            "target_node": node_index + 1,
            "target_pre_restart_erase_acks": rejoin.get("pre_restart_erase_acks"),
            "post_cleanup_recovery": recovered,
            "does_not_prove": "re-participation in consensus block signing",
            "rejoin": rejoin,
            "consensus_status_probe_verdict": probe.get("verdict"),
        }
        (self.run_dir / "post-cleanup-rejoin-analysis.json").write_text(json.dumps(result, indent=2) + "\n")
        self.event(
            "post_cleanup_rejoin_result",
            verdict=result["verdict"],
            target_node=node_index + 1,
            post_cleanup_recovery=recovered,
        )
        if result["verdict"] != "passed":
            raise AssertionError(f"post-cleanup rejoin failed on node {node_index + 1}: post_cleanup_recovery={recovered}")
        return result

    async def verify_live_rejoin(self, node_index: int = 3) -> dict[str, Any]:
        """Prove a NON-ZERO validator, restarted while its peers keep producing blocks,
        RECOVERS SYNC and keeps tracking the live chain rather than merely replaying its
        frozen DB. This proves catch-up and continued tracking; it does NOT by itself prove
        the validator re-signed consensus (that would need per-block signature/quorum
        evidence), so it is deliberately not called "rejoins consensus".

        The falsifiable core, with every progress bar measured against BOTH pre-stop heights
        so a node that was already ahead cannot pass by standing still:
          - baseline = max(network tip at stop, target's own tip at stop);
          - while the target is down its peers must advance to baseline + margin (3 of 4
            equal validators is a BFT quorum) -- a strictly higher chain than anything seen
            before the stop;
          - after restart the target's OWN view must reach that during-downtime tip (blocks
            only its peers could have produced while it was gone);
          - then the reference must reach a STRICTLY fresher tip than the sync point, and the
            target must reach that too -- so it is following the moving chain, not replaying
            to a frozen point. A frozen chain, or a target that never advances past its own
            pre-stop tip, makes one of these polls time out (a real failure).
        node 0 is off limits: it hosts the shared lite-client this run depends on.

        Post-cleanup scope: a generic sync recovery is NOT evidence that a node recovers
        AFTER a real validator cleanup. That stronger property is asserted only when the
        target actually completed a durable erase (a real VALCLEANUP erase_ack) before the
        restart; otherwise it is reported NOT_EXERCISED, never passed."""
        assert self.experiment is not None
        if node_index == 0:
            raise ValueError("live-rejoin target must be non-zero (node 0 hosts the lite-client)")

        tip_at_stop = await self.masterchain_seqno()
        target_before = await self._node_mc_seqno(node_index)
        # Any genuine catch-up must exceed the highest height EITHER endpoint already had:
        # if the target was ahead of the reference before the stop, standing still must not
        # count as progress.
        pre_stop_baseline = max(tip_at_stop, target_before)
        # Did a REAL validator cleanup (durable erase) already complete on this target? The
        # log is truncated on restart, so this can only be read now, before we stop it.
        pre_restart_erase_acks = 0
        try:
            pre_text = self.nodes[node_index].log_path.read_text(errors="replace")
            pre_restart_erase_acks = len(re.findall(r"VALCLEANUP erase_ack ", pre_text))
        except FileNotFoundError:
            pass
        self.event(
            "live_rejoin_begin",
            node=node_index + 1,
            network_tip=tip_at_stop,
            target_tip=target_before,
            pre_stop_baseline=pre_stop_baseline,
            pre_restart_erase_acks=pre_restart_erase_acks,
        )

        await self.nodes[node_index].stop()
        if self.pq_full:
            self.preserve_f01_log(node_index)

        # Peers must advance strictly past the pre-stop baseline while the target is down;
        # that gap is what the target has to catch up to. A stalled network here is itself a
        # real failure (we could not then attribute any later catch-up to live progress).
        advance_margin = 4
        downtime_target = pre_stop_baseline + advance_margin
        tip_during_downtime = await self.retry(
            self.masterchain_seqno,
            timeout=180,
            interval=2,
            description=f"peers advance to >= {downtime_target} while node {node_index + 1} is down",
            predicate=lambda seqno: seqno >= downtime_target,
        )

        # Restart with cleanup armed (validator_start_options carries the flag when enabled).
        await self.nodes[node_index].run(self.validator_start_options(node_index))
        self.record_f01_process(node_index)

        # SYNC PROOF: the target's own view must reach the tip its peers reached while it was
        # down (>= tip_during_downtime > pre_stop_baseline), so it cannot be satisfied by the
        # target's own frozen DB.
        target_after_sync = await self.retry(
            lambda: self._node_mc_seqno(node_index),
            timeout=240,
            interval=2,
            description=f"node {node_index + 1} syncs past the downtime tip {tip_during_downtime}",
            predicate=lambda seqno: seqno >= tip_during_downtime,
        )

        # LIVE-TRACKING PROOF: require the reference to reach a STRICTLY fresher tip than the
        # sync point, then require the target to reach that too. Re-reading the same tip is
        # not "the chain advanced": the fresh tip must exceed max(downtime tip, sync point).
        tracking_baseline = max(tip_during_downtime, target_after_sync)
        fresh_tip = await self.retry(
            self.masterchain_seqno,
            timeout=180,
            interval=2,
            description=f"reference advances strictly past {tracking_baseline} after node {node_index + 1} resyncs",
            predicate=lambda seqno: seqno > tracking_baseline,
        )
        target_tracking = await self.retry(
            lambda: self._node_mc_seqno(node_index),
            timeout=180,
            interval=2,
            description=f"node {node_index + 1} tracks the fresher live tip {fresh_tip}",
            predicate=lambda seqno: seqno >= fresh_tip,
        )

        # BLOCK-ID AGREEMENT: the target's masterchain block id must equal the reference's at
        # the LATEST height the target just caught up to (fresh_tip). Agreeing at the freshest
        # common height subsumes all ancestors -- a masterchain block commits its history --
        # so it rejects a target that shared an old prefix but forked after it. Comparing only
        # at the earlier during-downtime height would miss exactly that: agreement at height H
        # does not imply agreement at a later height. The earlier height is kept as extra
        # evidence, but the decisive gate is fresh_tip.
        async def _agree_at(height: int) -> tuple[bool, tuple[str, str], tuple[str, str]]:
            ref = await self.retry(
                lambda: self._node_mc_block_id(0, height),
                timeout=60, interval=2,
                description=f"reference block id at masterchain seqno {height}",
            )
            tgt = await self.retry(
                lambda: self._node_mc_block_id(node_index, height),
                timeout=60, interval=2,
                description=f"node {node_index + 1} block id at masterchain seqno {height}",
            )
            return (ref == tgt, ref, tgt)

        agreement_height = fresh_tip
        agree_fresh, reference_block_id, target_block_id = await _agree_at(agreement_height)
        early_agreement_height = tip_during_downtime
        agree_early, _, _ = await _agree_at(early_agreement_height)
        block_ids_agree = agree_fresh and agree_early

        # The recovered node's post-restart log (truncated to this run) must carry no fault;
        # record whether the armed cleanup worker ran a pass on it as supporting evidence.
        log_text = self.nodes[node_index].log_path.read_text(errors="replace")
        cleanup_passes = len(re.findall(r"VALCLEANUP pass ", log_text))
        fatals = [ln[:400] for ln in log_text.splitlines() if _FATAL_RE.search(ln)]

        # Sync + tracking + block-id agreement must all hold. Sync/tracking failures time
        # out above; a fork or a fault fails here. The separate post-cleanup-recovery
        # property is asserted only if a real durable erase completed on this target before
        # the restart.
        healthy = (not fatals) and block_ids_agree
        sync_recovery = "passed" if healthy else "failed"
        post_cleanup_recovery = (
            sync_recovery if pre_restart_erase_acks > 0 else "NOT_EXERCISED"
        )
        result = {
            "verdict": sync_recovery,
            "property": "target node recovered sync and keeps tracking the same chain",
            "does_not_prove": "re-participation in consensus block signing (needs signature/quorum evidence)",
            "post_cleanup_recovery": post_cleanup_recovery,
            "node": node_index + 1,
            "cleanup_armed": self.enable_consensus_cleanup,
            "pre_restart_erase_acks": pre_restart_erase_acks,
            "network_tip_at_stop": tip_at_stop,
            "target_tip_at_stop": target_before,
            "pre_stop_baseline": pre_stop_baseline,
            "network_tip_during_downtime": tip_during_downtime,
            "target_tip_after_sync": target_after_sync,
            "fresh_network_tip": fresh_tip,
            "target_tip_tracking": target_tracking,
            "block_id_agreement_height": agreement_height,
            "block_ids_agree": block_ids_agree,
            "block_ids_agree_fresh_tip": agree_fresh,
            "block_ids_agree_downtime_height": agree_early,
            "block_id_early_agreement_height": early_agreement_height,
            "cleanup_passes_after_rejoin": cleanup_passes,
            "fatals": fatals[:5],
        }
        self.live_rejoin_result = result
        (self.run_dir / "live-rejoin-analysis.json").write_text(json.dumps(result, indent=2) + "\n")
        self.event(
            "live_rejoin_passed" if healthy else "live_rejoin_failed",
            **{k: v for k, v in result.items() if k != "fatals"},
        )
        if not block_ids_agree:
            bad_height = agreement_height if not agree_fresh else early_agreement_height
            raise AssertionError(
                f"live rejoin block-id disagreement at masterchain seqno {bad_height} "
                f"(fresh_tip agree={agree_fresh}, downtime-height agree={agree_early}): "
                f"reference={reference_block_id} target={target_block_id} (node {node_index + 1} forked after the "
                f"shared prefix)"
            )
        if fatals:
            raise AssertionError(f"live rejoin saw fault diagnostics on node {node_index + 1}: {fatals[:3]}")
        return result

    async def verify_two_of_four_safe_halt(self) -> None:
        self.event("two_of_four_begin", stopped_nodes=[3, 4])
        if self.pq_full:
            await self.x01_stop("two_of_four", 2)
            await self.x01_stop("two_of_four", 3)
            self.preserve_f01_log(2)
            self.preserve_f01_log(3)
        else:
            await self.nodes[2].stop()
            await self.nodes[3].stop()
        samples: list[int] = []
        for _ in range(8):
            await asyncio.sleep(5)
            samples.append(await self.masterchain_seqno())
            if self.pq_full:
                await self.x01_sample("two_of_four", (0, 1))
        if len(set(samples[-4:])) != 1:
            raise AssertionError(f"2-of-4 did not reach a safe halt: {samples}")
        if self.pq_full:
            await self.x01_start("recovery", 2)
            self.record_f01_process(2)
            await self.x01_start("recovery", 3)
            self.record_f01_process(3)
            for index in range(4):
                await self.retry(lambda index=index: self.x01_rpc(index, "getMasterchainInfo"),
                                 timeout=60, interval=1,
                                 description=f"X01 {self.nodes[index].name} RPC ready after restart")
            await self.x01_sample("recovery", (0, 1, 2, 3))
        else:
            await self.nodes[2].run(self.validator_start_options(2))
            await self.nodes[3].run(self.validator_start_options(3))
        resumed_from = samples[-1]
        resumed_to = await self.retry(
            self.masterchain_seqno,
            timeout=60,
            description="resume after restoring 4-of-4",
            predicate=lambda value: value > resumed_from,
        )
        if self.pq_full:
            halt_height = self.x01_trace["phases"]["two_of_four"][-1]["nodes"][self.nodes[0].name]["seqno"]
            deadline = time.monotonic() + 90
            while True:
                sample = await self.x01_sample("recovery", (0, 1, 2, 3))
                if next(iter(sample["nodes"].values()))["seqno"] > halt_height:
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("X01 all four full IDs did not advance after recovery")
                await asyncio.sleep(2)
            await self.x01_finish()
        self.event(
            "two_of_four_safe_halt_passed",
            samples=samples,
            resumed_from=resumed_from,
            resumed_to=resumed_to,
        )

    async def capture_elector_snapshot(self, label: str) -> dict[str, Any]:
        snapshot: dict[str, Any] = {
            "label": label,
            "captured_at": utc_now(),
            "methods": {},
        }
        safe_label = re.sub(r"[^A-Za-z0-9_.-]", "-", label)
        for method in (
            "active_election_id",
            "participant_list_extended",
            "past_election_ids",
            "past_elections",
            "past_elections_list",
        ):
            output = await self.runmethod(method)
            path = self.artifacts_dir / f"{safe_label}-{method}.txt"
            path.write_text(output)
            snapshot["methods"][method] = self.file_provenance(path)
        return snapshot

    def experiment_allocation(
        self,
        election_id: int,
        *,
        purpose: str = "primary-window",
    ) -> dict[str, Any]:
        allocation = self.election_allocations.get(election_id)
        if allocation is None:
            allocation = {
                "election_id": election_id,
                "purpose": purpose,
                "first_observed_at": utc_now(),
                "target_set_since": election_id,
                "target_set_until": election_id + self.profile.elected_for,
                "initial_unfreeze_estimate": (
                    election_id + self.profile.elected_for + self.profile.stakes_frozen_for
                ),
                "submission_status": "submitting",
                "selection_status": "pending",
                "validators": {},
                "elector_snapshots": [],
            }
            self.election_allocations[election_id] = allocation
            self.event("experiment_election_observed", election_id=election_id)
        return allocation

    async def submit_experiment_candidate(
        self,
        *,
        index: int,
        election_id: int,
        round_number: int,
    ) -> None:
        allocation = self.experiment_allocation(election_id)
        candidate_key = str(index + 1)
        if candidate_key in allocation["validators"]:
            return
        wallet_balance = await self.balance(self.wallets[index].address)
        pool_balance = await self.balance(self.pools[index].address)
        # The pool, not the operator wallet, owns the three overlapping PQ
        # stakes. Wait for an older credit if its capital is still frozen;
        # the wallet only pays order and recovery-message fees.
        if wallet_balance < 3 * NANO or pool_balance < PQ_STAKE_MESSAGE_VALUE + 2 * NANO:
            return
        order = await self.submit_pq_candidate(index, election_id, round_number=round_number)
        controller = self.controllers[index]
        pool = self.pools[index]
        allocation["validators"][candidate_key] = {
            "validator_index": index + 1,
            "controller_id_hex": controller.address.hash_part.hex(),
            "consensus_key_id_hex": controller.consensus.key_id.hex(),
            "adnl_id_hex": self.nodes[index].validator_key.id.hex(),
            "operator_wallet_raw": raw_address(self.wallets[index].address),
            "pool_stake_owner_raw": raw_address(pool.address),
            "recovery_destination_raw": raw_address(pool.address),
            "effective_stake_nanotos": order["effective_stake_nanotos"],
            "stake_message_value_nanotos": PQ_STAKE_MESSAGE_VALUE,
            "submitted_at": utc_now(),
            "pq_authorized_order": order,
            "selection_status": "pending",
            "recovery_status": "pending",
        }
        if allocation["purpose"] == "settlement-rollover":
            allocation["validators"][candidate_key]["recovery_status"] = (
                "retained-settlement-rollover"
            )
            allocation["validators"][candidate_key]["recovery_expected"] = False
        else:
            allocation["validators"][candidate_key]["recovery_expected"] = True
        if len(allocation["validators"]) == VALIDATOR_COUNT:
            allocation["submission_status"] = "accepted-four-of-four"
            allocation["submitted_at"] = utc_now()
            allocation["elector_snapshots"].append(
                await self.capture_elector_snapshot(f"election-{election_id}-four-candidates")
            )
        self.publish_allocation_evidence("running")

    async def observe_experiment_activation(self) -> bool:
        config = await self.get_config34()
        self.experiment_current_config34_since = config.utime_since
        self.experiment_current_config34_hash = int.from_bytes(
            (await self.client.get_config_param(34)).hash, "big"
        )
        self.experiment_past_elections = parse_past_elections_list(
            await self.runmethod("past_elections_list")
        )
        allocation = self.election_allocations.get(config.utime_since)
        if allocation is None or allocation["selection_status"] == "selected":
            return False
        if len(allocation["validators"]) != VALIDATOR_COUNT:
            raise AssertionError(
                f"election {config.utime_since} activated before four candidates were recorded"
            )
        expected = {
            controller.address.hash_part.hex().upper(): node.validator_key.id.hex().upper()
            for controller, node in zip(self.controllers, self.nodes)
        }
        if config.total != VALIDATOR_COUNT or config.main != VALIDATOR_COUNT:
            raise AssertionError(f"experiment elected set is not four-of-four: {asdict(config)}")
        require_pq_config34_associations(config, expected)

        config_path = self.artifacts_dir / f"election-{config.utime_since}-config34.txt"
        config_path.write_text(config.raw)
        rpc_consensus = await self.rpc_config34_consensus(config.utime_since)
        rpc_validator_set = rpc_consensus["observations"][0]["validator_set"]
        if int(rpc_validator_set["utime_since"]) != config.utime_since:
            raise AssertionError("lite-client and JSON-RPC ConfigParam 34 IDs disagree")
        # JSON-RPC's legacy public_key is an empty Ed25519 placeholder for a
        # PQ descriptor. Join its weights by the unique ADNL ID only after
        # the lite ConfigParam 34 has checked controller/ADNL associations.
        rpc_validators_by_adnl = {
            base64.b64decode(item["adnl_address"]).hex(): item
            for item in rpc_validator_set["validators"]
        }
        if len(rpc_validators_by_adnl) != VALIDATOR_COUNT:
            raise AssertionError("JSON-RPC PQ ConfigParam 34 ADNL IDs are not unique")
        allocation["selection_status"] = "selected"
        allocation["config34_cell_hash"] = self.experiment_current_config34_hash
        allocation["selected_at"] = utc_now()
        allocation["config34"] = self.config34_evidence(config)
        allocation["config34_artifact"] = self.file_provenance(config_path)
        allocation["rpc_config34_consensus"] = rpc_consensus
        allocation["elector_snapshots"].append(
            await self.capture_elector_snapshot(f"election-{config.utime_since}-activated")
        )
        for candidate in allocation["validators"].values():
            rpc_validator = rpc_validators_by_adnl.get(candidate["adnl_id_hex"])
            if rpc_validator is None:
                raise AssertionError(
                    "JSON-RPC ConfigParam 34 omitted the elected controller's ADNL ID"
                )
            candidate["selection_status"] = "selected"
            candidate["selected_set_since"] = config.utime_since
            candidate["selected_set_until"] = config.utime_until
            candidate["individual_weight"] = rpc_validator["weight"]
            candidate["cumulative_weight"] = rpc_validator["cumulative_weight"]
            candidate["individual_weight_status"] = "decoded-four-node-consensus"
            candidate["selected_set_total_weight"] = config.total_weight
        self.event(
            "experiment_election_activated",
            election_id=config.utime_since,
            total_weight=config.total_weight,
        )
        self.publish_allocation_evidence("running")
        return True

    async def recover_experiment_stakes(self, chain_timestamp: int) -> int:
        recovered_count = 0
        for index, (wallet, pool) in enumerate(zip(self.wallets, self.pools)):
            pool_id = "0x" + pool.address.hash_part.hex()
            credit = await self.runmethod_int("compute_returned_stake", pool_id)
            if credit < EFFECTIVE_STAKE:
                continue
            eligible: list[tuple[int, dict[str, Any]]] = []
            for election_id in sorted(self.election_allocations):
                allocation = self.election_allocations[election_id]
                candidate = allocation["validators"].get(str(index + 1))
                if candidate is None or candidate["recovery_status"] not in (
                    "pending", "retained-settlement-rollover"
                ):
                    continue
                if (
                    candidate.get("selection_status") == "selected"
                    and self.experiment_retention_state(election_id) == "matured-unrecovered"
                ):
                    eligible.append((election_id, candidate))
            if not eligible:
                raise AssertionError(
                    f"pool {index + 1} has an unmapped Elector credit {credit}"
                )

            # The Elector exposes only the pool's aggregate credit, not the
            # contributing election IDs. Never greedily choose a subset:
            # include every matured candidate, even a settlement rollover,
            # and wait until the credit covers their full observed principals.
            principal = sum(
                candidate["effective_stake_nanotos"] for _, candidate in eligible
            )
            if credit < principal:
                self.event(
                    "experiment_pool_credit_below_matured_principal",
                    pool=raw_address(pool.address), credit=credit,
                    matured_election_ids=[election_id for election_id, _ in eligible],
                    required_principal=principal,
                )
                continue

            before = await self.balance(pool.address)
            recovery_label = f"experiment-pool-{index + 1}-recover-{chain_timestamp}"
            body = await self.recovery_body(recovery_label)
            view = body.begin_parse()
            if view.load_uint(32) != 0x47657424:
                raise AssertionError("PQ experiment pool recovery has the wrong opcode")
            query_id = view.load_uint(64)
            if view.remaining_bits or view.remaining_refs:
                raise AssertionError("PQ experiment pool recovery has trailing data")
            await self.send_from_wallet(
                wallet,
                dest=pool.address,
                amount=NANO,
                body=body,
                label=recovery_label,
            )
            opcode, detail = await self.wait_pq_pool_elector_reply(
                index, query_id,
                description=f"experiment pool {index + 1} mature elector recovery",
            )
            if opcode != 0xF96F7324 or detail != 0:
                raise AssertionError(
                    f"experiment pool {index + 1} did not receive mature recovery: "
                    f"opcode=0x{opcode:08x} detail={detail}"
                )
            await self.retry(
                lambda pool_id=pool_id: self.runmethod_int(
                    "compute_returned_stake", pool_id
                ),
                timeout=60,
                description=f"pool {index + 1} experiment credit removal",
                predicate=lambda value: value == 0,
            )
            after = await self.retry(
                lambda pool=pool: self.balance(pool.address),
                timeout=60,
                description=f"pool {index + 1} experiment recovery balance",
                predicate=lambda value, before=before, credit=credit: (
                    value >= before + credit - 2 * NANO
                ),
            )
            election_ids = [election_id for election_id, _ in eligible]
            attribution = recovery_attribution(election_ids)
            record = {
                "recovered_at": utc_now(),
                "chain_timestamp": chain_timestamp,
                "validator_index": index + 1,
                "controller_id_hex": self.controllers[index].address.hash_part.hex(),
                "adnl_id_hex": self.nodes[index].validator_key.id.hex(),
                "operator_wallet_raw": raw_address(wallet.address),
                "pool_stake_owner_raw": raw_address(pool.address),
                "recovery_destination_raw": raw_address(pool.address),
                "recovery_query_id": query_id,
                "elector_reply_opcode": f"0x{opcode:08x}",
                "candidate_election_ids": election_ids,
                **attribution,
                "principal_nanotos": principal,
                "credit_nanotos": credit,
                "reward_nanotos": credit - principal,
                "pool_balance_before_nanotos": before,
                "pool_balance_after_nanotos": after,
                "pool_balance_delta_nanotos": after - before,
                "recovery_message_value_nanotos": NANO,
                "reward_derivation": "credit_nanotos - principal_nanotos",
                "balance_delta_used_for_reward": False,
            }
            self.recovery_records.append(record)
            if len(eligible) == 1:
                candidate = eligible[0][1]
                was_retained = candidate["recovery_status"] == "retained-settlement-rollover"
                candidate["recovery_status"] = "recovered"
                candidate["recovered_despite_retained_rollover"] = was_retained
                candidate["recovered_at"] = record["recovered_at"]
                candidate["credit_nanotos"] = credit
                candidate["reward_nanotos"] = credit - candidate["effective_stake_nanotos"]
                candidate["recovery_attribution"] = attribution["attribution_status"]
                candidate["reward_attribution_status"] = "EXACT"
            else:
                for _, candidate in eligible:
                    was_retained = candidate["recovery_status"] == "retained-settlement-rollover"
                    candidate["recovery_status"] = "recovered-in-aggregate"
                    candidate["recovered_despite_retained_rollover"] = was_retained
                    candidate["recovered_at"] = record["recovered_at"]
                    candidate["recovery_attribution"] = attribution["attribution_status"]
                    candidate["reward_attribution_status"] = "NOT_ATTRIBUTABLE"
                    candidate["recovery_record_index"] = len(self.recovery_records) - 1
            recovered_count += 1
            self.event(
                "experiment_stake_recovered",
                validator=index + 1,
                election_ids=election_ids,
                principal=principal,
                credit=credit,
                reward=credit - principal,
                attribution_status=attribution["attribution_status"],
                per_election_reward_attribution_status=attribution[
                    "per_election_reward_attribution_status"
                ],
            )
            self.publish_allocation_evidence("running")
        return recovered_count

    async def run_experiment(self) -> None:
        assert self.experiment is not None
        self.rpc_readiness = await self.wait_json_rpc_readiness()
        # Fast dedicated rejoin: check rejoin against the freshly-ready network (already
        # producing blocks) and exit, without the long election window. Here no real cleanup
        # has happened yet, so post_cleanup_recovery is reported NOT_EXERCISED. The full
        # post-cleanup rejoin (a node that has actually erase_acked, restarted) runs at the
        # END of the experiment instead -- see below.
        if self.measure_live_rejoin and self.live_rejoin_only:
            await self.verify_live_rejoin()
            await self.probe_consensus_status()
            self.event("live_rejoin_only_complete")
            return
        started_wall = time.time()
        started_monotonic = time.monotonic()
        deadline_monotonic = started_monotonic + self.experiment.duration_seconds
        settlement_deadline_monotonic = deadline_monotonic + self.experiment.settlement_tail_seconds
        self.experiment_started_at = utc_at(started_wall)
        self.experiment_deadline_at = utc_at(started_wall + self.experiment.duration_seconds)
        self.settlement_deadline_at = utc_at(
            started_wall
            + self.experiment.duration_seconds
            + self.experiment.settlement_tail_seconds
        )
        write_json_atomic(self.readiness_path, self.readiness_manifest())
        self.publish_allocation_evidence("running")
        self.event(
            "validator_experiment_ready",
            readiness_manifest=str(self.readiness_path),
            allocation_evidence=str(self.allocation_evidence_path),
            rpc_addresses=self.experiment.rpc_addresses,
            deadline_at=self.experiment_deadline_at,
            settlement_deadline_at=self.settlement_deadline_at,
        )

        loop_interval = min(10.0, max(1.0, self.sample_interval))
        last_heartbeat = 0.0
        while time.monotonic() < settlement_deadline_monotonic:
            chain_timestamp = await self.chain_time()
            self.experiment_last_chain_timestamp = chain_timestamp
            await self.observe_experiment_activation()
            await self.recover_experiment_stakes(chain_timestamp)

            in_primary_window = time.monotonic() < deadline_monotonic
            active_election_id = await self.runmethod_int("active_election_id")
            allocation: dict[str, Any] | None = None
            if active_election_id > 0 and in_primary_window:
                allocation = self.experiment_allocation(
                    active_election_id,
                    purpose="primary-window",
                )
            elif active_election_id > 0:
                existing = self.election_allocations.get(active_election_id)
                if (
                    existing is not None
                    and existing["purpose"] == "primary-window"
                    and len(existing["validators"]) < VALIDATOR_COUNT
                ):
                    # Finish a candidate set that opened just before the
                    # measurement deadline.
                    allocation = existing
                else:
                    primary_ids = [
                        election_id
                        for election_id, item in self.election_allocations.items()
                        if item["purpose"] == "primary-window"
                    ]
                    rollover_exists = any(
                        item["purpose"] == "settlement-rollover"
                        for item in self.election_allocations.values()
                    )
                    if (
                        primary_ids
                        and active_election_id > max(primary_ids)
                        and not rollover_exists
                    ):
                        # One successor set retires the last measured set so
                        # its stake and reward become recoverable. The
                        # successor stake remains explicitly classified as a
                        # retained settlement-rollover allocation.
                        allocation = self.experiment_allocation(
                            active_election_id,
                            purpose="settlement-rollover",
                        )

            if allocation is not None:
                if active_election_id != allocation["election_id"]:
                    raise AssertionError("active election/allocation ID mismatch")
                if len(allocation["validators"]) < VALIDATOR_COUNT:
                    round_number = sorted(self.election_allocations).index(active_election_id) + 1
                    for index in range(VALIDATOR_COUNT):
                        await self.submit_experiment_candidate(
                            index=index,
                            election_id=active_election_id,
                            round_number=round_number,
                        )
                if len(allocation["validators"]) < VALIDATOR_COUNT:
                    allocation["submission_status"] = "waiting-for-recovery-funds"

            if time.monotonic() - last_heartbeat >= 60:
                self.publish_allocation_evidence("running")
                self.event(
                    "validator_experiment_heartbeat",
                    chain_timestamp=chain_timestamp,
                    phase=(
                        "primary" if time.monotonic() < deadline_monotonic else "settlement-tail"
                    ),
                    elections=len(self.election_allocations),
                    recoveries=len(self.recovery_records),
                )
                last_heartbeat = time.monotonic()
            remaining = settlement_deadline_monotonic - time.monotonic()
            if remaining > 0:
                await asyncio.sleep(min(loop_interval, remaining))

        chain_timestamp = await self.chain_time()
        self.experiment_last_chain_timestamp = chain_timestamp
        await self.observe_experiment_activation()
        await self.recover_experiment_stakes(chain_timestamp)
        final_snapshot = await self.capture_elector_snapshot("experiment-final")
        for allocation in self.election_allocations.values():
            allocation.setdefault("final_elector_snapshot", final_snapshot)
        preliminary = self.allocation_evidence("complete")
        outstanding = preliminary["reconciliation"]["outstanding_allocations"]
        final_status = self.set_experiment_final_status(outstanding)
        self.publish_allocation_evidence(final_status)
        self.event(
            (
                "validator_experiment_passed"
                if outstanding == 0
                else "validator_experiment_partial_settlement"
            ),
            elections=len(self.election_allocations),
            recoveries=len(self.recovery_records),
            outstanding_allocations=outstanding,
            settlement_tail_elapsed=True,
        )
        # Full post-cleanup rejoin: by now cleanup has run across the whole election window,
        # so a node has really erase_acked. Restart that node on its own db_root and prove it
        # keeps tracking the same chain -- turning post_cleanup_recovery into a real result.
        if self.measure_live_rejoin:
            await self.verify_post_cleanup_rejoin()
        self.require_complete_experiment_settlement(outstanding)

    async def chain_heads(self) -> dict[str, int]:
        output = await self.lite("time", "allshards")
        masterchain = re.search(
            r"latest masterchain block known to server is "
            r"\(-1,8000000000000000,(\d+)\).* created at (\d+)",
            output,
        )
        workchain = re.search(
            r"shard #\d+ : \(0,[0-9A-Fa-f]+,(\d+)\).* @ (\d+)",
            output,
        )
        if masterchain is None or workchain is None:
            raise RuntimeError("cannot parse masterchain/workchain heads")
        return {
            "masterchain_seqno": int(masterchain.group(1)),
            "masterchain_created_at": int(masterchain.group(2)),
            "workchain_seqno": int(workchain.group(1)),
            "workchain_created_at": int(workchain.group(2)),
        }

    def network_storage(self) -> dict[str, int]:
        logical_bytes = 0
        allocated_bytes = 0
        file_count = 0
        for path in self.network_dir.rglob("*"):
            try:
                if path.is_file():
                    stat = path.stat()
                    logical_bytes += stat.st_size
                    allocated_bytes += stat.st_blocks * 512
                    file_count += 1
            except (FileNotFoundError, PermissionError):
                continue
        return {
            "network_storage_logical_bytes": logical_bytes,
            "network_storage_allocated_bytes": allocated_bytes,
            "network_file_count": file_count,
        }

    async def metrics_monitor(self) -> None:
        self.metrics_path.parent.mkdir(parents=True, exist_ok=True)
        while not self._monitor_stop.is_set():
            sampled_at = time.time()
            sample: dict[str, Any] = {"at": datetime.fromtimestamp(sampled_at, UTC).isoformat()}
            try:
                heads = await self.chain_heads()
                sample.update(heads)
                sample["masterchain_head_age_seconds"] = max(
                    0.0, sampled_at - heads["masterchain_created_at"]
                )
                sample["workchain_head_age_seconds"] = max(
                    0.0, sampled_at - heads["workchain_created_at"]
                )
            except Exception as error:
                sample["chain_heads_error"] = str(error)
            try:
                config = await self.get_config34()
                sample["config34_since"] = config.utime_since
                sample["config34_until"] = config.utime_until
            except Exception as error:
                sample["config34_error"] = str(error)
            try:
                sample["elector_balance_nanotos"] = await self.balance(ELECTOR)
            except Exception as error:
                sample["elector_balance_error"] = str(error)
            try:
                sample["active_election_id"] = await self.runmethod_int("active_election_id")
            except Exception as error:
                sample["active_election_error"] = str(error)

            processes: list[dict[str, Any]] = []
            network_marker = str(self.network_dir).encode()
            # Per-process RSS/fd sampling reads Linux procfs; it does not exist on macOS,
            # where this harness also runs. Skip the sample there rather than fault -- the
            # rest of the metrics (config34, balances, storage) are portable.
            proc_root = Path("/proc")
            for proc_dir in (proc_root.iterdir() if proc_root.is_dir() else []):
                if not proc_dir.name.isdigit():
                    continue
                try:
                    cmdline = (proc_dir / "cmdline").read_bytes()
                    if network_marker not in cmdline or b"validator-engine" not in cmdline:
                        continue
                    status: dict[str, str] = {}
                    for line in (proc_dir / "status").read_text().splitlines():
                        if ":" in line:
                            key, value = line.split(":", 1)
                            status[key] = value.strip()
                    smaps: dict[str, str] = {}
                    for line in (proc_dir / "smaps_rollup").read_text().splitlines():
                        if ":" in line:
                            key, value = line.split(":", 1)
                            smaps[key] = value.strip()
                    fd_entries = list((proc_dir / "fd").iterdir())
                    archive_fds = 0
                    for fd_entry in fd_entries:
                        try:
                            if "/archive/" in str(fd_entry.readlink()):
                                archive_fds += 1
                        except FileNotFoundError:
                            # The descriptor may close between listing and
                            # resolving it; the next sample will observe the
                            # stable value.
                            pass
                    stat_tail = (proc_dir / "stat").read_text().rsplit(")", 1)[1]
                    stat_fields = stat_tail.split()
                    processes.append(
                        {
                            "pid": int(proc_dir.name),
                            "rss_kib": int(status.get("VmRSS", "0 kB").split()[0]),
                            "anon_kib": int(status.get("RssAnon", "0 kB").split()[0]),
                            "file_kib": int(status.get("RssFile", "0 kB").split()[0]),
                            "shmem_kib": int(status.get("RssShmem", "0 kB").split()[0]),
                            "archive_fds": archive_fds,
                            "pss_kib": int(smaps.get("Pss", "0 kB").split()[0]),
                            "private_kib": int(smaps.get("Private_Clean", "0 kB").split()[0])
                            + int(smaps.get("Private_Dirty", "0 kB").split()[0]),
                            "threads": int(status.get("Threads", "0")),
                            "open_fds": len(fd_entries),
                            "cpu_user_ticks": int(stat_fields[11]),
                            "cpu_system_ticks": int(stat_fields[12]),
                        }
                    )
                except (FileNotFoundError, PermissionError, ProcessLookupError):
                    continue
            sample["validator_processes"] = processes
            try:
                sample.update(await asyncio.to_thread(self.network_storage))
                disk = shutil.disk_usage(self.run_dir)
                sample["filesystem_free_bytes"] = disk.free
            except Exception as error:
                sample["storage_error"] = str(error)
            with self.metrics_path.open("a") as output:
                output.write(json.dumps(sample, sort_keys=True) + "\n")
            try:
                await asyncio.wait_for(self._monitor_stop.wait(), timeout=self.sample_interval)
            except TimeoutError:
                pass

    async def setup_wallets(self, faucet: WalletV1) -> None:
        wallet_funding = self.validator_wallet_funding()
        for index in range(VALIDATOR_COUNT):
            blueprint = WalletV1Blueprint(workchain=-1)
            before = await self.wallet_seqno(faucet)
            wallet = await faucet.deploy(
                blueprint,
                CurrencyCollection(tomis=wallet_funding),
                seqno=before,
            )
            await self.wait_wallet_seqno(faucet, before + 1)
            await self.retry(
                lambda wallet=wallet: self.balance(wallet.address),
                timeout=60,
                description=f"validator wallet {index + 1} funding",
                predicate=lambda value, wallet_funding=wallet_funding: (
                    value >= wallet_funding - NANO
                ),
            )
            self.wallets.append(wallet)
            await self.record_balance(f"validator-{index + 1}-funded", wallet)

        blueprint = WalletV1Blueprint(workchain=-1)
        before = await self.wallet_seqno(faucet)
        self.negative_wallet = await faucet.deploy(
            blueprint,
            CurrencyCollection(tomis=NEGATIVE_WALLET_FUNDING),
            seqno=before,
        )
        await self.wait_wallet_seqno(faucet, before + 1)
        await self.retry(
            lambda: self.balance(self.negative_wallet.address),
            timeout=60,
            description="negative-test wallet funding",
            predicate=lambda value: value >= NEGATIVE_WALLET_FUNDING - NANO,
        )
        await self.record_balance("negative-wallet-funded", self.negative_wallet)

    async def verify_live_controller_policy(self) -> None:
        if self.controller_code is None or self.client is None:
            raise AssertionError("controller policy read-back has no compiled code or lite client")
        policy = await self.client.get_config_param(47)
        view = policy.begin_parse()
        admitted = view.load_dict(256)
        expected = int.from_bytes(self.controller_code.hash, "big")
        if admitted is None or set(admitted) != {expected}:
            raise AssertionError(
                "live ConfigParam 47 does not admit exactly the compiled controller code: "
                f"expected={self.controller_code.hash.hex()} "
                f"actual={[] if admitted is None else [f'{key:064x}' for key in admitted]}"
            )
        if view.remaining_bits or view.remaining_refs:
            raise AssertionError("live ConfigParam 47 contains trailing data")
        version = ConfigParam8.deserialize((await self.client.get_config_param(8)).begin_parse())
        if version.version != 16:
            raise AssertionError(
                f"live PQ fixture global version is {version.version}, expected 16"
            )
        self.event(
            "controller_policy_read_back",
            parameter=47,
            admitted_code_hash=self.controller_code.hash.hex(),
            code_count=1,
            global_version=version.version,
        )

    async def deploy_pq_fixture_accounts(self, faucet: WalletV1) -> None:
        if self.controller_code is None or self.pool_code is None:
            raise AssertionError("PQ fixture contracts were not compiled or loaded")
        if len(self.controllers) != VALIDATOR_COUNT or len(self.wallets) != VALIDATOR_COUNT:
            raise AssertionError("PQ fixture does not have four controllers and four wallets")
        assert self.client is not None

        for index, (wallet, controller) in enumerate(zip(self.wallets, self.controllers)):
            pool = make_pool_fixture(self.pool_code, wallet.address, controller.address)
            self.pools.append(pool)
            for label, address, state_init, code, sender in (
                ("controller", controller.address, controller.state_init, self.controller_code, faucet),
                ("pool", pool.address, pool.state_init, self.pool_code, wallet),
            ):
                await self.send_from_wallet(
                    sender,
                    dest=address,
                    amount=10 * NANO,
                    body=Cell.empty(),
                    init=state_init,
                    label=f"validator-{index + 1}-{label}-deployment",
                )

                async def deployed_code() -> bytes:
                    return (await self.client.raw_get_account_state(address)).code

                code_boc = await self.retry(
                    deployed_code,
                    timeout=60,
                    description=f"validator {index + 1} {label} deployment",
                    predicate=bool,
                )
                observed = Cell.one_from_boc(code_boc).hash
                if observed != code.hash:
                    raise AssertionError(
                        f"validator {index + 1} {label} deployed unexpected code: "
                        f"expected={code.hash.hex()} actual={observed.hex()}"
                    )
            if self.pq_election:
                capital_amount = (
                    PQ_EXPERIMENT_POOL_CAPITAL if self.experiment is not None
                    else PQ_STAKE_MESSAGE_VALUE + 20 * NANO
                )
                await self.send_from_wallet(
                    wallet, dest=pool.address, amount=capital_amount,
                    body=Cell.empty(), label=f"validator-{index + 1}-pool-capital",
                )
                await self.wait_pool_capital(
                    pool.address, capital_amount, f"validator {index + 1}"
                )
            self.event(
                "pq_fixture_accounts_deployed",
                validator=index + 1,
                controller=raw_address(controller.address),
                pool=raw_address(pool.address),
                controller_code_hash=self.controller_code.hash.hex(),
                pool_code_hash=self.pool_code.hash.hex(),
            )

    async def authorized_pq_pool_order(
        self, index: int, election_id: int, query_id: int, *,
        stake_amount: int = PQ_STAKE_MESSAGE_VALUE,
        corrupt_signature_for_negative: bool = False,
        retry_restart_transients: bool = False,
    ) -> tuple[Cell, bytes]:
        """Obtain one node-bound authorization and encode the production pool body.

        The finite launch-gate rounds and the one-round diagnostic must share
        this path; neither may reconstruct a preimage or borrow a key from a
        different source.
        """
        node = self.nodes[index]
        pool = self.pools[index]
        controller = self.controllers[index]
        request = tos_api.Engine_validator_createPqStakeAuthorizationRequest(
            election_date=election_id,
            max_factor=MAX_FACTOR,
            adnl_addr=node.validator_key.id,
            stake_owner=pool.address.hash_part,
        )
        auth = request.parse_result(await self.request_pq_authorization(
            index, request, retry_restart_transients=retry_restart_transients,
        ))
        if auth.validator_id != controller.address.hash_part:
            raise AssertionError(f"validator {index + 1} node authorized the wrong controller")
        if auth.key_id != controller.consensus.key_id:
            raise AssertionError(f"validator {index + 1} node authorized the wrong consensus key")
        if auth.public_key != controller.consensus.public_key or auth.algorithm_id != 1:
            raise AssertionError(f"validator {index + 1} authorization differs from the bound key")
        signature = auth.signature
        if corrupt_signature_for_negative:
            if not signature:
                raise AssertionError("cannot corrupt an empty PQ stake signature")
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        body = build_production_pool_stake_order(
            self.install.build_dir / "tosctl/pq_pool_stake_order",
            query_id=query_id,
            stake_amount=stake_amount,
            stake_at=election_id,
            max_factor=MAX_FACTOR,
            adnl_addr=node.validator_key.id,
            algorithm_id=auth.algorithm_id,
            public_key=auth.public_key,
            signature=signature,
            witness=controller.birth_witness,
        )
        return body, auth.key_id

    async def request_pq_authorization(
        self, index: int, request: Any, *, retry_restart_transients: bool,
        timeout: float = 30.0,
    ) -> Any:
        """Retry only a restarted node's pre-send connection/state race.

        No wallet transaction has been sent at this point. Other authorization
        errors are not readiness signals and must remain immediate failures.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        connection_closures = 0
        not_started = 0
        while (remaining := deadline - loop.time()) > 0:
            try:
                async with asyncio.timeout(remaining):
                    response = await self.nodes[index].engine_console.request(request)
                if retry_restart_transients:
                    self.event(
                        "pq_authority_ready_after_restart", node=index + 1,
                        transient_connection_closures=connection_closures,
                        transient_not_started=not_started,
                    )
                return response
            except LocalError as error:
                if not retry_restart_transients or error.code != 0 or error.message != "Connection closed":
                    raise
                connection_closures += 1
            except RemoteError as error:
                if not retry_restart_transients or error.code != 651 or error.message not in (
                    "not started", "this node cannot authorise a stake: not started"
                ):
                    raise
                not_started += 1
            except TimeoutError:
                break
            await asyncio.sleep(min(0.5, max(0.0, deadline - loop.time())))
        raise TimeoutError(
            f"validator {index + 1} PQ authorization did not become ready within "
            f"{timeout:.1f}s after restart; Connection closed={connection_closures} "
            f"not started={not_started}"
        )

    async def submit_pq_candidate(
        self, index: int, election_id: int, *, round_number: int = 1,
        retry_restart_transients: bool = False
    ) -> dict[str, Any]:
        wallet = self.wallets[index]
        pool = self.pools[index]
        controller = self.controllers[index]
        # Pool transaction history spans elections. Reusing a query id could
        # let an old STAKE_ACCEPTED satisfy a new round's reply lookup.
        query_id = (round_number - 1) * 1_000 + index + 1
        body, authorization_key_id = await self.authorized_pq_pool_order(
            index, election_id, query_id,
            retry_restart_transients=retry_restart_transients,
        )
        elect_close = await self.require_open_pq_election(
            election_id, f"round-{round_number}-validator-{index + 1}",
        )
        body_path = self.artifacts_dir / f"pq-round-{round_number}-validator-{index + 1}-pool-order.boc"
        body_path.parent.mkdir(parents=True, exist_ok=True)
        body_path.write_bytes(body.to_boc())
        await self.send_from_wallet(
            wallet, dest=pool.address, amount=2 * NANO, body=body,
            label=f"pq-round-{round_number}-validator-{index + 1}-pool-stake-order",
        )
        opcode, detail = await self.wait_pq_pool_elector_reply(
            index, query_id, description=f"validator {index + 1} elector answer to pool"
        )
        elector_input = await self.retry(
            lambda: self.exact_pq_elector_input(controller.address, query_id),
            timeout=30, description=f"validator {index + 1} exact Elector inbound",
            predicate=lambda value: value is not None,
        )
        input_path = self.artifacts_dir / (
            f"pq-round-{round_number}-validator-{index + 1}-elector-input-transaction.boc"
        )
        input_path.write_bytes(elector_input.data)
        input_id = elector_input.transaction_id
        self.event(
            "pq_candidate_elector_input_observed", validator=index + 1,
            round=round_number, query_id=query_id, election_id=election_id,
            elect_close=elect_close, elector_input_utime=elector_input.utime,
            elector_input_lt=input_id.lt if input_id is not None else None,
            elector_input_hash=input_id.hash.hex() if input_id is not None else None,
            elector_input_boc=self.file_provenance(input_path),
            elector_reply_opcode=f"0x{opcode:08x}", elector_reply_detail=detail,
        )
        if elector_input.utime >= elect_close:
            raise AssertionError(
                f"PQ validator {index + 1} Elector inbound was after election close: "
                f"query_id={query_id} utime={elector_input.utime} elect_close={elect_close} "
                f"reply=0x{opcode:08x}/{detail}"
            )
        if opcode != 0xF374484C:
            raise AssertionError(
                f"PQ validator {index + 1} did not receive STAKE_ACCEPTED: "
                f"elector opcode=0x{opcode:08x} reason={detail}"
            )
        participant_id = "0x" + controller.address.hash_part.hex()
        actual = await self.retry(
            lambda: self.runmethod_int("participates_in", participant_id),
            timeout=90,
            description=f"PQ controller {index + 1} accepted stake",
            predicate=lambda value: value >= EFFECTIVE_STAKE,
        )
        self.event(
            "pq_candidate_accepted", validator=index + 1,
            round=round_number, query_id=query_id,
            controller=raw_address(controller.address),
            pool=raw_address(pool.address), election_id=election_id,
            effective_stake=actual, authorization_key_id=authorization_key_id.hex(),
            stake_accepted=True, elector_reply_opcode=f"0x{opcode:08x}",
        )
        return {
            "query_id": query_id,
            "authorization_key_id_hex": authorization_key_id.hex(),
            "controller_id_hex": controller.address.hash_part.hex(),
            "stake_owner_pool_raw": raw_address(pool.address),
            "body_boc": self.file_provenance(body_path),
            "elector_reply_opcode": f"0x{opcode:08x}",
            "effective_stake_nanotos": actual,
        }

    async def require_open_pq_election(self, election_id: int, label: str) -> int:
        output = await self.runmethod("participant_list_extended")
        path = self.artifacts_dir / f"pq-{label}-presend-window.txt"
        path.write_text(output)
        window = re.search(r"result:\s*\[\s*(\d+)\s+(\d+)", output)
        if window is None:
            raise RuntimeError(f"PQ {label} has no readable Elector acceptance window")
        elect_at, elect_close = map(int, window.groups())
        chain_time = await self.chain_time()
        self.event(
            "pq_candidate_presend_window", label=label,
            election_id=election_id, elect_at=elect_at,
            elect_close=elect_close, chain_time=chain_time,
            raw_window=self.file_provenance(path),
        )
        if elect_at != election_id or elect_close - chain_time <= 30:
            raise RuntimeError(
                f"PQ {label} lacks an open election acceptance window: "
                f"target={election_id} elect_at={elect_at} "
                f"elect_close={elect_close} chain_time={chain_time}"
            )
        return elect_close

    async def exact_pq_elector_input(self, source: Address, query_id: int) -> Any | None:
        assert self.client is not None
        state = await self.client.raw_get_account_state(ELECTOR)
        cursor = state.last_transaction_id
        for _ in range(32):
            if cursor is None:
                return None
            page = await self.client.raw_get_transactions(ELECTOR, cursor)
            for transaction in page.transactions:
                message = transaction.in_msg
                if (message is None or message.source is None
                        or not message.source.account_address
                        or Address(message.source.account_address) != source
                        or not isinstance(message.msg_data, toslib_api.Msg_dataRaw)):
                    continue
                body_slice = Cell.one_from_boc(message.msg_data.body).begin_parse()
                if (body_slice.remaining_bits >= 96
                        and body_slice.load_uint(32) == 0x50517374
                        and body_slice.load_uint(64) == query_id):
                    return transaction
            previous = page.previous_transaction_id
            if previous is None or previous.lt >= cursor.lt:
                return None
            cursor = previous
        return None

    async def wait_pq_pool_elector_reply(
        self, index: int, query_id: int, *, description: str
    ) -> tuple[int, int]:
        """Read the elector reply received by this pool, not a successful send."""
        assert self.client is not None
        pool = self.pools[index]

        async def pool_answer() -> tuple[int, int] | None:
            state = await self.client.raw_get_account_state(pool.address)
            if state.last_transaction_id is None:
                return None
            transactions = await self.client.raw_get_transactions(
                pool.address, state.last_transaction_id
            )
            return elector_reply(transactions.transactions, query_id)

        return await self.retry(
            pool_answer, timeout=60, description=description,
            predicate=lambda value: value is not None,
        )

    async def assert_pq_first_round_negative_cases(self, election_id: int) -> None:
        """Exercise three distinct elector refusals through the real pool route.

        These are not direct-wallet layout probes. The node supplies each
        authorization; only the named negative property is changed before
        the production builder encodes the pool order.
        """
        controller_id = "0x" + self.controllers[0].address.hash_part.hex()
        cases = (
            ("under-minimum", election_id, 1_001 * NANO, False, 5),
            ("wrong-election", election_id + 1, PQ_STAKE_MESSAGE_VALUE, False, 3),
            ("invalid-signature", election_id, PQ_STAKE_MESSAGE_VALUE, True, 1),
        )
        for offset, (label, signed_election_id, stake_amount, corrupt, expected_reason) in enumerate(cases):
            query_id = 101 + offset
            before = await self.runmethod_int("participates_in", controller_id)
            body, _ = await self.authorized_pq_pool_order(
                0, signed_election_id, query_id,
                stake_amount=stake_amount,
                corrupt_signature_for_negative=corrupt,
            )
            await self.send_from_wallet(
                self.wallets[0], dest=self.pools[0].address, amount=2 * NANO,
                body=body, label=f"pq-negative-{label}-pool-order",
            )
            opcode, reason = await self.wait_pq_pool_elector_reply(
                0, query_id, description=f"PQ {label} elector refusal through pool"
            )
            if opcode != 0xEE6F454C or reason != expected_reason:
                raise AssertionError(
                    f"PQ {label} refusal was opcode=0x{opcode:08x} reason={reason}, "
                    f"expected elector return reason {expected_reason}"
                )
            after = await self.runmethod_int("participates_in", controller_id)
            if after != before:
                raise AssertionError(
                    f"PQ {label} refusal changed controller participation: {before} -> {after}"
                )
            self.event(
                "pq_negative_pool_order_refused", case=label,
                election_id=election_id, query_id=query_id,
                reason=reason, expected_reason=expected_reason,
                participation_before=before, participation_after=after,
            )

    async def run_pq_first_election(self) -> None:
        if len(self.pools) != VALIDATOR_COUNT:
            raise AssertionError("PQ election has no four-pool fixture")
        self.first_election_id = await self.retry(
            lambda: self.runmethod_int("active_election_id"),
            timeout=max(600, self.profile.initial_set_valid + 300),
            interval=self.long_poll_interval,
            description="first PQ election opening",
            predicate=lambda value: value > 0,
        )
        self.event("pq_first_election_open", election_id=self.first_election_id)
        await self.assert_unwitnessed_wallet_stake_refused(self.first_election_id)
        await self.assert_pq_first_round_negative_cases(self.first_election_id)
        for index in range(VALIDATOR_COUNT - 1):
            await self.submit_pq_candidate(index, self.first_election_id)
            if index == 0:
                # Exercise duplicate-key admission while the same election is
                # demonstrably open. The later fourth-node restart can consume
                # the remaining window; reason 0 then masks reason 4.
                await self.assert_duplicate_pq_key_refused(self.first_election_id)
        three_output = await self.runmethod("participant_list_extended")
        (self.artifacts_dir / "pq-first-three-participants.txt").write_text(three_output)
        three_ids = participant_ids_from_runmethod(three_output)
        expected_three = {
            int.from_bytes(controller.address.hash_part, "big")
            for controller in self.controllers[: VALIDATOR_COUNT - 1]
        }
        total_match = re.search(r"result:\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", three_output)
        three_stake = int(total_match.group(4)) if total_match is not None else -1
        if three_ids != expected_three or not 0 < three_stake < VALIDATOR_COUNT * EFFECTIVE_STAKE:
            raise AssertionError(
                "PQ three-participant state is not below the four-validator threshold: "
                f"ids={sorted(three_ids)} total_stake={three_stake}"
            )
        self.event(
            "pq_below_minimum_total_observed", controllers=3,
            total_stake=three_stake, required_total=VALIDATOR_COUNT * EFFECTIVE_STAKE,
        )
        await self.restart_node(3, "open first PQ election")
        await self.submit_pq_candidate(3, self.first_election_id, retry_restart_transients=True)
        participant_output = await self.runmethod("participant_list_extended")
        (self.artifacts_dir / "pq-first-participants.txt").write_text(participant_output)
        participant_ids = participant_ids_from_runmethod(participant_output)
        expected_ids = {
            int.from_bytes(controller.address.hash_part, "big")
            for controller in self.controllers
        }
        if participant_ids != expected_ids:
            raise AssertionError(
                "PQ election participants differ from the four controllers: "
                f"missing={sorted(expected_ids - participant_ids)} "
                f"unexpected={sorted(participant_ids - expected_ids)}"
            )
        self.event("pq_first_election_participants", controllers=len(participant_ids))
        await self.wait_until_chain_time(
            self.first_election_id - 55, "first PQ election closed"
        )
        self.first_config34 = await self.retry(
            self.get_config34,
            timeout=180,
            description="PQ elected ConfigParam 34 activation",
            predicate=lambda value: value.utime_since == self.first_election_id,
        )
        actual_ids = {value.upper() for value in self.first_config34.validator_ids}
        expected_ids_hex = {
            controller.address.hash_part.hex().upper() for controller in self.controllers
        }
        expected_adnl = {node.validator_key.id.hex().upper() for node in self.nodes}
        actual_adnl = {value.upper() for value in self.first_config34.adnl_ids}
        expected_associations = {
            controller.address.hash_part.hex().upper(): node.validator_key.id.hex().upper()
            for controller, node in zip(self.controllers, self.nodes, strict=True)
        }
        require_pq_config34_associations(self.first_config34, expected_associations)
        if (
            actual_ids != expected_ids_hex
            or actual_adnl != expected_adnl
            or self.first_config34.total != VALIDATOR_COUNT
            or self.first_config34.main != VALIDATOR_COUNT
        ):
            raise AssertionError(
                "PQ elected ConfigParam 34 is not exactly the four controllers: "
                f"missing={sorted(expected_ids_hex - actual_ids)} "
                f"unexpected={sorted(actual_ids - expected_ids_hex)} "
                f"adnl_missing={sorted(expected_adnl - actual_adnl)} "
                f"adnl_unexpected={sorted(actual_adnl - expected_adnl)} "
                f"total={self.first_config34.total} main={self.first_config34.main}"
            )
        self.event(
            "pq_first_election_activated", election_id=self.first_election_id,
            controllers=VALIDATOR_COUNT, config34=asdict(self.first_config34),
        )
        await self.capture_f01_transition("first PQ set")
        await self.verify_three_of_four_liveness()
        await self.assert_pq_early_recovery_no_credit()

    async def assert_pq_early_recovery_no_credit(self) -> None:
        """The pool owns the credit; the validator wallet does not."""
        pool = self.pools[0]
        pool_id = "0x" + pool.address.hash_part.hex()
        before_credit = await self.runmethod_int("compute_returned_stake", pool_id)
        if before_credit != 0:
            raise AssertionError(f"PQ pool stake recoverable before unfreeze: {before_credit}")
        before_balance = await self.balance(pool.address)
        body = await self.recovery_body("pq-early-recovery")
        view = body.begin_parse()
        if view.load_uint(32) != 0x47657424:
            raise AssertionError("PQ pool early-recovery body has the wrong opcode")
        query_id = view.load_uint(64)
        if view.remaining_bits or view.remaining_refs:
            raise AssertionError("PQ pool early-recovery body has trailing data")
        await self.send_from_wallet(
            self.wallets[0], dest=pool.address, amount=1 * NANO,
            body=body, label="pq-early-pool-recovery",
        )
        opcode, detail = await self.wait_pq_pool_elector_reply(
            0, query_id, description="PQ pool early-recovery elector refusal"
        )
        if opcode != 0xFFFFFFFE or detail != 0x47657424:
            raise AssertionError(
                "PQ pool early recovery did not receive elector no-credit reply: "
                f"opcode=0x{opcode:08x} detail=0x{detail:08x}"
            )
        after_credit = await self.runmethod_int("compute_returned_stake", pool_id)
        after_balance = await self.balance(pool.address)
        if after_credit != 0 or after_balance >= before_balance + 2 * NANO:
            raise AssertionError(
                "PQ pool early recovery credited principal before unfreeze: "
                f"credit={before_credit}->{after_credit} balance={before_balance}->{after_balance}"
            )
        self.event(
            "pq_early_recovery_no_credit", pool=raw_address(pool.address),
            query_id=query_id, elector_reply_opcode=f"0x{opcode:08x}",
            credit_before=before_credit, credit_after=after_credit,
            balance_before=before_balance, balance_after=after_balance,
        )

    async def wait_pq_config_activation(self, election_id: int, label: str) -> Config34:
        config = await self.retry(
            self.get_config34, timeout=180, interval=1,
            description=f"{label} PQ ConfigParam 34 activation",
            predicate=lambda value: value.utime_since == election_id,
        )
        expected = {
            controller.address.hash_part.hex().upper(): node.validator_key.id.hex().upper()
            for controller, node in zip(self.controllers, self.nodes)
        }
        if config.total != VALIDATOR_COUNT or config.main != VALIDATOR_COUNT:
            raise AssertionError(
                f"{label} PQ elected set is not four main validators: {asdict(config)}"
            )
        require_pq_config34_associations(config, expected)
        await self.capture_f01_transition(label)
        self.event(
            "pq_config34_activated", label=label, election_id=election_id,
            total=config.total, main=config.main,
            validator_adnl_pairs=config.validator_adnl_pairs,
        )
        return config

    async def prefund_pq_followup_rounds(self, faucet: WalletV1) -> None:
        """Fund rounds 2 and 3 before any short election window opens.

        This is fixture capital, not a returned stake. Funding inside an
        election window can make a valid fourth order arrive after elect_close.
        """
        for index in range(VALIDATOR_COUNT):
            await self.prefund_pq_followup_pool(faucet, index)

    async def prefund_pq_followup_pool(self, faucet: WalletV1, index: int) -> None:
        wallet = self.wallets[index]
        pool = self.pools[index]
        amount = 2 * (PQ_STAKE_MESSAGE_VALUE + 20 * NANO)
        wallet_before = await self.balance(wallet.address)
        await self.send_from_wallet(
            faucet, dest=wallet.address, amount=amount + 40 * NANO,
            body=Cell.empty(),
            label=f"pq-followup-validator-{index + 1}-wallet-capital",
        )
        await self.retry(
            lambda: self.balance(wallet.address), timeout=60,
            description=f"PQ followup wallet {index + 1} fresh capital",
            predicate=lambda value: value >= wallet_before + amount,
        )
        before = await self.balance(pool.address)
        await self.send_from_wallet(
            wallet, dest=pool.address, amount=amount, body=Cell.empty(),
            label=f"pq-followup-validator-{index + 1}-pool-capital",
        )
        after = await self.retry(
            lambda: self.balance(pool.address), timeout=60,
            description=f"PQ followup pool {index + 1} fresh capital",
            predicate=lambda value: value >= before + amount - 2 * NANO,
        )
        self.event(
            "pq_followup_pool_prefunded", rounds=[2, 3], validator=index + 1,
            fresh_from_faucet=amount + 40 * NANO, fresh_to_pool=amount,
            pool_balance_before=before, pool_balance_after=after,
        )

    async def require_pq_full_faucet_capacity(self, faucet: WalletV1) -> None:
        actual = await self.balance(faucet.address)
        required = PQ_FULL_FOLLOWUP_FAUCET_CAPITAL + PQ_FULL_FAUCET_FEE_RESERVE
        if actual < required:
            raise AssertionError(
                f"full PQ rehearsal faucet cannot fund rounds 2 and 3: "
                f"balance={actual} required={required}"
            )
        self.event(
            "pq_full_faucet_capacity", balance=actual, required=required,
            genesis_budget=PQ_FULL_GENESIS_FAUCET_FUNDING,
        )

    async def recover_pq_round(self, round_number: int) -> list[int]:
        election_id = self.first_election_id if round_number == 1 else self.second_election_id
        unfreeze_at = election_id + self.profile.elected_for + self.profile.stakes_frozen_for
        credit_timeout = max(240, unfreeze_at - int(time.time()) + 90)
        credits: list[int] = []
        for index, (wallet, pool) in enumerate(zip(self.wallets, self.pools)):
            pool_id = "0x" + pool.address.hash_part.hex()
            credit = await self.retry(
                lambda pool_id=pool_id: self.runmethod_int("compute_returned_stake", pool_id),
                timeout=credit_timeout, interval=max(2.0, self.long_poll_interval),
                description=f"PQ round {round_number} pool {index + 1} mature credit",
                predicate=lambda value: value > EFFECTIVE_STAKE,
            )
            before = await self.balance(pool.address)
            body = await self.recovery_body(f"pq-round-{round_number}-pool-{index + 1}")
            view = body.begin_parse()
            if view.load_uint(32) != 0x47657424:
                raise AssertionError("PQ pool recovery body has the wrong opcode")
            query_id = view.load_uint(64)
            if view.remaining_bits or view.remaining_refs:
                raise AssertionError("PQ pool recovery body has trailing data")
            await self.send_from_wallet(
                wallet, dest=pool.address, amount=1 * NANO, body=body,
                label=f"pq-round-{round_number}-pool-{index + 1}-recover",
            )
            opcode, detail = await self.wait_pq_pool_elector_reply(
                index, query_id,
                description=f"PQ round {round_number} pool {index + 1} mature elector recovery",
            )
            if opcode != 0xF96F7324 or detail != 0:
                raise AssertionError(
                    f"PQ round {round_number} pool {index + 1} did not receive mature "
                    f"recovery opcode: 0x{opcode:08x} detail={detail}"
                )
            await self.retry(
                lambda pool_id=pool_id: self.runmethod_int("compute_returned_stake", pool_id),
                timeout=60,
                description=f"PQ round {round_number} pool {index + 1} credit deletion",
                predicate=lambda value: value == 0,
            )
            after = await self.retry(
                lambda pool=pool: self.balance(pool.address), timeout=60,
                description=f"PQ round {round_number} pool {index + 1} payout",
                predicate=lambda value, before=before, credit=credit: value >= before + credit - 2 * NANO,
            )
            credits.append(credit)
            self.event(
                "pq_pool_stake_recovered", round=round_number, validator=index + 1,
                pool=raw_address(pool.address), query_id=query_id, credit=credit,
                pool_balance_before=before, pool_balance_after=after,
                elector_reply_opcode=f"0x{opcode:08x}",
            )
        return credits

    async def assert_duplicate_pq_recovery_no_credit(self) -> None:
        pool = self.pools[0]
        pool_id = "0x" + pool.address.hash_part.hex()
        before_credit = await self.runmethod_int("compute_returned_stake", pool_id)
        if before_credit != 0:
            raise AssertionError(f"duplicate PQ recovery still has pool credit {before_credit}")
        before_balance = await self.balance(pool.address)
        body = await self.recovery_body("pq-duplicate-pool-recovery")
        view = body.begin_parse()
        if view.load_uint(32) != 0x47657424:
            raise AssertionError("duplicate PQ recovery body has the wrong opcode")
        query_id = view.load_uint(64)
        await self.send_from_wallet(
            self.wallets[0], dest=pool.address, amount=1 * NANO, body=body,
            label="pq-duplicate-pool-recovery",
        )
        opcode, detail = await self.wait_pq_pool_elector_reply(
            0, query_id, description="PQ duplicate pool recovery elector refusal",
        )
        after_credit = await self.runmethod_int("compute_returned_stake", pool_id)
        after_balance = await self.balance(pool.address)
        if opcode != 0xFFFFFFFE or detail != 0x47657424 or after_credit != 0:
            raise AssertionError(
                "PQ duplicate recovery did not receive the exact no-credit refusal: "
                f"opcode=0x{opcode:08x} detail=0x{detail:08x} credit={after_credit}"
            )
        if after_balance >= before_balance + 2 * NANO:
            raise AssertionError(
                f"PQ duplicate recovery unexpectedly credited pool: {before_balance}->{after_balance}"
            )
        self.event(
            "pq_duplicate_recovery_no_credit", query_id=query_id,
            elector_reply_opcode=f"0x{opcode:08x}",
            pool_balance_before=before_balance, pool_balance_after=after_balance,
        )

    async def run_pq_followup_elections(self, faucet: WalletV1) -> None:
        """Run later elections using capital placed before the first window."""
        self.second_election_id = await self.retry(
            lambda: self.runmethod_int("active_election_id"),
            timeout=max(240, self.profile.elected_for), interval=self.long_poll_interval,
            description="second PQ election opening",
            predicate=lambda value: value > self.first_election_id,
        )
        self.event("pq_second_election_open", election_id=self.second_election_id)
        for index in range(VALIDATOR_COUNT):
            await self.submit_pq_candidate(
                index, self.second_election_id, round_number=2,
                retry_restart_transients=True,
            )
        second_output = await self.runmethod("participant_list_extended")
        (self.artifacts_dir / "pq-round-2-participants.txt").write_text(second_output)
        expected_ids = {int.from_bytes(c.address.hash_part, "big") for c in self.controllers}
        if participant_ids_from_runmethod(second_output) != expected_ids:
            raise AssertionError("second PQ election participants are not exactly four controllers")
        await self.wait_until_chain_time(self.second_election_id - 55, "second PQ election closed")
        await self.restart_node(2, "second PQ election before ConfigParam 34 activation")
        self.second_config34 = await self.wait_pq_config_activation(
            self.second_election_id, "second PQ set"
        )
        await self.restart_node(1, "PQ rewards before first pool recovery")

        self.rollover_election_id = await self.retry(
            lambda: self.runmethod_int("active_election_id"),
            timeout=max(240, self.profile.elected_for), interval=self.long_poll_interval,
            description="rollover PQ election opening",
            predicate=lambda value: value > self.second_election_id,
        )
        self.event("pq_rollover_election_open", election_id=self.rollover_election_id)
        for index in range(VALIDATOR_COUNT):
            await self.submit_pq_candidate(
                index, self.rollover_election_id, round_number=3,
                retry_restart_transients=True,
            )
        rollover_output = await self.runmethod("participant_list_extended")
        (self.artifacts_dir / "pq-round-3-participants.txt").write_text(rollover_output)
        if participant_ids_from_runmethod(rollover_output) != expected_ids:
            raise AssertionError("rollover PQ election participants are not exactly four controllers")
        past_first = await self.runmethod("past_elections")
        (self.artifacts_dir / "pq-past-elections-before-first-recovery.txt").write_text(past_first)
        self.first_credits = await self.recover_pq_round(1)
        await self.wait_until_chain_time(self.rollover_election_id - 55, "rollover PQ election closed")
        self.rollover_config34 = await self.wait_pq_config_activation(
            self.rollover_election_id, "rollover PQ set"
        )
        past_second = await self.runmethod("past_elections")
        (self.artifacts_dir / "pq-past-elections-before-second-recovery.txt").write_text(past_second)
        self.second_credits = await self.recover_pq_round(2)
        await self.assert_duplicate_pq_recovery_no_credit()
        await self.verify_two_of_four_safe_halt()
        self.event(
            "pq_full_launch_gate_passed", first_election_id=self.first_election_id,
            second_election_id=self.second_election_id,
            rollover_election_id=self.rollover_election_id,
            first_credits=self.first_credits, second_credits=self.second_credits,
        )

    async def assert_unwitnessed_wallet_stake_refused(self, election_id: int) -> None:
        """A deliberately elector-layout negative request must reach admission reason 8.

        A pool-layout body would underflow in the elector parser and bounce; it
        cannot prove that the Genesis controller policy is enforced.
        """
        assert self.negative_wallet is not None and self.client is not None
        wallet = self.negative_wallet
        node = self.nodes[0]
        query_id = 0xE1EC7
        request = tos_api.Engine_validator_createPqStakeAuthorizationRequest(
            election_date=election_id, max_factor=MAX_FACTOR,
            adnl_addr=node.validator_key.id, stake_owner=wallet.address.hash_part,
        )
        auth = request.parse_result(await node.engine_console.request(request))
        public_key = Builder().store_uint(1312, 32).store_ref(byte_chain(auth.public_key)).end_cell()
        signature = Builder().store_uint(2420, 32).store_ref(byte_chain(auth.signature)).end_cell()
        body = (
            # Direct-to-elector negative control uses PQst, not the pool's
            # NEW_STAKE opcode. This body is never a client staking path.
            Builder().store_uint(0x50517374, 32).store_uint(query_id, 64)
            .store_uint(auth.algorithm_id, 16).store_ref(public_key)
            .store_uint(election_id, 32).store_uint(MAX_FACTOR, 32)
            .store_bytes(node.validator_key.id).store_ref(signature)
            .store_maybe_ref(None).store_bit(0).end_cell()
        )
        await self.send_from_wallet(
            wallet, dest=ELECTOR, amount=PQ_STAKE_MESSAGE_VALUE,
            body=body, label="negative-wallet-no-controller-birth-witness",
        )

        async def reason_reply() -> tuple[int, int] | None:
            state = await self.client.raw_get_account_state(wallet.address)
            if state.last_transaction_id is None:
                return None
            transactions = await self.client.raw_get_transactions(
                wallet.address, state.last_transaction_id
            )
            return elector_reply(transactions.transactions, query_id)

        opcode, reason = await self.retry(
            reason_reply, timeout=60, description="negative wallet elector return reason",
            predicate=lambda value: value is not None,
        )
        if opcode != 0xEE6F454C or reason != 8:
            raise AssertionError(
                f"negative wallet without controller birth witness was refused for "
                f"opcode=0x{opcode:08x} reason={reason}, expected elector return reason 8"
            )
        self.event("pq_negative_wallet_refused", reason=reason, expected_reason=8)

    async def assert_duplicate_pq_key_refused(self, election_id: int) -> None:
        """A second account cannot claim an already held PQ consensus key.

        This deliberately sends an elector-layout test probe, never a client
        stake. The elector checks key ownership before controller admission,
        so the direct wallet must receive reason 4 rather than reason 8.
        """
        assert self.negative_wallet is not None and self.client is not None
        wallet = self.negative_wallet
        node = self.nodes[0]
        controller_id = "0x" + self.controllers[0].address.hash_part.hex()
        before = await self.runmethod_int("participates_in", controller_id)
        window_output = await self.runmethod("participant_list_extended")
        (self.artifacts_dir / "pq-duplicate-key-presend-window.txt").write_text(window_output)
        window = re.search(r"result:\s*\[\s*(\d+)\s+(\d+)", window_output)
        if window is None:
            raise RuntimeError("PQ duplicate-key control has no live Elector window")
        elect_at, elect_close = map(int, window.groups())
        presend_chain_time = await self.chain_time()
        if elect_at != election_id or elect_close - presend_chain_time <= 30:
            raise RuntimeError(
                "PQ duplicate-key control lacks an open election window: "
                f"elect_at={elect_at} elect_close={elect_close} "
                f"chain_time={presend_chain_time}"
            )
        query_id = 0xE1EC8
        request = tos_api.Engine_validator_createPqStakeAuthorizationRequest(
            election_date=election_id, max_factor=MAX_FACTOR,
            adnl_addr=node.validator_key.id, stake_owner=wallet.address.hash_part,
        )
        auth = request.parse_result(await node.engine_console.request(request))
        public_key = Builder().store_uint(1312, 32).store_ref(byte_chain(auth.public_key)).end_cell()
        signature = Builder().store_uint(2420, 32).store_ref(byte_chain(auth.signature)).end_cell()
        body = (
            Builder().store_uint(0x50517374, 32).store_uint(query_id, 64)
            .store_uint(auth.algorithm_id, 16).store_ref(public_key)
            .store_uint(election_id, 32).store_uint(MAX_FACTOR, 32)
            .store_bytes(node.validator_key.id).store_ref(signature)
            .store_maybe_ref(None).store_bit(0).end_cell()
        )
        await self.send_from_wallet(
            wallet, dest=ELECTOR, amount=PQ_STAKE_MESSAGE_VALUE,
            body=body, label="pq-negative-duplicate-key",
        )

        async def duplicate_reply() -> tuple[int, int, Any] | None:
            state = await self.client.raw_get_account_state(wallet.address)
            if state.last_transaction_id is None:
                return None
            transactions = await self.client.raw_get_transactions(
                wallet.address, state.last_transaction_id
            )
            for transaction in transactions.transactions:
                reply = elector_reply([transaction], query_id)
                if reply is not None:
                    return reply[0], reply[1], transaction
            return None

        opcode, reason, reply_transaction = await self.retry(
            duplicate_reply, timeout=60,
            description="PQ duplicate key elector return reason",
            predicate=lambda value: value is not None,
        )
        receipt_path = self.artifacts_dir / "pq-duplicate-key-elector-reply-transaction.boc"
        receipt_path.write_bytes(reply_transaction.data)
        receipt_id = reply_transaction.transaction_id

        input_transaction = await self.retry(
            lambda: self.exact_pq_elector_input(wallet.address, query_id), timeout=30,
            description="PQ duplicate key exact Elector inbound transaction",
            predicate=lambda value: value is not None,
        )
        input_path = self.artifacts_dir / "pq-duplicate-key-elector-input-transaction.boc"
        input_path.write_bytes(input_transaction.data)
        input_id = input_transaction.transaction_id
        self.event(
            "pq_duplicate_key_reply_observed", election_id=election_id,
            elect_close=elect_close, presend_chain_time=presend_chain_time,
            elector_input_utime=input_transaction.utime,
            elector_input_lt=input_id.lt if input_id is not None else None,
            elector_input_hash=input_id.hash.hex() if input_id is not None else None,
            elector_input_boc=self.file_provenance(input_path),
            reply_utime=reply_transaction.utime,
            reply_lt=receipt_id.lt if receipt_id is not None else None,
            reply_hash=receipt_id.hash.hex() if receipt_id is not None else None,
            reply_boc=self.file_provenance(receipt_path),
            opcode=f"0x{opcode:08x}", reason=reason,
        )
        if input_transaction.utime >= elect_close:
            raise AssertionError(
                "PQ duplicate-key control reached Elector after election close: "
                f"elector_input_utime={input_transaction.utime} elect_close={elect_close}"
            )
        if opcode != 0xEE6F454C or reason != 4:
            raise AssertionError(
                f"PQ duplicate held key returned opcode=0x{opcode:08x} reason={reason}, "
                "expected elector reason 4"
            )
        after = await self.runmethod_int("participates_in", controller_id)
        if after != before:
            raise AssertionError(
                f"PQ duplicate held key changed first controller's stake: {before} -> {after}"
            )
        self.event(
            "pq_duplicate_key_refused", reason=reason, expected_reason=4,
            participation_before=before, participation_after=after,
        )

    async def execute(self) -> None:
        if self.pq_election:
            require_pq_stake_authorization_binding(
                tos_api.Engine_validator_pqStakeAuthorization
            )
        self.ensure_experiment_rpc_ports_available()
        self.run_dir.mkdir(parents=True, exist_ok=False)
        self.network_dir.mkdir()
        self.artifacts_dir.mkdir()
        if self.pq_election:
            # Compile before the chain starts: the election window must not be
            # spent building a diagnostic executable. Its only encoding call
            # is the production nominator::new_stake_with_witness builder.
            result = subprocess.run(
                ["cargo", "build", "--manifest-path", "tosctl/src/Cargo.toml",
                 "-p", "contracts", "--example", "pq_pool_stake_order", "--locked"],
                cwd=REPO, text=True, capture_output=True, check=False,
            )
            if result.returncode:
                raise RuntimeError(
                    "cannot build production PQ pool order bridge: " + result.stderr[-4000:]
                )
        self.prepare_artifact_snapshot()
        if self.fixture_only or self.pq_election:
            self.install.toslibjson.client_set_verbosity_level(0)
            self.controller_code = compile_controller_code(
                self.install, self.artifacts_dir / "compiled-controller"
            )
            self.pool_code = Cell.one_from_boc(
                bytes.fromhex(
                    (self.install.source_dir /
                     "crypto/smartcont/single-nominator-pool/single-nominator-code.hex")
                    .read_text().strip()
                )
            )
            self.controllers = [
                make_controller_fixture(
                    self.install, self.artifacts_dir / "controller-keys", self.controller_code, index
                )
                for index in range(VALIDATOR_COUNT)
            ]
        start_event = (
            "validator_experiment_start"
            if self.experiment is not None
            else f"stage_{self.profile.stage}_start"
        )
        self.event(
            start_event,
            stage=self.profile.label,
            mode=("fixture-check" if self.fixture_only else
                  "experiment" if self.experiment is not None and not self.soak_mode else
                  "pq-launch-gate" if self.pq_full else
                  "pq-election" if self.pq_election else
                  "transfer-soak" if self.soak_mode else "launch-gate"),
            accelerated=self.profile.accelerated,
            source_commit=self.provenance["source_commit"],
            artifact_snapshot=str(self.run_dir / "artifact-snapshot"),
            base_port=self.base_port,
            production_defaults_unchanged=not (self.fixture_only or self.pq_election),
        )

        network = Network(
            self.install,
            self.network_dir,
            base_port=self.base_port,
        )
        self.network = network
        try:
            self.configure_network_profile(network.config)

            dht = network.create_dht_node()
            for validator_index in range(VALIDATOR_COUNT):
                node = network.create_full_node()
                if self.fixture_only or self.pq_election:
                    controller = self.controllers[validator_index]
                    make_deterministic_pq_initial_validator(
                        node, validator_index, validator_id=controller.address.hash_part
                    )
                    assert_controller_identity(node, controller, index=validator_index + 1)
                    self.event(
                        "controller_identity_bound",
                        validator=validator_index + 1,
                        controller_id=controller.address.hash_part.hex(),
                        node_validator_id=node.pq_initial_validator.validator_id.hex(),
                        node_key_id=node.pq_initial_validator.key_id.hex(),
                    )
                else:
                    make_deterministic_pq_initial_validator(node, validator_index)
                node.announce_to(dht)
                self.nodes.append(node)

            await dht.run(StartOptions(threads=2, verbosity=3))
            for index, node in enumerate(self.nodes):
                await node.run(self.validator_start_options(index))
                self.record_f01_process(index)

            self.lite_config.write_text(self.nodes[0]._liteserver_config.to_json())
            await asyncio.wait_for(network.wait_mc_block(seqno=3), timeout=120)
            self.client = await self.nodes[0].toslib_client()
            if self.fixture_only or self.pq_election:
                await self.verify_live_controller_policy()
            self.monitor_task = asyncio.create_task(self.metrics_monitor())

            config15 = await self.lite("time", "getconfig 15 16 17 28 34")
            (self.artifacts_dir / "initial-config.txt").write_text(config15)
            if (
                f"validators_elected_for:{self.profile.elected_for}" not in config15
                or (f"elections_start_before:{self.profile.elect_start_before}" not in config15)
                or (f"elections_end_before:{self.profile.elect_end_before}" not in config15)
                or (f"stake_held_for:{self.profile.stakes_frozen_for}" not in config15)
            ):
                raise AssertionError(
                    f"{self.profile.label} ConfigParam 15 does not match its profile"
                )
            if "min_validators:4" not in config15:
                raise AssertionError(f"{self.profile.label} changed ConfigParam 16")
            if "value:10000000000000" not in config15:
                raise AssertionError(f"{self.profile.label} changed the 10,000 TOS minimum stake")

            self.initial_config34 = await self.get_config34()
            if self.pq_full:
                self.f01_previous_config_height = await self.masterchain_seqno()
                self.f01_previous_config_hash = (await self.client.get_config_param(34)).hash.hex()
            self.event(
                "network_ready",
                initial_config34=asdict(self.initial_config34),
                masterchain_seqno=await self.masterchain_seqno(),
            )

            faucet = network.zerostate.main_wallet(self.client)

            if self.soak_mode:
                self.monitor_task = asyncio.create_task(self.metrics_monitor())
                await self.transfer_soak(faucet)
                return

            await self.setup_wallets(faucet)

            if self.fixture_only or self.pq_election:
                await self.deploy_pq_fixture_accounts(faucet)
                self.event(
                    "pq_election_fixture_ready",
                    controllers=len(self.controllers),
                    pools=len(self.pools),
                    live_policy_admitted=True,
                    rehearsal_election_executed=False,
                )
                if self.fixture_only:
                    return
                if self.experiment is not None:
                    await self.run_experiment()
                    return
                if self.pq_full:
                    await self.require_pq_full_faucet_capacity(faucet)
                    await self.prefund_pq_followup_rounds(faucet)
                await self.run_pq_first_election()
                if self.pq_full:
                    await self.run_pq_followup_elections(faucet)
                return

        except Exception as error:
            self.fail(f"{type(error).__name__}: {error}")
            if (
                self.experiment is not None
                and self.network is not None
                and len(self.wallets) == VALIDATOR_COUNT
            ):
                evidence_status = (
                    "partial-settlement"
                    if self.experiment_final_status == "partial-settlement"
                    else "failed"
                )
                self.publish_allocation_evidence(evidence_status)
            raise
        finally:
            self._monitor_stop.set()
            if self.monitor_task is not None:
                await self.monitor_task
            await network.aclose()
            self.write_report()

    def write_report(self) -> None:
        if self.pq_full:
            try:
                self.write_f01_capture()
                if (self.x01_policy is not None
                        and (self.x01_directory / "trace.json").is_file()):
                    self.write_x01_check()
            except Exception as error:
                self.fail(f"F01/X01 Stage A capture incomplete: {error}")
        report = {
            "status": self.report_status(),
            "generated_at": utc_now(),
            "run_dir": str(self.run_dir),
            "mode": ("fixture-check" if self.fixture_only else
                     "experiment" if self.experiment is not None and not self.soak_mode else
                     "pq-launch-gate" if self.pq_full else
                     "pq-election" if self.pq_election else
                     "transfer-soak" if self.soak_mode else "launch-gate"),
            "source_commit": self.provenance["source_commit"],
            "source_commit_at_report": subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip(),
            "provenance": self.provenance,
            "git_status": subprocess.run(
                ["git", "status", "--short"],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.splitlines(),
            "profile": {
                "stage": self.profile.label,
                "accelerated": self.profile.accelerated,
                "elected_for": self.profile.elected_for,
                "elect_start_before": self.profile.elect_start_before,
                "elect_end_before": self.profile.elect_end_before,
                "stakes_frozen_for": self.profile.stakes_frozen_for,
                "initial_set_valid": self.profile.initial_set_valid,
                "effective_stake": EFFECTIVE_STAKE,
                "stake_message_value": PQ_STAKE_MESSAGE_VALUE if self.pq_election else None,
                "validator_wallet_funding": self.validator_wallet_funding(),
            },
            "experiment": (
                {
                    **asdict(self.experiment),
                    "started_at": self.experiment_started_at,
                    "deadline_at": self.experiment_deadline_at,
                    "settlement_deadline_at": self.settlement_deadline_at,
                    "final_status": self.experiment_final_status,
                    "genesis_faucet_funding_nanotos": (
                        EXPERIMENT_GENESIS_FAUCET_FUNDING
                    ),
                    "readiness_manifest": str(self.readiness_path),
                    "allocation_evidence": str(self.allocation_evidence_path),
                    "election_count": len(self.election_allocations),
                    "recovery_count": len(self.recovery_records),
                }
                if self.experiment is not None
                else None
            ),
            "first_election_id": self.first_election_id,
            "second_election_id": self.second_election_id,
            "initial_config34": (asdict(self.initial_config34) if self.initial_config34 else None),
            "first_config34": (asdict(self.first_config34) if self.first_config34 else None),
            "second_config34": (asdict(self.second_config34) if self.second_config34 else None),
            "rollover_election_id": self.rollover_election_id,
            "rollover_config34": (
                asdict(self.rollover_config34) if self.rollover_config34 else None
            ),
            "first_credits": self.first_credits,
            "second_credits": self.second_credits,
            "wallet_balance_history": self.wallet_balance_history,
            "events": self.events,
            "failures": self.failures,
            "metrics_file": str(self.metrics_path),
            "f01_capture_manifest": self.f01_capture_provenance,
            "x01_capture_manifest": self.x01_capture_provenance,
        }
        self.report_path.write_text(json.dumps(report, indent=2, sort_keys=True))
        print(f"{self.profile.label} report: {self.report_path}", flush=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run a local validator election launch-gate rehearsal or a "
            "parallel application-experiment validator network"
        )
    )
    parser.add_argument(
        "--mode",
        choices=("launch-gate", "experiment", "transfer-soak", "fixture-check", "pq-election", "pq-launch-gate"),
        default="launch-gate",
        help=(
            "launch-gate runs the complete PQ Stage-A/Stage-B rehearsal; "
            "experiment runs stable Stage A for a requested observation window; "
            "transfer-soak runs randomized A/B/C transfers with cross-node 到账 checks; "
            "fixture-check provisions four PQ controllers and pools without claiming an election; "
            "pq-election proves the first PQ election; pq-launch-gate continues through rollover and recovery"
        ),
    )
    parser.add_argument("--soak-duration", type=float, default=600.0,
                        help="transfer-soak: seconds to run the random-transfer loop")
    parser.add_argument("--soak-min-interval", type=float, default=1.0,
                        help="transfer-soak: minimum seconds between transfers")
    parser.add_argument("--soak-max-interval", type=float, default=5.0,
                        help="transfer-soak: maximum seconds between transfers")
    parser.add_argument("--soak-wallet-funding-tos", type=int, default=2000,
                        help="transfer-soak: initial funding per A/B/C wallet, in TOS")
    parser.add_argument(
        "--stage",
        choices=sorted(PROFILES),
        default="a",
        help="'a' for accelerated timing or 'b' for unmodified production timing",
    )
    parser.add_argument(
        "--f01-extended-election-window", action="store_true",
        help="F01 launch-gate Stage A only: elect_start_before=240 instead of 180",
    )
    parser.add_argument(
        "--base-port",
        type=int,
        default=26_000,
        help="first loopback port reserved for the throwaway network",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=REPO / "build",
        help="TOS build directory",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=None,
        help="parent directory for timestamped run artifacts (stage-specific default)",
    )
    parser.add_argument(
        "--sample-interval",
        type=float,
        default=None,
        help="sample interval in seconds (default: Stage A 10, Stage B 60)",
    )
    parser.add_argument(
        "--duration-seconds",
        type=float,
        default=DEFAULT_EXPERIMENT_DURATION,
        help="experiment primary window (default: 10800 / three hours)",
    )
    parser.add_argument(
        "--settlement-tail-seconds",
        type=float,
        default=DEFAULT_SETTLEMENT_TAIL,
        help=("experiment recovery-only tail after the primary window (default: 900)"),
    )
    parser.add_argument(
        "--rpc-host",
        default="127.0.0.1",
        help="experiment JSON-RPC IPv4 loopback bind address",
    )
    parser.add_argument(
        "--rpc-base-port",
        type=int,
        default=DEFAULT_RPC_BASE_PORT,
        help="first of four consecutive experiment JSON-RPC ports",
    )
    parser.add_argument(
        "--enable-consensus-cleanup",
        action="store_true",
        help=(
            "ACCEPTANCE ONLY: arm the gated validator consensus-DB cleanup on every "
            "engine (--enable-validator-consensus-cleanup) so live deletion of obsolete "
            "validator groups runs during this election experiment. Default off."
        ),
    )
    parser.add_argument(
        "--consensus-cleanup-state-ttl",
        type=int,
        default=30,
        help="with --enable-consensus-cleanup: engine --state-ttl (s) so the GC floor advances",
    )
    parser.add_argument(
        "--consensus-cleanup-archive-ttl",
        type=int,
        default=60,
        help="with --enable-consensus-cleanup: engine --archive-ttl (s)",
    )
    parser.add_argument(
        "--measure-live-rejoin",
        action="store_true",
        help=(
            "ACCEPTANCE ONLY (experiment mode): after readiness, restart a non-zero "
            "validator while its peers keep producing and prove it rejoins live consensus. "
            "Default off."
        ),
    )
    parser.add_argument(
        "--live-rejoin-only",
        action="store_true",
        help="with --measure-live-rejoin: exit right after the rejoin check (fast dedicated run)",
    )
    return parser.parse_args(argv)


async def async_main() -> int:
    args = parse_args()
    if args.f01_extended_election_window and args.mode not in ("launch-gate", "pq-launch-gate"):
        raise ValueError("F01 extended election window requires launch-gate mode")
    profile = f01_profile(PROFILES[args.stage], args.f01_extended_election_window)
    if args.mode in ("experiment", "transfer-soak") and not profile.accelerated:
        raise ValueError(f"{args.mode} mode requires the accelerated Stage-A profile")
    experiment = None
    if args.mode in ("experiment", "transfer-soak"):
        # transfer-soak reuses the experiment network (4 loopback JSON-RPC nodes) but runs the
        # transfer loop instead of the election observation window.
        experiment = ExperimentProfile(
            duration_seconds=args.duration_seconds,
            settlement_tail_seconds=args.settlement_tail_seconds,
            rpc_host=args.rpc_host,
            rpc_base_port=args.rpc_base_port,
        )
    output_root = args.output_root
    if output_root is None:
        output_root = (
            REPO / "test/integration/.validator-election-experiment"
            if experiment is not None
            else REPO / f"test/integration/.validator-election-stage-{profile.stage}"
        )
    output_root = output_root.resolve()
    sample_interval = args.sample_interval
    if sample_interval is None:
        sample_interval = 10.0 if profile.accelerated else 60.0
    if sample_interval <= 0:
        raise ValueError("sample interval must be positive")
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_dir = output_root / timestamp
    stage = ValidatorElectionRehearsal(
        run_dir=run_dir,
        base_port=args.base_port,
        build_dir=args.build_dir,
        sample_interval=sample_interval,
        profile=profile,
        experiment=experiment,
        enable_consensus_cleanup=args.enable_consensus_cleanup,
        consensus_cleanup_state_ttl=args.consensus_cleanup_state_ttl,
        consensus_cleanup_archive_ttl=args.consensus_cleanup_archive_ttl,
        measure_live_rejoin=args.measure_live_rejoin,
        live_rejoin_only=args.live_rejoin_only,
        soak_mode=(args.mode == "transfer-soak"),
        soak_duration=args.soak_duration,
        soak_min_interval=args.soak_min_interval,
        soak_max_interval=args.soak_max_interval,
        soak_wallet_funding_tos=args.soak_wallet_funding_tos,
        fixture_only=(args.mode == "fixture-check"),
        pq_election=(args.mode in ("launch-gate", "pq-election", "pq-launch-gate")),
        pq_full=(args.mode in ("launch-gate", "pq-launch-gate")),
    )
    try:
        await stage.execute()
    except Exception:
        import traceback as _tb

        _tb.print_exc()
        return 1
    return stage.completion_exit_code()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(async_main()))
