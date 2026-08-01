#!/usr/bin/env python3
"""Run a validator-election launch-gate rehearsal on a local network.

Stage A is an accelerated, opt-in, throwaway integration exercise. Stage B
uses the unmodified production election periods and initial validator-set
lifetime. Both preserve the production candidate's contracts,
validator-count rules, stake limits, rewards, and message paths.

The script starts one DHT node and four validator processes on loopback,
deploys five real masterchain wallets (four validators plus one negative-test
wallet), submits two overlapping target elections and the required rollover
election with the repository's Fift tools, recovers both target rounds, injects
restart/quorum faults, and writes JSONL metrics plus a final JSON report under
the selected stage's test/integration output directory.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Awaitable, Callable, TypeVar

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "test/tostester/src"))

from contract import WalletV1, WalletV1Blueprint  # noqa: E402
from pytosiq_core import (  # noqa: E402
    Address,
    Builder,
    Cell,
    CurrencyCollection,
    InternalMsgInfo,
    MessageAny,
    WalletMessage,
)
from tostester.install import Install  # noqa: E402
from tostester.key import PUB_ED25519_PREFIX, Key  # noqa: E402
from tostester.network import FullNode, Network, StartOptions  # noqa: E402

NANO = 1_000_000_000
ELECTOR = Address((-1, bytes.fromhex("33" * 32)))
EFFECTIVE_STAKE = 10_000 * NANO
ELECTOR_CONFIRMATION_ALLOWANCE = 1 * NANO
STAKE_MESSAGE_VALUE = EFFECTIVE_STAKE + ELECTOR_CONFIRMATION_ALLOWANCE
VALIDATOR_WALLET_FUNDING = 20_020 * NANO
NEGATIVE_WALLET_FUNDING = 15_000 * NANO
MAX_FACTOR = 1 << 16
MAX_ARCHIVE_FDS = 512
ROCKSDB_CACHE_BYTES = 256 * 1024 * 1024
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


@dataclass
class Config34:
    utime_since: int
    utime_until: int
    total: int
    main: int
    total_weight: int
    public_keys: list[str]
    adnl_ids: list[str]
    raw: str


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def raw_address(address: Address) -> str:
    return f"{address.wc}:{address.hash_part.hex()}"


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


def build_election_body(
    *,
    query_id: int,
    validator_pubkey: bytes,
    election_id: int,
    max_factor: int,
    adnl_id: bytes,
    signature: bytes,
) -> Cell:
    if len(validator_pubkey) != 32 or len(adnl_id) != 32 or len(signature) != 64:
        raise ValueError("invalid validator election field length")
    return (
        Builder()
        .store_uint(0x4E73744B, 32)
        .store_uint(query_id, 64)
        .store_bytes(validator_pubkey)
        .store_uint(election_id, 32)
        .store_uint(max_factor, 32)
        .store_bytes(adnl_id)
        .store_ref(Builder().store_bytes(signature).end_cell())
        .end_cell()
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
    ):
        self.run_dir = run_dir
        self.network_dir = run_dir / "network"
        self.artifacts_dir = run_dir / "artifacts"
        self.base_port = base_port
        self.original_build_dir = build_dir.absolute()
        self.install = Install(self.original_build_dir, REPO)
        self.sample_interval = sample_interval
        self.profile = profile
        self.long_poll_interval = 1.0 if profile.accelerated else 30.0
        self.events: list[dict[str, Any]] = []
        self.failures: list[str] = []
        self.metrics_path = run_dir / "metrics.jsonl"
        self.report_path = run_dir / "report.json"
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

    @staticmethod
    def validator_start_options() -> StartOptions:
        # Keep archive RocksDB/package handles bounded during the multi-day
        # Stage B run. The engine has the same safe default; spelling it out
        # here makes the rehearsal invariant explicit in its provenance.
        return StartOptions(
            args=(
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
            ),
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
                "MALLOC_CONF": (
                    "background_thread:true,dirty_decay_ms:10000,"
                    "muzzy_decay_ms:10000"
                ),
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

    def prepare_artifact_snapshot(self) -> None:
        snapshot_dir = self.run_dir / "artifact-snapshot"
        snapshot_build = snapshot_dir / "build"
        snapshot_source = snapshot_dir / "source"

        binary_paths = [
            "crypto/create-state",
            "utils/generate-random-id",
            "lite-client/lite-client",
            "validator-engine/validator-engine",
            "dht-server/dht-server",
            "validator-engine-console/validator-engine-console",
            "blockchain-explorer/blockchain-explorer",
        ]
        binaries: dict[str, dict[str, Any]] = {}
        for relative in binary_paths:
            source = self.original_build_dir / relative
            target = snapshot_build / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            binaries[relative] = self.file_provenance(target)

        toslib_source = (
            self.original_build_dir / "toslib/libtoslibjson.so"
        ).resolve(strict=True)
        toslib_target = snapshot_build / "toslib/libtoslibjson.so"
        toslib_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(toslib_source, toslib_target)
        binaries["toslib/libtoslibjson.so"] = self.file_provenance(
            toslib_target
        )

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
            "binaries": binaries,
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
                raise RuntimeError(
                    f"lite-client failed ({result.returncode}): {output[-2000:]}"
                )
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
            public_keys=re.findall(r"pubkey:x([0-9A-Fa-f]{64})", output),
            adnl_ids=re.findall(r"adnl_addr:x([0-9A-Fa-f]{64})", output),
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
    ) -> None:
        before = await self.wallet_seqno(wallet)
        await wallet.send(
            internal_message(wallet.address, dest, amount, body),
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
                raise RuntimeError(
                    f"Fift {script.name} failed ({result.returncode}): {output}"
                )
            return output

        return await asyncio.to_thread(run)

    async def election_body(
        self,
        *,
        wallet: WalletV1,
        validator_key: Key,
        election_id: int,
        label: str,
    ) -> Cell:
        request_file = self.artifacts_dir / f"{label}-to-sign.bin"
        body_file = self.artifacts_dir / f"{label}-body.boc"
        await self.run_fift(
            self.install.source_dir
            / "crypto/smartcont/validator-elect-req.fif",
            raw_address(wallet.address),
            str(election_id),
            "1",
            validator_key.id.hex(),
            str(request_file),
        )
        to_sign = request_file.read_bytes()
        signature = validator_key.key.sign(to_sign).signature
        public_key = base64.b64encode(
            PUB_ED25519_PREFIX + validator_key.public_key.key
        ).decode()
        signature_b64 = base64.b64encode(signature).decode()
        await self.run_fift(
            self.install.source_dir
            / "crypto/smartcont/validator-elect-signed.fif",
            raw_address(wallet.address),
            str(election_id),
            "1",
            validator_key.id.hex(),
            public_key,
            signature_b64,
            str(body_file),
        )
        body = Cell.one_from_boc(body_file.read_bytes())
        self.event(
            "election_body_created",
            label=label,
            election_id=election_id,
            wallet=raw_address(wallet.address),
            validator_pubkey=validator_key.public_key.key.hex(),
            adnl=validator_key.id.hex(),
            to_sign_sha256=hashlib.sha256(to_sign).hexdigest(),
            body_hash=body.hash.hex(),
        )
        return body

    async def recovery_body(self, label: str) -> Cell:
        body_file = self.artifacts_dir / f"{label}-recover.boc"
        await self.run_fift(
            self.install.source_dir / "crypto/smartcont/recover-stake.fif",
            str(body_file),
        )
        return Cell.one_from_boc(body_file.read_bytes())

    async def wait_returned_negative_funds(
        self, before: int, *, description: str
    ) -> int:
        assert self.negative_wallet is not None
        # Rejected Elector requests return the inbound value. Allow up to
        # 20 TOS for all local transaction and forwarding fees.
        return await self.retry(
            lambda: self.balance(self.negative_wallet.address),
            timeout=60,
            description=description,
            predicate=lambda value: value >= before - 20 * NANO,
        )

    async def submit_negative_cases(
        self,
        *,
        election_id: int,
        validator_key: Key,
        accepted_stake: int,
    ) -> None:
        assert self.negative_wallet is not None
        wallet = self.negative_wallet
        public_param = "0x" + validator_key.public_key.key.hex()

        before = await self.balance(wallet.address)
        body = await self.election_body(
            wallet=wallet,
            validator_key=validator_key,
            election_id=election_id,
            label=f"negative-under-min-{election_id}",
        )
        await self.send_from_wallet(
            wallet,
            dest=ELECTOR,
            amount=1_001 * NANO,
            body=body,
            label="negative-under-minimum-stake",
        )
        await self.wait_returned_negative_funds(
            before, description="under-minimum stake return"
        )
        if await self.runmethod_int("participates_in", public_param) != accepted_stake:
            raise AssertionError("under-minimum stake changed participant state")

        before = await self.balance(wallet.address)
        body = await self.election_body(
            wallet=wallet,
            validator_key=validator_key,
            election_id=election_id + 1,
            label=f"negative-wrong-election-{election_id}",
        )
        await self.send_from_wallet(
            wallet,
            dest=ELECTOR,
            amount=STAKE_MESSAGE_VALUE,
            body=body,
            label="negative-wrong-election-id",
        )
        await self.wait_returned_negative_funds(
            before, description="wrong-election stake return"
        )
        if await self.runmethod_int("participates_in", public_param) != accepted_stake:
            raise AssertionError("wrong election id changed participant state")

        before = await self.balance(wallet.address)
        invalid_body = build_election_body(
            query_id=int(time.time()),
            validator_pubkey=validator_key.public_key.key,
            election_id=election_id,
            max_factor=MAX_FACTOR,
            adnl_id=validator_key.id,
            signature=bytes(64),
        )
        await self.send_from_wallet(
            wallet,
            dest=ELECTOR,
            amount=STAKE_MESSAGE_VALUE,
            body=invalid_body,
            label="negative-invalid-validator-signature",
        )
        await self.wait_returned_negative_funds(
            before, description="invalid-signature stake return"
        )
        if await self.runmethod_int("participates_in", public_param) != accepted_stake:
            raise AssertionError("invalid signature changed participant state")

        self.event("negative_cases_passed", election_id=election_id)

    async def submit_candidate(
        self,
        index: int,
        election_id: int,
        round_number: int,
    ) -> None:
        node = self.nodes[index]
        wallet = self.wallets[index]
        body = await self.election_body(
            wallet=wallet,
            validator_key=node.validator_key,
            election_id=election_id,
            label=f"round-{round_number}-validator-{index + 1}",
        )
        await self.send_from_wallet(
            wallet,
            dest=ELECTOR,
            amount=STAKE_MESSAGE_VALUE,
            body=body,
            label=f"round-{round_number}-validator-{index + 1}-stake",
        )
        public_param = "0x" + node.validator_key.public_key.key.hex()
        actual = await self.retry(
            lambda: self.runmethod_int("participates_in", public_param),
            timeout=60,
            description=f"validator {index + 1} accepted stake",
            predicate=lambda value: value == EFFECTIVE_STAKE,
        )
        if actual != EFFECTIVE_STAKE:
            raise AssertionError(
                f"validator {index + 1} effective stake {actual}, "
                f"expected {EFFECTIVE_STAKE}"
            )
        self.event(
            "candidate_accepted",
            round=round_number,
            validator=index + 1,
            election_id=election_id,
            effective_stake=actual,
        )

    async def restart_node(self, index: int, reason: str) -> None:
        self.event("node_restart_begin", node=index + 1, reason=reason)
        await self.nodes[index].stop()
        await asyncio.sleep(1)
        await self.nodes[index].run(self.validator_start_options())
        self.event("node_restart_complete", node=index + 1, reason=reason)

    async def wait_until_chain_time(self, timestamp: int, label: str) -> None:
        async def chain_time() -> int:
            output = await self.lite("time")
            match = re.search(r"server time is\s+(\d+)", output)
            if match:
                return int(match.group(1))
            match = re.search(r"created at\s+(\d+)", output)
            if match:
                return int(match.group(1))
            raise RuntimeError("cannot parse chain time")

        reached = await self.retry(
            chain_time,
            timeout=max(120.0, timestamp - time.time() + 120.0),
            interval=self.long_poll_interval,
            description=label,
            predicate=lambda value: value >= timestamp,
        )
        self.event("chain_time_reached", label=label, target=timestamp, actual=reached)

    async def wait_config_activation(
        self, election_id: int, label: str, timeout: float = 180
    ) -> Config34:
        config = await self.retry(
            self.get_config34,
            timeout=timeout,
            interval=1,
            description=f"{label} ConfigParam 34 activation",
            predicate=lambda value: value.utime_since == election_id,
        )
        expected_keys = {
            node.validator_key.public_key.key.hex().upper() for node in self.nodes
        }
        expected_adnl = {node.validator_key.id.hex().upper() for node in self.nodes}
        if config.total != 4 or config.main != 4:
            raise AssertionError(f"{label} elected set is not 4/4: {asdict(config)}")
        if set(value.upper() for value in config.public_keys) != expected_keys:
            raise AssertionError(f"{label} validator public keys do not match")
        if set(value.upper() for value in config.adnl_ids) != expected_adnl:
            raise AssertionError(f"{label} validator ADNL identities do not match")
        self.event(
            "config34_activated",
            label=label,
            utime_since=config.utime_since,
            utime_until=config.utime_until,
            total_weight=config.total_weight,
        )
        return config

    async def verify_three_of_four_liveness(self) -> None:
        before = await self.masterchain_seqno()
        self.event("three_of_four_begin", stopped_node=4, seqno=before)
        await self.nodes[3].stop()
        await asyncio.sleep(15)
        after = await self.masterchain_seqno()
        if after <= before:
            raise AssertionError(f"3-of-4 did not advance: {before} -> {after}")
        await self.nodes[3].run(self.validator_start_options())
        self.event("three_of_four_passed", before=before, after=after)

    async def verify_two_of_four_safe_halt(self) -> None:
        self.event("two_of_four_begin", stopped_nodes=[3, 4])
        await self.nodes[2].stop()
        await self.nodes[3].stop()
        samples: list[int] = []
        for _ in range(8):
            await asyncio.sleep(5)
            samples.append(await self.masterchain_seqno())
        if len(set(samples[-4:])) != 1:
            raise AssertionError(f"2-of-4 did not reach a safe halt: {samples}")
        await self.nodes[2].run(self.validator_start_options())
        await self.nodes[3].run(self.validator_start_options())
        resumed_from = samples[-1]
        resumed_to = await self.retry(
            self.masterchain_seqno,
            timeout=60,
            description="resume after restoring 4-of-4",
            predicate=lambda value: value > resumed_from,
        )
        self.event(
            "two_of_four_safe_halt_passed",
            samples=samples,
            resumed_from=resumed_from,
            resumed_to=resumed_to,
        )

    async def recover_round(self, round_number: int) -> list[int]:
        election_id = (
            self.first_election_id if round_number == 1 else self.second_election_id
        )
        unfreeze_at = (
            election_id
            + self.profile.elected_for
            + self.profile.stakes_frozen_for
        )
        credit_timeout = max(240, unfreeze_at - int(time.time()) + 90)
        credits: list[int] = []
        for index, wallet in enumerate(self.wallets):
            wallet_hash = "0x" + wallet.address.hash_part.hex()
            credit = await self.retry(
                lambda wallet_hash=wallet_hash: self.runmethod_int(
                    "compute_returned_stake", wallet_hash
                ),
                timeout=credit_timeout,
                interval=max(2.0, self.long_poll_interval),
                description=f"round {round_number} validator {index + 1} credit",
                predicate=lambda value: value >= EFFECTIVE_STAKE,
            )
            before = await self.record_balance(
                f"validator-{index + 1}-before-recover-{round_number}", wallet
            )
            body = await self.recovery_body(
                f"round-{round_number}-validator-{index + 1}"
            )
            await self.send_from_wallet(
                wallet,
                dest=ELECTOR,
                amount=1 * NANO,
                body=body,
                label=f"round-{round_number}-validator-{index + 1}-recover",
            )
            await self.retry(
                lambda wallet_hash=wallet_hash: self.runmethod_int(
                    "compute_returned_stake", wallet_hash
                ),
                timeout=60,
                description=f"round {round_number} validator {index + 1} credit removal",
                predicate=lambda value: value == 0,
            )
            after = await self.retry(
                lambda wallet=wallet: self.balance(wallet.address),
                timeout=60,
                description=f"round {round_number} validator {index + 1} balance credit",
                predicate=lambda value, before=before, credit=credit: (
                    value >= before + credit - 2 * NANO
                ),
            )
            credits.append(credit)
            self.event(
                "stake_recovered",
                round=round_number,
                validator=index + 1,
                credit=credit,
                balance_before=before,
                balance_after=after,
            )
        return credits

    async def duplicate_recovery_must_not_pay(self) -> None:
        wallet = self.wallets[0]
        before = await self.balance(wallet.address)
        body = await self.recovery_body("duplicate-recovery")
        await self.send_from_wallet(
            wallet,
            dest=ELECTOR,
            amount=1 * NANO,
            body=body,
            label="duplicate-recovery",
        )
        await asyncio.sleep(3)
        after = await self.balance(wallet.address)
        if after > before + NANO // 10:
            raise AssertionError(
                f"duplicate recovery increased balance: {before} -> {after}"
            )
        self.event(
            "duplicate_recovery_rejected",
            balance_before=before,
            balance_after=after,
        )

    async def early_recovery_must_not_pay(self) -> None:
        wallet = self.wallets[0]
        wallet_hash = "0x" + wallet.address.hash_part.hex()
        if await self.runmethod_int("compute_returned_stake", wallet_hash) != 0:
            raise AssertionError("stake unexpectedly recoverable before unfreeze")
        before = await self.balance(wallet.address)
        body = await self.recovery_body("early-recovery")
        await self.send_from_wallet(
            wallet,
            dest=ELECTOR,
            amount=1 * NANO,
            body=body,
            label="early-recovery",
        )
        await asyncio.sleep(3)
        after = await self.balance(wallet.address)
        if after > before + NANO // 10:
            raise AssertionError("early recovery unexpectedly credited principal")
        self.event(
            "early_recovery_rejected",
            balance_before=before,
            balance_after=after,
        )

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
            sample: dict[str, Any] = {
                "at": datetime.fromtimestamp(sampled_at, UTC).isoformat()
            }
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
                sample["active_election_id"] = await self.runmethod_int(
                    "active_election_id"
                )
            except Exception as error:
                sample["active_election_error"] = str(error)

            processes: list[dict[str, Any]] = []
            network_marker = str(self.network_dir).encode()
            for proc_dir in Path("/proc").iterdir():
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
                            "anon_kib": int(
                                status.get("RssAnon", "0 kB").split()[0]
                            ),
                            "file_kib": int(
                                status.get("RssFile", "0 kB").split()[0]
                            ),
                            "shmem_kib": int(
                                status.get("RssShmem", "0 kB").split()[0]
                            ),
                            "archive_fds": archive_fds,
                            "pss_kib": int(smaps.get("Pss", "0 kB").split()[0]),
                            "private_kib": int(
                                smaps.get("Private_Clean", "0 kB").split()[0]
                            )
                            + int(
                                smaps.get("Private_Dirty", "0 kB").split()[0]
                            ),
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
                await asyncio.wait_for(
                    self._monitor_stop.wait(), timeout=self.sample_interval
                )
            except TimeoutError:
                pass

    async def setup_wallets(self, faucet: WalletV1) -> None:
        for index in range(4):
            blueprint = WalletV1Blueprint(workchain=-1)
            before = await self.wallet_seqno(faucet)
            wallet = await faucet.deploy(
                blueprint,
                CurrencyCollection(tomis=VALIDATOR_WALLET_FUNDING),
                seqno=before,
            )
            await self.wait_wallet_seqno(faucet, before + 1)
            await self.retry(
                lambda wallet=wallet: self.balance(wallet.address),
                timeout=60,
                description=f"validator wallet {index + 1} funding",
                predicate=lambda value: value >= VALIDATOR_WALLET_FUNDING - NANO,
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

    async def execute(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=False)
        self.network_dir.mkdir()
        self.artifacts_dir.mkdir()
        self.prepare_artifact_snapshot()
        self.event(
            f"stage_{self.profile.stage}_start",
            stage=self.profile.label,
            accelerated=self.profile.accelerated,
            source_commit=self.provenance["source_commit"],
            artifact_snapshot=str(self.run_dir / "artifact-snapshot"),
            base_port=self.base_port,
            production_defaults_unchanged=True,
        )

        network = Network(
            self.install,
            self.network_dir,
            base_port=self.base_port,
        )
        self.network = network
        try:
            network.config.shard_validators = 4
            network.config.validator_economics_profile = True
            network.config.validator_election_stage_a_profile = (
                self.profile.accelerated
            )

            dht = network.create_dht_node()
            for _ in range(4):
                node = network.create_full_node()
                node.make_initial_validator()
                node.announce_to(dht)
                self.nodes.append(node)

            await dht.run(StartOptions(threads=2, verbosity=3))
            for node in self.nodes:
                await node.run(self.validator_start_options())

            self.lite_config.write_text(self.nodes[0]._liteserver_config.to_json())
            await asyncio.wait_for(network.wait_mc_block(seqno=3), timeout=120)
            self.client = await self.nodes[0].toslib_client()
            self.monitor_task = asyncio.create_task(self.metrics_monitor())

            config15 = await self.lite("time", "getconfig 15 16 17 28 34")
            (self.artifacts_dir / "initial-config.txt").write_text(config15)
            if (
                f"validators_elected_for:{self.profile.elected_for}" not in config15
                or (
                    f"elections_start_before:{self.profile.elect_start_before}"
                    not in config15
                )
                or (
                    f"elections_end_before:{self.profile.elect_end_before}"
                    not in config15
                )
                or (
                    f"stake_held_for:{self.profile.stakes_frozen_for}"
                    not in config15
                )
            ):
                raise AssertionError(
                    f"{self.profile.label} ConfigParam 15 does not match its profile"
                )
            if "min_validators:4" not in config15:
                raise AssertionError(
                    f"{self.profile.label} changed ConfigParam 16"
                )
            if "value:10000000000000" not in config15:
                raise AssertionError(
                    f"{self.profile.label} changed the 10,000 TOS minimum stake"
                )

            self.initial_config34 = await self.get_config34()
            self.event(
                "network_ready",
                initial_config34=asdict(self.initial_config34),
                masterchain_seqno=await self.masterchain_seqno(),
            )

            faucet = network.zerostate.main_wallet(self.client)
            await self.setup_wallets(faucet)

            self.first_election_id = await self.retry(
                lambda: self.runmethod_int("active_election_id"),
                timeout=max(600, self.profile.initial_set_valid + 300),
                interval=self.long_poll_interval,
                description="first election opening",
                predicate=lambda value: value > 0,
            )
            self.event("first_election_open", election_id=self.first_election_id)

            await self.submit_negative_cases(
                election_id=self.first_election_id,
                validator_key=self.nodes[0].validator_key,
                accepted_stake=0,
            )

            for index in range(3):
                await self.submit_candidate(index, self.first_election_id, 1)
            participant_output = await self.runmethod("participant_list_extended")
            (self.artifacts_dir / "round-1-three-participants.txt").write_text(
                participant_output
            )
            result_numbers = re.search(
                r"result:\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)",
                participant_output,
            )
            if result_numbers is None or int(result_numbers.group(4)) != 3 * EFFECTIVE_STAKE:
                raise AssertionError("three-participant total stake was not 30,000 TOS")
            self.event(
                "below_minimum_total_observed",
                total_stake=3 * EFFECTIVE_STAKE,
                required_total=4 * EFFECTIVE_STAKE,
            )

            await self.restart_node(3, "open first election")
            await self.submit_candidate(3, self.first_election_id, 1)

            assert self.negative_wallet is not None
            duplicate_before = await self.balance(self.negative_wallet.address)
            duplicate_body = await self.election_body(
                wallet=self.negative_wallet,
                validator_key=self.nodes[0].validator_key,
                election_id=self.first_election_id,
                label="negative-duplicate-validator-key",
            )
            await self.send_from_wallet(
                self.negative_wallet,
                dest=ELECTOR,
                amount=STAKE_MESSAGE_VALUE,
                body=duplicate_body,
                label="negative-duplicate-validator-key",
            )
            await self.wait_returned_negative_funds(
                duplicate_before, description="duplicate validator stake return"
            )
            node0_stake = await self.runmethod_int(
                "participates_in",
                "0x" + self.nodes[0].validator_key.public_key.key.hex(),
            )
            if node0_stake != EFFECTIVE_STAKE:
                raise AssertionError("duplicate request changed validator stake")
            self.event("duplicate_validator_key_rejected")

            round1_participants = await self.runmethod("participant_list_extended")
            (self.artifacts_dir / "round-1-participants.txt").write_text(
                round1_participants
            )

            await self.wait_until_chain_time(
                self.first_election_id - 55,
                "first election closed",
            )
            await self.restart_node(
                3, "first election completed before ConfigParam 34 activation"
            )
            self.first_config34 = await self.wait_config_activation(
                self.first_election_id, "first ordinary set"
            )
            await self.verify_three_of_four_liveness()
            await self.early_recovery_must_not_pay()

            self.second_election_id = await self.retry(
                lambda: self.runmethod_int("active_election_id"),
                timeout=max(240, self.profile.elected_for),
                interval=self.long_poll_interval,
                description="second election opening",
                predicate=lambda value: value > self.first_election_id,
            )
            self.event("second_election_open", election_id=self.second_election_id)
            for index in range(4):
                await self.submit_candidate(index, self.second_election_id, 2)
            round2_participants = await self.runmethod("participant_list_extended")
            (self.artifacts_dir / "round-2-participants.txt").write_text(
                round2_participants
            )

            await self.wait_until_chain_time(
                self.second_election_id - 55,
                "second election closed",
            )
            await self.restart_node(
                2, "second election completed before ConfigParam 34 activation"
            )
            self.second_config34 = await self.wait_config_activation(
                self.second_election_id, "second ordinary set"
            )
            await self.restart_node(1, "rewards received before stake recovery")

            self.rollover_election_id = await self.retry(
                lambda: self.runmethod_int("active_election_id"),
                timeout=max(240, self.profile.elected_for),
                interval=self.long_poll_interval,
                description="rollover election opening",
                predicate=lambda value: value > self.second_election_id,
            )
            self.event(
                "rollover_election_open",
                election_id=self.rollover_election_id,
                purpose="retire the second ordinary validator set",
            )

            past_before_first_recovery = await self.runmethod("past_elections")
            (self.artifacts_dir / "past-elections-before-first-recovery.txt").write_text(
                past_before_first_recovery
            )
            self.first_credits = await self.recover_round(1)
            if not all(value > EFFECTIVE_STAKE for value in self.first_credits):
                raise AssertionError(
                    f"first-round validator bonus missing: {self.first_credits}"
                )

            for index in range(4):
                await self.submit_candidate(index, self.rollover_election_id, 3)
            rollover_participants = await self.runmethod(
                "participant_list_extended"
            )
            (self.artifacts_dir / "round-3-rollover-participants.txt").write_text(
                rollover_participants
            )
            await self.wait_until_chain_time(
                self.rollover_election_id - 55,
                "rollover election closed",
            )
            self.rollover_config34 = await self.wait_config_activation(
                self.rollover_election_id, "rollover set"
            )

            past_before_second_recovery = await self.runmethod("past_elections")
            (
                self.artifacts_dir / "past-elections-before-second-recovery.txt"
            ).write_text(past_before_second_recovery)
            self.second_credits = await self.recover_round(2)
            if not all(value > EFFECTIVE_STAKE for value in self.second_credits):
                raise AssertionError(
                    f"second-round validator bonus missing: {self.second_credits}"
                )

            await self.duplicate_recovery_must_not_pay()
            await self.verify_two_of_four_safe_halt()

            final_seqno = await self.masterchain_seqno()
            elector_balance = await self.balance(ELECTOR)
            self.event(
                f"stage_{self.profile.stage}_passed",
                stage=self.profile.label,
                final_masterchain_seqno=final_seqno,
                elector_balance=elector_balance,
                first_credits=self.first_credits,
                second_credits=self.second_credits,
            )
        except Exception as error:
            self.fail(f"{type(error).__name__}: {error}")
            raise
        finally:
            self._monitor_stop.set()
            if self.monitor_task is not None:
                await self.monitor_task
            await network.aclose()
            self.write_report()

    def write_report(self) -> None:
        report = {
            "status": "pass" if not self.failures else "fail",
            "generated_at": utc_now(),
            "run_dir": str(self.run_dir),
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
                "stake_message_value": STAKE_MESSAGE_VALUE,
            },
            "first_election_id": self.first_election_id,
            "second_election_id": self.second_election_id,
            "initial_config34": (
                asdict(self.initial_config34) if self.initial_config34 else None
            ),
            "first_config34": (
                asdict(self.first_config34) if self.first_config34 else None
            ),
            "second_config34": (
                asdict(self.second_config34) if self.second_config34 else None
            ),
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
        }
        self.report_path.write_text(json.dumps(report, indent=2, sort_keys=True))
        print(f"{self.profile.label} report: {self.report_path}", flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a local validator election launch-gate rehearsal"
    )
    parser.add_argument(
        "--stage",
        choices=sorted(PROFILES),
        default="a",
        help="'a' for accelerated timing or 'b' for unmodified production timing",
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
    return parser.parse_args()


async def async_main() -> int:
    args = parse_args()
    profile = PROFILES[args.stage]
    output_root = args.output_root or (
        REPO / f"test/integration/.validator-election-stage-{profile.stage}"
    )
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
    )
    try:
        await stage.execute()
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(async_main()))
