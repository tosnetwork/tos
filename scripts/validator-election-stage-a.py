#!/usr/bin/env python3
"""Run the accelerated validator-election Stage A rehearsal on a local network.

This is an opt-in, throwaway integration exercise. It preserves the production
candidate's contracts, validator-count rules, stake limits, rewards, and
message paths while shortening only ConfigParam 15 and the genesis validator
set lifetime through NetworkConfig.validator_election_stage_a_profile.

The script starts one DHT node and four validator processes on loopback,
deploys five real masterchain wallets (four validators plus one negative-test
wallet), submits two overlapping target elections and the required rollover
election with the repository's Fift tools, recovers both target rounds, injects
restart/quorum faults, and writes JSONL metrics plus a final JSON report under
test/integration/.validator-election-stage-a.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import re
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
STAGE_A_ELECTED_FOR = 300
STAGE_A_STAKES_FROZEN_FOR = 180
T = TypeVar("T")


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


class StageA:
    def __init__(
        self,
        *,
        run_dir: Path,
        base_port: int,
        build_dir: Path,
        sample_interval: float,
    ):
        self.run_dir = run_dir
        self.network_dir = run_dir / "network"
        self.artifacts_dir = run_dir / "artifacts"
        self.base_port = base_port
        self.install = Install(build_dir, REPO)
        self.sample_interval = sample_interval
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
            REPO / "crypto/smartcont/validator-elect-req.fif",
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
            REPO / "crypto/smartcont/validator-elect-signed.fif",
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
            REPO / "crypto/smartcont/recover-stake.fif",
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
        await self.nodes[index].run(StartOptions(threads=4, verbosity=3))
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
            interval=1,
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
        await self.nodes[3].run(StartOptions(threads=4, verbosity=3))
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
        await self.nodes[2].run(StartOptions(threads=4, verbosity=3))
        await self.nodes[3].run(StartOptions(threads=4, verbosity=3))
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
            + STAGE_A_ELECTED_FOR
            + STAGE_A_STAKES_FROZEN_FOR
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
                interval=2,
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

    async def metrics_monitor(self) -> None:
        self.metrics_path.parent.mkdir(parents=True, exist_ok=True)
        while not self._monitor_stop.is_set():
            sample: dict[str, Any] = {"at": utc_now()}
            try:
                sample["masterchain_seqno"] = await self.masterchain_seqno()
            except Exception as error:
                sample["masterchain_error"] = str(error)
            try:
                config = await self.get_config34()
                sample["config34_since"] = config.utime_since
                sample["config34_until"] = config.utime_until
            except Exception as error:
                sample["config34_error"] = str(error)

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
                    processes.append(
                        {
                            "pid": int(proc_dir.name),
                            "rss_kib": int(status.get("VmRSS", "0 kB").split()[0]),
                            "anon_kib": int(
                                status.get("RssAnon", "0 kB").split()[0]
                            ),
                            "threads": int(status.get("Threads", "0")),
                        }
                    )
                except (FileNotFoundError, PermissionError, ProcessLookupError):
                    continue
            sample["validator_processes"] = processes
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
        self.event(
            "stage_a_start",
            source_commit=subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip(),
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
            network.config.validator_election_stage_a_profile = True

            dht = network.create_dht_node()
            for _ in range(4):
                node = network.create_full_node()
                node.make_initial_validator()
                node.announce_to(dht)
                self.nodes.append(node)

            await dht.run(StartOptions(threads=2, verbosity=3))
            for node in self.nodes:
                await node.run(StartOptions(threads=4, verbosity=3))

            self.lite_config.write_text(self.nodes[0]._liteserver_config.to_json())
            await asyncio.wait_for(network.wait_mc_block(seqno=3), timeout=120)
            self.client = await self.nodes[0].toslib_client()
            self.monitor_task = asyncio.create_task(self.metrics_monitor())

            config15 = await self.lite("time", "getconfig 15 16 17 28 34")
            (self.artifacts_dir / "initial-config.txt").write_text(config15)
            if (
                "validators_elected_for:300" not in config15
                or "elections_start_before:180" not in config15
                or "elections_end_before:60" not in config15
                or "stake_held_for:180" not in config15
            ):
                raise AssertionError("Stage A ConfigParam 15 is not accelerated")
            if "min_validators:4" not in config15:
                raise AssertionError("Stage A changed ConfigParam 16")
            if "value:10000000000000" not in config15:
                raise AssertionError("Stage A changed the 10,000 TOS minimum stake")

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
                timeout=600,
                interval=1,
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
                timeout=240,
                interval=1,
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
                timeout=240,
                interval=1,
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
                "stage_a_passed",
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
            "source_commit": subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip(),
            "git_status": subprocess.run(
                ["git", "status", "--short"],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.splitlines(),
            "profile": {
                "elected_for": STAGE_A_ELECTED_FOR,
                "elect_start_before": 180,
                "elect_end_before": 60,
                "stakes_frozen_for": STAGE_A_STAKES_FROZEN_FOR,
                "initial_set_valid": 600,
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
        print(f"Stage A report: {self.report_path}", flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the local validator election Stage A rehearsal"
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
        default=REPO / "test/integration/.validator-election-stage-a",
        help="parent directory for timestamped run artifacts",
    )
    parser.add_argument(
        "--sample-interval",
        type=float,
        default=10.0,
        help="resource and chain-state sample interval in seconds",
    )
    return parser.parse_args()


async def async_main() -> int:
    args = parse_args()
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.output_root / timestamp
    stage = StageA(
        run_dir=run_dir,
        base_port=args.base_port,
        build_dir=args.build_dir,
        sample_interval=args.sample_interval,
    )
    try:
        await stage.execute()
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(async_main()))
