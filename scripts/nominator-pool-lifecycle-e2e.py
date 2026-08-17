#!/usr/bin/env python3
"""Take a nominator pool through one complete staking round on a local network.

Everything else in the tree tests a piece of this: the contract compiles, the
message builders emit the right opcodes, the daemon knows which nudges a pool
needs. None of that answers the only question a depositor cares about, which is
whether money put into a pool comes back out with a share of what it earned.

So this runs the whole path against a real chain and real blocks:

    basechain wallets deposit with a text comment
    the validator posts its own funds and stakes the pooled total
    the Elector accepts the pool as a participant and elects it
    the validator set turns over, and the pool is told each time
    the holding period expires and the stake is recovered
    rewards are split, and a nominator withdraws what they are owed

It also exercises the two refusals that decide whether a pool survives contact
with reality: a queued withdrawal blocks the next stake outright, and the
recover path stays shut until the pool has counted enough validator set
changes. Both are easy to write off as edge cases; both take a pool out of
service permanently when nothing handles them.

The accelerated profile keeps production economics, stake limits, contracts and
message paths and shortens only the election timing, so a full round takes
minutes rather than a day. That makes the run affordable, not the result
weaker: every transition below is a real block.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
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
    StateInit,
    WalletMessage,
)
from tostester.install import Install  # noqa: E402
from tostester.key import PUB_ED25519_PREFIX, Key  # noqa: E402
from tostester.network import FullNode, Network, StartOptions  # noqa: E402

T = TypeVar("T")

NANO = 1_000_000_000
ELECTOR = Address((-1, bytes.fromhex("33" * 32)))

# pool.fc constants.
MIN_TOS_FOR_STORAGE = 10 * NANO
DEPOSIT_PROCESSING_FEE = 1 * NANO
MIN_STAKE_TO_SEND = 500 * NANO

# Pool configuration under test.
VALIDATOR_REWARD_SHARE_BPS = 4000  # 40%
MAX_NOMINATORS = 40
MIN_VALIDATOR_STAKE = 5_000 * NANO
MIN_NOMINATOR_STAKE = 100 * NANO

# The network's minimum stake is 10,000 TOS, which is the whole point: the
# validator cannot reach it alone, and three nominators make up the difference.
NETWORK_MIN_STAKE = 10_000 * NANO
ELECTOR_CONFIRMATION_ALLOWANCE = 1 * NANO
POOL_STAKE_VALUE = NETWORK_MIN_STAKE + ELECTOR_CONFIRMATION_ALLOWANCE
# ConfigParam 40's worst tier is TM$2500 plus a quarter of the stake, so the
# validator has to have posted at least that before pool.fc will stake.
VALIDATOR_OWN_DEPOSIT = 5_100 * NANO
NOMINATOR_DEPOSIT = 2_000 * NANO
NOMINATOR_COUNT = 5

# A validator whose stake is frozen cannot enter the next election, which
# opens before the current round ends, so continuous participation costs two
# stake principals. This is the same arithmetic the economics document uses to
# size a validator's genesis allocation.
DIRECT_VALIDATOR_FUNDING = 20_100 * NANO
POOL_VALIDATOR_FUNDING = 6_000 * NANO
NOMINATOR_FUNDING = NOMINATOR_DEPOSIT + 100 * NANO
# A basechain wallet with no standing in the pool: not the validator, not a
# depositor. It exists to prove that recovering a staked pool and paying its
# depositors out needs nobody's permission.
RESCUER_FUNDING = 50 * NANO
POOL_DEPLOY_VALUE = 20 * NANO

# pool.fc requires at least one TOS of message value to process a stake; the
# rest of what it forwards comes from its own balance.
POOL_STAKE_GAS = 2 * NANO
MAX_FACTOR = 1 << 16
POOL_STATE_IDLE = 0
POOL_STATE_SENT = 1
POOL_STATE_STAKED = 2


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
    init: StateInit | None = None,
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


def text_command(command: str) -> Cell:
    """A nominator's whole interface: a plain transfer with a comment.

    pool.fc reads op 0 followed by one ASCII byte, which is what lets a
    depositor act from any wallet that can attach a comment.
    """
    builder = Builder().store_uint(0, 32)
    for char in command:
        builder.store_uint(ord(char), 8)
    return builder.end_cell()


def pool_message(opcode: int, query_id: int, *, extra: Cell | None = None) -> Cell:
    builder = Builder().store_uint(opcode, 32).store_uint(query_id, 64)
    if extra is not None:
        builder.store_slice(extra.begin_parse())
    return builder.end_cell()


def store_coins(builder: Builder, amount: int) -> Builder:
    length = (amount.bit_length() + 7) // 8
    builder.store_uint(length, 4)
    if length:
        builder.store_uint(amount, length * 8)
    return builder


def build_pool_state_init(
    code: Cell,
    *,
    validator_account: bytes,
    reward_share_bps: int,
    max_nominators: int,
    min_validator_stake: int,
    min_nominator_stake: int,
) -> StateInit:
    """The initial storage pool.fc's save_data expects, in its exact order."""
    config = (
        Builder()
        .store_bytes(validator_account)
        .store_uint(reward_share_bps, 16)
        .store_uint(max_nominators, 16)
    )
    store_coins(config, min_validator_stake)
    store_coins(config, min_nominator_stake)

    data = Builder().store_uint(0, 8).store_uint(0, 16)
    store_coins(data, 0)  # stake_amount_sent
    store_coins(data, 0)  # validator_amount
    data.store_ref(config.end_cell())
    data.store_bit(0)  # nominators
    data.store_bit(0)  # withdraw_requests
    data.store_uint(0, 32)  # stake_at
    data.store_uint(0, 256)  # saved_validator_set_hash
    data.store_uint(0, 8)  # validator_set_changes_count
    data.store_uint(0, 32)  # validator_set_change_time
    data.store_uint(0, 32)  # stake_held_for
    data.store_bit(0)  # config_proposal_votings
    return StateInit(code=code, data=data.end_cell())


def build_pool_stake_body(
    *,
    query_id: int,
    stake_value: int,
    validator_pubkey: bytes,
    election_id: int,
    max_factor: int,
    adnl_id: bytes,
    signature: bytes,
) -> Cell:
    """pool.fc's new_stake body.

    Identical to the Elector's own, with the amount to forward inserted after
    the query id -- the pool needs to be told how much of its balance to stake,
    and everything after that it passes through untouched.
    """
    if len(validator_pubkey) != 32 or len(adnl_id) != 32 or len(signature) != 64:
        raise ValueError("invalid validator election field length")
    builder = Builder().store_uint(0x4E73744B, 32).store_uint(query_id, 64)
    store_coins(builder, stake_value)
    return (
        builder.store_bytes(validator_pubkey)
        .store_uint(election_id, 32)
        .store_uint(max_factor, 32)
        .store_bytes(adnl_id)
        .store_ref(Builder().store_bytes(signature).end_cell())
        .end_cell()
    )


@dataclass
class PoolData:
    state: int
    nominators_count: int
    stake_amount_sent: int
    validator_amount: int
    stake_at: int
    validator_set_changes_count: int

    @property
    def state_name(self) -> str:
        return {0: "idle", 1: "sent", 2: "staked"}.get(self.state, "unknown")


@dataclass
class Nominator:
    index: int
    wallet: WalletV1
    key: Key
    deposited: int = 0


@dataclass
class Report:
    started_at: str = field(default_factory=utc_now)
    events: list[dict[str, Any]] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)


class PoolLifecycle:
    def __init__(self, install: Install, run_dir: Path, base_port: int) -> None:
        self.install = install
        self.run_dir = run_dir
        self.network_dir = run_dir / "network"
        self.artifacts_dir = run_dir / "artifacts"
        self.base_port = base_port
        self.lite_config = run_dir / "lite-client.json"
        self.report = Report()
        self.network: Network | None = None
        self.nodes: list[FullNode] = []
        self.wallets: list[WalletV1] = []
        self.nominators: list[Nominator] = []
        self.client: Any = None
        self.rescuer: WalletV1 | None = None
        # Messages the validator sends once its stake is in. A pool whose
        # depositors depend on the validator staying responsive is a pool that
        # traps them when it stops, so this has to stay at zero through
        # recovery and exit.
        self.validator_sends_after_stake = 0
        self.count_validator_sends = False
        self.pool_address: Address | None = None
        self.pool_code: Cell | None = None
        self.failures: list[str] = []
        self._last_signature: bytes = b""

    # ----- plumbing -------------------------------------------------------

    def event(self, name: str, **details: Any) -> None:
        record = {"at": utc_now(), "event": name, **details}
        self.report.events.append(record)
        print(f"[{record['at']}] {name} {json.dumps(details, default=str)}", flush=True)

    def check(self, name: str, passed: bool, **details: Any) -> bool:
        self.report.checks.append(
            {"at": utc_now(), "check": name, "passed": passed, **details}
        )
        status = "PASS" if passed else "FAIL"
        print(f"  {status}  {name} {json.dumps(details, default=str)}", flush=True)
        if not passed:
            self.failures.append(name)
        return passed

    async def retry(
        self,
        action: Callable[[], Awaitable[T]],
        *,
        timeout: float,
        description: str,
        predicate: Callable[[T], bool],
        interval: float = 2.0,
    ) -> T:
        deadline = time.monotonic() + timeout
        last: Any = None
        while time.monotonic() < deadline:
            try:
                last = await action()
                if predicate(last):
                    return last
            except Exception as error:  # noqa: BLE001 - reported below
                last = error
            await asyncio.sleep(interval)
        raise TimeoutError(f"{description}: gave up after {timeout}s, last={last!r}")

    async def lite(self, *commands: str, timeout: float = 30.0) -> str:
        args = [
            str(self.install.build_dir / "lite-client/lite-client"),
            "-C",
            str(self.lite_config),
            "-v",
            "1",
        ]
        for command in commands:
            args += ["-c", command]

        def run() -> str:
            result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
            return result.stdout + result.stderr

        return await asyncio.to_thread(run)

    async def runmethod(self, address: str, method: str, *params: str) -> str:
        command = " ".join(["runmethod", address, method, *params])
        return await self.lite("time", command)

    async def balance(self, address: Address) -> int:
        assert self.client is not None
        return (await self.client.raw_get_account_state(address)).balance

    @staticmethod
    def _stack_tokens(payload: str) -> list[str]:
        """Split a lite-client result stack into one token per slot.

        Cells and empty tuples render as ``C{...}`` and ``()`` rather than as
        numbers. Dropping them and indexing what is left shifts every field
        after the two dictionaries, which is the kind of mistake that reads a
        duration as a counter and reports success without ever having checked
        anything.
        """
        tokens: list[str] = []
        index = 0
        while index < len(payload):
            char = payload[index]
            if char.isspace():
                index += 1
            elif payload.startswith("C{", index):
                close = payload.index("}", index)
                tokens.append(payload[index : close + 1])
                index = close + 1
            elif char == "(":
                close = payload.index(")", index)
                tokens.append(payload[index : close + 1])
                index = close + 1
            else:
                end = index
                while end < len(payload) and not payload[end].isspace():
                    end += 1
                tokens.append(payload[index:end])
                index = end
        return tokens

    async def pool_data(self) -> PoolData:
        assert self.pool_address is not None
        output = await self.runmethod(raw_address(self.pool_address), "get_pool_data")
        match = re.search(r"^result:\s*\[(.*)\]\s*$", output, re.MULTILINE)
        if match is None:
            raise RuntimeError(f"get_pool_data returned no result:\n{output[-1500:]}")
        tokens = self._stack_tokens(match.group(1))
        if len(tokens) < 16:
            raise RuntimeError(f"unexpected get_pool_data stack: {tokens}")

        def number(index: int) -> int:
            token = tokens[index]
            if not token.lstrip("-").isdigit():
                raise RuntimeError(f"stack slot {index} is not a number: {token}")
            return int(token)

        # Slot order follows pool.fc's save_data; 9 and 10 are the nominator and
        # withdraw-request dictionaries.
        return PoolData(
            state=number(0),
            nominators_count=number(1),
            stake_amount_sent=number(2),
            validator_amount=number(3),
            stake_at=number(11),
            validator_set_changes_count=number(13),
        )

    async def active_election_id(self) -> int:
        output = await self.runmethod(raw_address(ELECTOR), "active_election_id")
        for token in reversed(output.split()):
            if token.lstrip("-").isdigit():
                return int(token)
        return 0

    async def wallet_seqno(self, wallet: WalletV1) -> int:
        return (await wallet.current).seqno

    async def send(
        self,
        wallet: WalletV1,
        *,
        dest: Address,
        amount: int,
        body: Cell,
        label: str,
        init: StateInit | None = None,
    ) -> None:
        before = await self.wallet_seqno(wallet)
        await wallet.send(
            internal_message(wallet.address, dest, amount, body, init=init),
            seqno=before,
        )
        await self.retry(
            lambda: self.wallet_seqno(wallet),
            timeout=60,
            description=f"{label} accepted",
            predicate=lambda value: value > before,
        )
        if self.count_validator_sends and self.wallets and wallet is self.wallets[0]:
            self.validator_sends_after_stake += 1
        self.event("message_sent", label=label, dest=raw_address(dest), amount=amount)

    # ----- phases ---------------------------------------------------------

    async def bring_up_network(self) -> None:
        network = Network(self.install, self.network_dir, base_port=self.base_port)
        self.network = network
        network.config.shard_validators = 4
        network.config.validator_economics_profile = True
        network.config.validator_election_stage_a_profile = True

        dht = network.create_dht_node()
        for _ in range(4):
            node = network.create_full_node()
            node.make_initial_validator()
            node.announce_to(dht)
            self.nodes.append(node)

        # A fifth identity, not in the genesis set. While the pool's stake is
        # frozen its validator cannot enter the next election, and with only
        # four keys that election has three participants -- below both the
        # minimum count and the minimum total stake. It fails, the validator
        # set never rotates, and the pool's recover guard, which counts
        # rotations, stays shut forever with the principal inside. A pool
        # therefore needs the network to keep electing without it, which is the
        # same reason a real operator runs two pools on alternating rounds.
        spare = network.create_full_node()
        spare.announce_to(dht)
        self.nodes.append(spare)

        await dht.run(StartOptions(threads=2, verbosity=3))
        for node in self.nodes:
            await node.run(StartOptions(threads=4, verbosity=3))

        self.lite_config.write_text(self.nodes[0]._liteserver_config.to_json())
        await asyncio.wait_for(network.wait_mc_block(seqno=3), timeout=180)
        self.client = await self.nodes[0].toslib_client()
        self.event("network_ready", validators=len(self.nodes))

    async def fund_wallets(self) -> None:
        assert self.network is not None
        faucet = self.network.zerostate.main_wallet(self.client)

        for index in range(len(self.nodes)):
            funding = (
                POOL_VALIDATOR_FUNDING if index == 0 else DIRECT_VALIDATOR_FUNDING
            )
            before = await self.wallet_seqno(faucet)
            wallet = await faucet.deploy(
                WalletV1Blueprint(workchain=-1),
                CurrencyCollection(tomis=funding),
                seqno=before,
            )
            await self.retry(
                lambda: self.wallet_seqno(faucet),
                timeout=60,
                description=f"validator wallet {index} funded",
                predicate=lambda value, before=before: value > before,
            )
            self.wallets.append(wallet)

        for index in range(NOMINATOR_COUNT):
            before = await self.wallet_seqno(faucet)
            wallet = await faucet.deploy(
                WalletV1Blueprint(workchain=0),
                CurrencyCollection(tomis=NOMINATOR_FUNDING),
                seqno=before,
            )
            await self.retry(
                lambda: self.wallet_seqno(faucet),
                timeout=60,
                description=f"nominator wallet {index} funded",
                predicate=lambda value, before=before: value > before,
            )
            self.nominators.append(
                Nominator(index=index, wallet=wallet, key=wallet.key)
            )

        before = await self.wallet_seqno(faucet)
        self.rescuer = await faucet.deploy(
            WalletV1Blueprint(workchain=0),
            CurrencyCollection(tomis=RESCUER_FUNDING),
            seqno=before,
        )
        await self.retry(
            lambda: self.wallet_seqno(faucet),
            timeout=60,
            description="rescuer wallet funded",
            predicate=lambda value, before=before: value > before,
        )

        self.event(
            "wallets_funded",
            validators=len(self.wallets),
            nominators=len(self.nominators),
            rescuer=raw_address(self.rescuer.address),
        )
        self.check(
            "nominator wallets are in the basechain",
            all(n.wallet.address.wc == 0 for n in self.nominators),
        )

    async def deploy_pool(self) -> None:
        """Deploy the pool from the compiled artifact, at its derived address."""
        build = subprocess.run(
            [str(REPO / "scripts/build-nominator-pool-v1.sh")],
            capture_output=True,
            text=True,
            check=True,
        )
        artifact = None
        for line in build.stdout.splitlines():
            if line.startswith("output="):
                artifact = Path(line.split("=", 1)[1])
        if artifact is None:
            raise RuntimeError("build script did not report an output path")
        self.pool_code = Cell.one_from_boc(artifact.read_bytes())

        validator_wallet = self.wallets[0]
        validator_account = validator_wallet.address.hash_part
        state_init = build_pool_state_init(
            self.pool_code,
            validator_account=validator_account,
            reward_share_bps=VALIDATOR_REWARD_SHARE_BPS,
            max_nominators=MAX_NOMINATORS,
            min_validator_stake=MIN_VALIDATOR_STAKE,
            min_nominator_stake=MIN_NOMINATOR_STAKE,
        )
        self.pool_address = Address((-1, state_init.serialize().hash))

        # pool.fc always reads an opcode, so a bare value transfer would abort
        # and leave the account uninitialized. op 1 is its accept-coins path.
        await self.send(
            validator_wallet,
            dest=self.pool_address,
            amount=POOL_DEPLOY_VALUE,
            body=pool_message(1, int(time.time())),
            label="pool-deploy",
            init=state_init,
        )
        data = await self.retry(
            self.pool_data,
            timeout=90,
            description="pool deployed and answering get-methods",
            predicate=lambda value: value.state == POOL_STATE_IDLE,
        )
        self.event(
            "pool_deployed",
            address=raw_address(self.pool_address),
            code_hash=self.pool_code.hash.hex(),
            state=data.state_name,
        )
        self.check("pool starts idle with no nominators", data.nominators_count == 0)

    async def deposit(self) -> None:
        for nominator in self.nominators:
            assert self.pool_address is not None
            await self.send(
                nominator.wallet,
                dest=self.pool_address,
                amount=NOMINATOR_DEPOSIT,
                body=text_command("d"),
                label=f"nominator-{nominator.index}-deposit",
            )
            nominator.deposited = NOMINATOR_DEPOSIT - DEPOSIT_PROCESSING_FEE

        data = await self.retry(
            self.pool_data,
            timeout=120,
            description="all nominator deposits recorded",
            predicate=lambda value: value.nominators_count == NOMINATOR_COUNT,
        )
        self.check(
            "every depositor is on the pool's ledger",
            data.nominators_count == NOMINATOR_COUNT,
            recorded=data.nominators_count,
        )

        # The validator's own funds go in through the deposit opcode, which is
        # what the punishment guard measures.
        await self.send(
            self.wallets[0],
            dest=self.pool_address,
            amount=VALIDATOR_OWN_DEPOSIT,
            body=pool_message(4, int(time.time())),
            label="validator-own-deposit",
        )
        data = await self.retry(
            self.pool_data,
            timeout=90,
            description="validator's own stake recorded",
            predicate=lambda value: value.validator_amount >= MIN_VALIDATOR_STAKE,
        )
        self.check(
            "validator's own funds cover the minimum it must post",
            data.validator_amount >= MIN_VALIDATOR_STAKE,
            validator_amount=data.validator_amount,
            required=MIN_VALIDATOR_STAKE,
        )

    async def leave_while_idle(self) -> None:
        """Between rounds a nominator can simply walk away.

        pool.fc pays out immediately when the pool is idle, because the money
        is right there. This is the benign case, and it is worth pinning
        because the hostile one below looks identical from the outside.
        """
        assert self.pool_address is not None
        leaver = self.nominators[-1]
        before = await self.balance(leaver.wallet.address)
        await self.send(
            leaver.wallet,
            dest=self.pool_address,
            amount=NANO,
            body=text_command("w"),
            label="idle-withdrawal",
        )
        data = await self.retry(
            self.pool_data,
            timeout=90,
            description="idle withdrawal settles immediately",
            predicate=lambda value: value.nominators_count == len(self.nominators) - 1,
        )
        after = await self.retry(
            lambda: self.balance(leaver.wallet.address),
            timeout=90,
            description="the leaver is paid",
            predicate=lambda value: value > before,
        )
        self.check(
            "leaving between rounds pays out without waiting",
            data.nominators_count == len(self.nominators) - 1 and after > before,
            paid=after - before,
            deposited=leaver.deposited,
        )
        self.nominators = self.nominators[:-1]

    async def queue_withdrawal_while_staked(self) -> None:
        """Asking to leave mid-round leaves a request the pool cannot settle.

        The principal is with the Elector, so the contract can only write the
        request down. What matters is what that request then does to the pool:
        it blocks the next stake outright, and recovery does not clear it.
        """
        assert self.pool_address is not None
        leaver = self.nominators[-1]
        await self.send(
            leaver.wallet,
            dest=self.pool_address,
            amount=NANO,
            body=text_command("w"),
            label="staked-withdrawal-request",
        )
        await asyncio.sleep(8)
        queued = await self.has_withdraw_requests()
        data = await self.pool_data()
        self.check(
            "a mid-round request is recorded rather than paid",
            queued and data.nominators_count == len(self.nominators),
            queued=queued,
            nominators=data.nominators_count,
        )

    async def has_withdraw_requests(self) -> bool:
        assert self.pool_address is not None
        output = await self.runmethod(
            raw_address(self.pool_address), "has_withdraw_requests"
        )
        match = re.search(r"result:\s*\[\s*(-?\d+)", output)
        if match is None:
            raise RuntimeError(f"cannot parse has_withdraw_requests: {output[-800:]}")
        return int(match.group(1)) != 0

    async def stake_must_be_refused(self, election_id: int) -> None:
        """The refusal that takes a pool out of service without saying so."""
        await self.stake_through_pool(election_id, label="stake-blocked-by-queue")
        await asyncio.sleep(12)
        data = await self.pool_data()
        self.check(
            "a queued withdrawal keeps the pool out of the next election",
            data.state == POOL_STATE_IDLE,
            state=data.state_name,
        )

    async def drain_withdraw_queue(self) -> None:
        """What the daemon's maintenance pass does, and why it has to."""
        assert self.pool_address is not None
        leaver = self.nominators[-1]
        before = await self.balance(leaver.wallet.address)
        await self.send(
            self.rescuer,
            dest=self.pool_address,
            amount=NANO // 5,
            body=pool_message(
                2, int(time.time()), extra=Builder().store_uint(8, 8).end_cell()
            ),
            label="process-withdraw-requests",
        )
        data = await self.retry(
            self.pool_data,
            timeout=120,
            description="withdraw queue drained",
            predicate=lambda value: value.nominators_count == len(self.nominators) - 1,
        )
        after = await self.retry(
            lambda: self.balance(leaver.wallet.address),
            timeout=90,
            description="the queued leaver is paid",
            predicate=lambda value: value > before,
        )
        self.check(
            "draining the queue pays the leaver and frees the pool",
            data.nominators_count == len(self.nominators) - 1 and after > before,
            paid=after - before,
        )
        self.nominators = self.nominators[:-1]
        self.check(
            "the queue is empty afterwards",
            not await self.has_withdraw_requests(),
        )

    async def keep_elections_alive(self) -> None:
        """Stake the other validators into every election that opens.

        Without this the network stops rotating the moment the pool sits a
        round out, and everything downstream of a rotation stops with it.
        """
        entered: set[tuple[int, int]] = set()
        while True:
            try:
                election_id = await self.active_election_id()
                if election_id:
                    for index in range(1, len(self.nodes)):
                        if (index, election_id) in entered:
                            continue
                        balance = await self.balance(self.wallets[index].address)
                        if balance < POOL_STAKE_VALUE + NANO:
                            continue
                        await self.stake_directly(index, election_id)
                        entered.add((index, election_id))
            except asyncio.CancelledError:
                raise
            except Exception as error:  # noqa: BLE001 - a missed round is not fatal
                self.event("keep_elections_alive_error", error=repr(error))
            await asyncio.sleep(20)

    async def stake_directly(self, index: int, election_id: int) -> None:
        """The other validators stake the ordinary way.

        Without them the election has one participant and fails, and a pool
        that is never elected earns nothing to distribute -- which would make
        the reward check below vacuous rather than passing.
        """
        wallet = self.wallets[index]
        node = self.nodes[index]
        body = await self.signed_election_body(
            source=wallet.address,
            node=node,
            election_id=election_id,
            label=f"direct-{index}",
        )
        await self.send(
            wallet,
            dest=ELECTOR,
            amount=POOL_STAKE_VALUE,
            body=body,
            label=f"direct-validator-{index}-stake",
        )

    async def signed_election_body(
        self, *, source: Address, node: FullNode, election_id: int, label: str
    ) -> Cell:
        """The Elector checks the signature against whoever sent the stake.

        For a pool that is the pool's address, not the wallet driving it, which
        is the one detail that makes staking through a pool different.
        """
        request = self.artifacts_dir / f"{label}-to-sign.bin"
        body_file = self.artifacts_dir / f"{label}-body.boc"
        await self.run_fift(
            REPO / "crypto/smartcont/validator-elect-req.fif",
            raw_address(source),
            str(election_id),
            "1",
            node.validator_key.id.hex(),
            str(request),
        )
        signature = node.validator_key.key.sign(request.read_bytes()).signature
        await self.run_fift(
            REPO / "crypto/smartcont/validator-elect-signed.fif",
            raw_address(source),
            str(election_id),
            "1",
            node.validator_key.id.hex(),
            base64.b64encode(
                PUB_ED25519_PREFIX + node.validator_key.public_key.key
            ).decode(),
            base64.b64encode(signature).decode(),
            str(body_file),
        )
        self._last_signature = signature
        return Cell.one_from_boc(body_file.read_bytes())

    async def stake_through_pool(self, election_id: int, *, label: str) -> None:
        assert self.pool_address is not None
        node = self.nodes[0]
        await self.signed_election_body(
            source=self.pool_address,
            node=node,
            election_id=election_id,
            label=label,
        )
        signature = self._last_signature

        body = build_pool_stake_body(
            query_id=int(time.time()),
            stake_value=POOL_STAKE_VALUE,
            validator_pubkey=node.validator_key.public_key.key,
            election_id=election_id,
            max_factor=MAX_FACTOR,
            adnl_id=node.validator_key.id,
            signature=signature,
        )
        await self.send(
            self.wallets[0],
            dest=self.pool_address,
            amount=POOL_STAKE_GAS,
            body=body,
            label=label,
        )

    async def nominator_amount(self, nominator: Nominator) -> int:
        assert self.pool_address is not None
        output = await self.runmethod(
            raw_address(self.pool_address),
            "get_nominator_data",
            "0x" + nominator.wallet.address.hash_part.hex(),
        )
        match = re.search(r"result:\s*\[\s*(\d+)\s+(\d+)", output)
        if match is None:
            raise RuntimeError(f"cannot parse get_nominator_data: {output[-800:]}")
        return int(match.group(1)) + int(match.group(2))

    async def announce_validator_set_changes(self, *, target: int) -> None:
        """Tell the pool the validator set moved, until it has counted enough.

        Nothing does this on its own, and until the count is high enough the
        recover path refuses outright -- with every nominator's principal still
        at the Elector. This is the single most consequential thing a keeper
        does for a pool.
        """
        assert self.pool_address is not None
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            data = await self.pool_data()
            if data.validator_set_changes_count >= target:
                self.check(
                    "the pool has counted enough validator set changes to recover",
                    True,
                    counted=data.validator_set_changes_count,
                    required=target,
                )
                return
            # Sent by the rescuer, not the validator. pool.fc puts no sender
            # restriction on this, and that is the whole point: the counter it
            # advances is what unlocks recovery.
            await self.send(
                self.rescuer,
                dest=self.pool_address,
                amount=NANO // 5,
                body=pool_message(6, int(time.time())),
                label="update-validator-set",
            )
            await asyncio.sleep(15)
        self.check(
            "the pool has counted enough validator set changes to recover",
            False,
            counted=(await self.pool_data()).validator_set_changes_count,
            required=target,
        )

    async def recover(self) -> None:
        assert self.pool_address is not None
        before = {n.index: await self.nominator_amount(n) for n in self.nominators}
        staked = (await self.pool_data()).stake_amount_sent

        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            await self.send(
                self.rescuer,
                dest=self.pool_address,
                amount=NANO // 2,
                body=pool_message(0x47657424, int(time.time())),
                label="recover-stake",
            )
            await asyncio.sleep(15)
            if (await self.pool_data()).state == POOL_STATE_IDLE:
                break

        data = await self.pool_data()
        self.check(
            "the stake comes back and the pool goes idle",
            data.state == POOL_STATE_IDLE and data.stake_amount_sent == 0,
            state=data.state_name,
            stake_amount_sent=data.stake_amount_sent,
        )

        after = {n.index: await self.nominator_amount(n) for n in self.nominators}
        grew = [index for index, value in after.items() if value > before[index]]
        self.check(
            "every nominator's principal is at least what it was",
            all(after[index] >= before[index] for index in after),
            before=before,
            after=after,
        )
        self.event(
            "distribution",
            staked=staked,
            rewarded_nominators=grew,
            before=before,
            after=after,
        )

    async def check_solvency(self) -> None:
        """The invariant nothing in the contract enforces.

        pool.fc's ledger says what each nominator is owed; the balance is what
        is actually there. Storage rent moves the second and not the first, so
        the two only stay equal while something is watching them.
        """
        assert self.pool_address is not None
        balance = await self.balance(self.pool_address)
        owed = sum([await self.nominator_amount(n) for n in self.nominators])
        self.check(
            "the pool holds what it owes plus its storage reserve",
            balance >= owed + MIN_TOS_FOR_STORAGE,
            balance=balance,
            owed=owed,
            reserve=MIN_TOS_FOR_STORAGE,
        )

    async def run_fift(self, script: Path, *args: str) -> str:
        command = [str(self.install.fift_exe)]
        for include in self.install.fift_include_dirs:
            command += ["-I", str(include)]
        command += ["-s", str(script), *args]

        def run() -> str:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=60, check=True
            )
            return result.stdout

        return await asyncio.to_thread(run)

    async def execute(self) -> int:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        upkeep: asyncio.Task | None = None
        try:
            await self.bring_up_network()
            await self.fund_wallets()
            await self.deploy_pool()
            await self.deposit()
            await self.leave_while_idle()
            await self.check_solvency()

            # One owner of the other validators' stakes, so nobody enters the
            # same election twice. Each of them holds exactly two principals,
            # and spending both on one round leaves the network unable to elect
            # a successor -- which looks identical to the contract refusing to
            # recover.
            upkeep = asyncio.create_task(self.keep_elections_alive())

            election_id = await self.retry(
                self.active_election_id,
                timeout=900,
                description="an election opens",
                predicate=lambda value: value > 0,
            )
            self.event("election_open", election_id=election_id)
            await self.stake_through_pool(election_id, label="pool-stake")
            data = await self.retry(
                self.pool_data,
                timeout=180,
                description="the Elector accepts the pool's stake",
                predicate=lambda value: value.state == POOL_STATE_STAKED,
            )
            self.check(
                "the pool is a participant in the election",
                data.state == POOL_STATE_STAKED,
                stake_amount_sent=data.stake_amount_sent,
                stake_at=data.stake_at,
            )

            # From here the validator does nothing. Everything that follows --
            # telling the pool the set moved, pulling the stake back from the
            # Elector, settling the withdrawal queue -- is driven by a wallet
            # with no standing in the pool at all.
            self.count_validator_sends = True

            await self.queue_withdrawal_while_staked()
            await self.announce_validator_set_changes(target=2)
            await self.recover()

            self.check(
                "recovering does not settle a queued withdrawal",
                await self.has_withdraw_requests(),
            )

            next_election = await self.retry(
                self.active_election_id,
                timeout=900,
                description="the next election opens",
                predicate=lambda value: value > 0 and value != election_id,
            )
            await self.stake_must_be_refused(next_election)
            await self.drain_withdraw_queue()

            # The property a depositor actually needs when a validator stops
            # answering: their principal came back, and getting it back took
            # nothing from the validator.
            self.check(
                "a staked pool is recovered and paid out without the validator",
                self.validator_sends_after_stake == 0,
                validator_messages_since_staking=self.validator_sends_after_stake,
            )
            self.count_validator_sends = False

            await self.check_solvency()

            # A pool that has lost depositors can fall below the network's
            # minimum stake and lose the ability to participate at all. From
            # outside that is indistinguishable from still being blocked by the
            # queue it just cleared, so name it before staking rather than
            # letting the next wait time out ambiguously.
            pool_balance = await self.balance(self.pool_address)
            self.check(
                "the pool still holds enough to meet the network minimum",
                pool_balance >= POOL_STAKE_VALUE + MIN_TOS_FOR_STORAGE,
                balance=pool_balance,
                required=POOL_STAKE_VALUE + MIN_TOS_FOR_STORAGE,
                nominators_remaining=len(self.nominators),
            )

            # A fresh id rather than the one captured before the queue was
            # drained: draining takes long enough that the earlier election has
            # closed, and the Elector refuses a stake for a finished one --
            # which looks exactly like the pool still being blocked.
            final_election = await self.retry(
                self.active_election_id,
                timeout=900,
                description="an election the pool can still enter",
                predicate=lambda value: value > 0,
            )
            await self.stake_through_pool(final_election, label="pool-stake-after-drain")
            data = await self.retry(
                self.pool_data,
                timeout=180,
                description="the pool can stake again once the queue is clear",
                predicate=lambda value: value.state == POOL_STATE_STAKED,
            )
            self.check(
                "draining the queue lets the pool back into an election",
                data.state == POOL_STATE_STAKED,
                state=data.state_name,
            )
        except Exception as error:  # noqa: BLE001 - recorded in the report
            self.event("aborted", error=repr(error))
            self.failures.append(f"aborted: {error!r}")
        finally:
            if upkeep is not None:
                upkeep.cancel()
            await self.shutdown()

        self.write_report()
        return 1 if self.failures else 0

    async def shutdown(self) -> None:
        for node in self.nodes:
            try:
                await node.stop()
            except Exception:  # noqa: BLE001 - shutdown is best effort
                pass

    def write_report(self) -> None:
        # Everything this run is supposed to establish, whether or not it got
        # there. A release gate reading only the checks that ran cannot tell a
        # leg that passed from one the run never reached, and an aborted run
        # would look like a shorter clean one. Absence has to be visible.
        expected = [
            "the pool holds what it owes plus its storage reserve",
            "every depositor is on the pool's ledger",
            "validator's own funds cover the minimum it must post",
            "leaving between rounds pays out without waiting",
            "the pool is a participant in the election",
            "a mid-round request is recorded rather than paid",
            "the pool has counted enough validator set changes to recover",
            "the stake comes back and the pool goes idle",
            "every nominator's principal is at least what it was",
            "recovering does not settle a queued withdrawal",
            "a queued withdrawal keeps the pool out of the next election",
            "draining the queue pays the leaver and frees the pool",
            "a staked pool is recovered and paid out without the validator",
            "the pool still holds enough to meet the network minimum",
            "draining the queue lets the pool back into an election",
        ]
        observed = {entry["check"] for entry in self.report.checks}
        not_exercised = [name for name in expected if name not in observed]

        report = {
            "started_at": self.report.started_at,
            "finished_at": utc_now(),
            "pool_address": raw_address(self.pool_address) if self.pool_address else None,
            "pool_code_hash": self.pool_code.hash.hex() if self.pool_code else None,
            "checks": self.report.checks,
            "not_exercised": not_exercised,
            "events": self.report.events,
            "failures": self.failures,
            # Complete only when nothing failed and nothing was skipped, so a
            # gate can require this single field instead of restating the list.
            "passed": not self.failures and not not_exercised,
        }
        path = self.run_dir / "report.json"
        path.write_text(json.dumps(report, indent=2, default=str))
        print(f"\nreport: {path}")
        if not_exercised:
            print(f"not exercised ({len(not_exercised)}):")
            for name in not_exercised:
                print(f"  - {name}")
        if report["passed"]:
            print("result: PASS")
        else:
            reasons = []
            if self.failures:
                reasons.append(f"{len(self.failures)} failed")
            if not_exercised:
                reasons.append(f"{len(not_exercised)} not exercised")
            print("result: FAIL (" + ", ".join(reasons) + ")")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build-dir", type=Path, default=REPO / "build", help="built binaries"
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=REPO / "test/integration/.nominator-pool-lifecycle",
        help="where the network, artifacts and report are written",
    )
    parser.add_argument("--base-port", type=int, default=21000)
    return parser.parse_args()


async def async_main() -> int:
    args = parse_args()
    install = Install(args.build_dir, REPO)
    run_dir = args.run_dir / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return await PoolLifecycle(install, run_dir, args.base_port).execute()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(async_main()))
