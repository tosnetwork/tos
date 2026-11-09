"""Remote mode for the shard bench: one bounded hop burst against existing JSON-RPC endpoints.

``run_shard_bench.py --remote`` lands here before any liteserver or local-net
module is imported, so nothing on this path opens a liteserver connection or
boots a node. Every read and send goes through ``rpc.PacedRpc`` inside
``--rpc-share`` of each node's per-source budget.

A run:

1. checks the burst caps and computes an upper bound on the burst's work
   (messages and transactions) and on what it can cost the bench wallet,
   prints the bound, and refuses to go on when it exceeds ``--max-messages``
   or ``--max-cost``. Nothing is read or sent before this step;
2. funds the hop accounts from the supplied bench wallet (a self-pay Quantum
   wallet whose ML-DSA-44 seed is read from ``--key-file``) in one
   deployment tree, and checks the wallet's own fee against its cap;
3. opens the window at an empty outbound queue, sends the start message, waits
   past the deadline and closes the window at an empty queue;
4. counts by an RPC chain walk (``t2collect``), and records the value left in
   the hop accounts, which nothing can withdraw.

How the work bound holds: ``hop.fc`` decrements ``remaining`` on every hop
and ends the chain when it reaches 0, forks only while ``forks`` is positive
and decrements it on every fork, and sends hop messages without bounce. The
start message carries ``remaining`` (``--hops``) and ``forks``, and
``chains`` is a uint8, so the contract itself stops every chain at the cap;
running out of value or passing the deadline only ends chains sooner.
"""

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import os
import stat
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from contract.pq_auth import transfer_message
from pqbench.workload import (
    PUBLIC_KEY_BYTES,
    QSP_PRIMARY_CONTEXT,
    SIGNATURE_BYTES,
    QuantumWallet,
    primary_nonce,
)
from pytosiq_core import Address, Cell, ExternalMsgInfo, MessageAny

from shard import hopbench, t2collect
from shard.rpc import PacedRpc

NANO = 1_000_000_000
MAX_CHAINS = hopbench.MAX_CHAINS
MAX_FORKS = 12
MAX_HOPS = 1_000_000
MAX_ACCOUNTS = 65_536
# A self-pay request is valid for at most an hour after the chain's now().
REQUEST_LIFETIME = 600
# The wallet sends two externals: the deployment and the start.
WALLET_EXTERNALS = 2
REFUSED = 3
log = logging.getLogger("shard-bench-remote")


# ─── caps and the work bound ─────────────────────────────────────────


@dataclass(frozen=True)
class Caps:
    chains: int
    forks: int
    hops: int
    accounts: int
    account_funding: int  # nanotos kept by every hop account
    load_funding: int  # nanotos attached to the start message
    wallet_fee_cap: int  # nanotos one wallet external may cost in fees


def _int_in(name: str, value: object, lo: int, hi: int) -> int:
    if type(value) is not int or not lo <= value <= hi:
        raise ValueError(f"{name} must be an integer in [{lo}, {hi}]")
    return value


def validate_caps(caps: Caps) -> Caps:
    """Refuse any cap outside the range the bound and the contract support."""
    _int_in("chains", caps.chains, 1, MAX_CHAINS)
    _int_in("forks", caps.forks, 0, MAX_FORKS)
    _int_in("hops", caps.hops, 1, MAX_HOPS)
    _int_in("accounts", caps.accounts, 2, MAX_ACCOUNTS)
    for name in ("account_funding", "load_funding", "wallet_fee_cap"):
        _int_in(name, getattr(caps, name), 1, (1 << 120) - 1)
    return caps


def hop_transactions(remaining: int, forks: int) -> int:
    """Transactions a hop message with ``remaining`` and ``forks`` causes, itself included.

    hop.fc: with remaining 0 the receiver ends the chain (one transaction);
    otherwise it sends two hops with (remaining - 1, forks - 1) while forks
    is positive and one hop with (remaining - 1, 0) after that.
    """
    _int_in("remaining", remaining, 0, (1 << 32) - 1)
    _int_in("forks", forks, 0, 255)
    if forks >= remaining:
        return (1 << (remaining + 1)) - 1
    return (1 << forks) - 1 + (1 << forks) * (remaining - forks + 1)


@dataclass(frozen=True)
class Bound:
    deploy_messages: int
    deploy_transactions: int
    burst_messages: int
    burst_transactions: int
    messages: int
    transactions: int
    attached_value: int
    wallet_fees: int
    cost: int

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = asdict(self)
        out["cost_tos"] = self.cost / NANO
        return out


def work_bound(caps: Caps) -> Bound:
    """An upper bound on the run's messages, transactions and cost to the bench wallet.

    Deployment: one external, one message from the wallet to copy 0 and one
    message into every other copy, each executed once. Burst: one external,
    the start message, and ``chains`` hop trees of ``hop_transactions(hops,
    forks)`` transactions, each executing one inbound message. Cost: the
    value the wallet attaches (account funding and load funding; every
    hop's fee comes out of that value) plus the wallet's own fees, capped
    per external.
    """
    validate_caps(caps)
    tree = hop_transactions(caps.hops, caps.forks)
    deploy_messages = caps.accounts
    deploy_transactions = 1 + caps.accounts
    burst_messages = 1 + caps.chains * tree
    burst_transactions = 2 + caps.chains * tree
    attached = caps.accounts * caps.account_funding + caps.load_funding
    fees = WALLET_EXTERNALS * caps.wallet_fee_cap
    return Bound(
        deploy_messages,
        deploy_transactions,
        burst_messages,
        burst_transactions,
        deploy_messages + burst_messages,
        deploy_transactions + burst_transactions,
        attached,
        fees,
        attached + fees,
    )


def refusal(bound: Bound, max_messages: int, max_cost: int) -> str | None:
    """Why the bound is over a limit, or None when it is inside both."""
    _int_in("max messages", max_messages, 1, 1 << 64)
    _int_in("max cost", max_cost, 1, 1 << 120)
    reasons = []
    if bound.messages > max_messages:
        reasons.append(f"message bound {bound.messages} exceeds --max-messages {max_messages}")
    if bound.cost > max_cost:
        reasons.append(f"cost bound {bound.cost} nanotos exceeds --max-cost {max_cost}")
    return "; ".join(reasons) or None


# ─── the bench wallet key ────────────────────────────────────────────


class Secret:
    """Key bytes that never render: repr and str hide them."""

    __slots__ = ("_value",)

    def __init__(self, value: bytes):
        self._value = value

    def reveal(self) -> bytes:
        return self._value

    def __repr__(self) -> str:
        return "Secret(<redacted>)"

    __str__ = __repr__


@dataclass(frozen=True)
class WalletKey:
    seed: Secret
    rescue_public_key: bytes
    wallet_id: int


def load_key(path: Path) -> WalletKey:
    """The bench wallet key file: JSON with ``mldsa44_seed`` and ``rescue_public_key`` (hex).

    The file must be readable by its owner only. Errors name the field, never its value.
    """
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError(f"{path}: the key file must not be readable by group or others")
    try:
        document = json.loads(path.read_text())
    except ValueError as error:
        raise ValueError(f"{path}: the key file is not JSON") from error
    if not isinstance(document, dict):
        raise ValueError(f"{path}: the key file is not a JSON object")
    fields: dict[str, bytes] = {}
    for name in ("mldsa44_seed", "rescue_public_key"):
        value = document.get(name)
        try:
            raw = bytes.fromhex(value) if isinstance(value, str) else b""
        except ValueError:
            raw = b""
        if len(raw) != 32:
            raise ValueError(f"{path}: {name} must be 32 bytes of hex")
        fields[name] = raw
    wallet_id = document.get("wallet_id", 0)
    if type(wallet_id) is not int or not 0 <= wallet_id < (1 << 32):
        raise ValueError(f"{path}: wallet_id must fit uint32")
    return WalletKey(Secret(fields["mldsa44_seed"]), fields["rescue_public_key"], wallet_id)


class Signer:
    """ML-DSA-44 through the bench signer executable; the seed goes over stdin only."""

    def __init__(self, executable: Path, key: WalletKey):
        if not executable.is_file():
            raise FileNotFoundError(f"bench signer not found: {executable}")
        self.executable, self.key = executable.resolve(), key

    def _run(self, args: list[str], line: str, size: int) -> bytes:
        result = subprocess.run(
            [str(self.executable), *args, "--threads", "1"],
            input=line + "\n",
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            # The signer's stderr could echo its input; report only the exit status.
            raise RuntimeError(f"bench signer failed with exit status {result.returncode}")
        lines = result.stdout.splitlines()
        try:
            out = bytes.fromhex(lines[0]) if len(lines) == 1 else b""
        except ValueError:
            out = b""
        if len(out) != size:
            raise RuntimeError("bench signer returned a malformed answer")
        return out

    def public_key(self) -> bytes:
        return self._run(["public"], self.key.seed.reveal().hex(), PUBLIC_KEY_BYTES)

    def sign(self, message: bytes) -> bytes:
        line = f"{self.key.seed.reveal().hex()} {message.hex()}"
        return self._run(["sign", QSP_PRIMARY_CONTEXT.hex()], line, SIGNATURE_BYTES)


# ─── chain reads and sends over JSON-RPC ─────────────────────────────


def raw(address: Address) -> str:
    return f"{address.wc}:{address.hash_part.hex()}"


class Remote:
    def __init__(self, rpcs: list[PacedRpc], poll: float):
        if not rpcs:
            raise ValueError("remote mode needs at least one --rpc endpoint")
        self.rpcs, self.rpc, self.poll = rpcs, rpcs[0], poll

    async def mc_header(self) -> dict[str, Any]:
        info = await self.rpc.call("getMasterchainInfo")
        last = t2collect.parse_block_id(info.get("last"))
        return await self.rpc.call(
            "getBlockHeader",
            {"workchain": -1, "shard": str(t2collect.MASTERCHAIN_SHARD), "seqno": last.seqno},
        )

    async def now(self) -> int:
        return int((await self.mc_header())["gen_utime"])

    async def account(self, address: Address) -> dict[str, Any]:
        answer = await self.rpc.call("getAddressInformation", {"address": raw(address)})
        if not isinstance(answer, dict):
            raise ValueError("an account state answer is not an object")
        return answer

    async def balance(self, address: Address) -> int:
        return int((await self.account(address)).get("balance", 0))

    async def balances(self, addresses: list[Address], parallel: int = 8) -> dict[str, int]:
        out: dict[str, int] = {}
        for i in range(0, len(addresses), parallel):
            chunk = addresses[i : i + parallel]
            for address, value in zip(
                chunk, await asyncio.gather(*(self.balance(x) for x in chunk))
            ):
                out[raw(address)] = value
        return out

    async def wait_active(self, addresses: list[Address], timeout: float) -> list[Address]:
        """The accounts still not active when ``timeout`` runs out (empty when all are)."""
        pending = list(addresses)
        deadline = time.monotonic() + timeout
        while pending:
            states = [await self.account(x) for x in pending]
            pending = [x for x, s in zip(pending, states) if s.get("state") != "active"]
            if not pending or time.monotonic() >= deadline:
                break
            log.info(
                "deployment: %d of %d hop accounts not active yet", len(pending), len(addresses)
            )
            await asyncio.sleep(self.poll)
        return pending

    async def send(self, message: MessageAny) -> None:
        boc = base64.b64encode(message.serialize().to_boc()).decode()
        await self.rpc.call("sendBoc", {"boc": boc})


def bench_wallet(
    code: Cell, global_id: int, auth: bytes, key: WalletKey, public_key: bytes
) -> QuantumWallet:
    """The self-pay Quantum wallet of the key; it holds no seed (the signer does)."""
    return QuantumWallet.derive(
        code,
        global_id,
        auth,
        bytes(32),  # only used to derive a RESCUE key, and the key file supplies one
        "bench",
        key.wallet_id,
        public_key,
        b"",
        rescue=key.rescue_public_key,
    )


class BenchWallet:
    def __init__(self, wallet: QuantumWallet, signer: Signer, remote: Remote):
        self.wallet, self.signer, self.remote = wallet, signer, remote

    @property
    def address(self) -> Address:
        return self.wallet.address

    async def state(self) -> tuple[int, int | None]:
        """(balance, PRIMARY nonce); the nonce is None while the wallet is not deployed."""
        answer = await self.remote.account(self.address)
        balance = int(answer.get("balance", 0))
        if answer.get("state") != "active":
            return balance, None
        data = answer.get("data")
        if not isinstance(data, str) or not data:
            raise ValueError("the bench wallet is active but has no data")
        return balance, primary_nonce(Cell.one_from_boc(base64.b64decode(data)))

    async def send(self, actions: list[MessageAny], what: str, timeout: float) -> int:
        """Send one signed request; wait until its nonce is consumed. Returns the balance spent."""
        balance, nonce = await self.state()
        deployed = nonce is not None
        request = self.wallet.request(
            nonce or 0, actions, await self.remote.now() + REQUEST_LIFETIME
        )
        external = self.wallet.external(request, self.signer.sign(request.hash))
        if not deployed:
            # The first request also deploys the wallet from its funded address.
            external = MessageAny(
                info=ExternalMsgInfo(None, self.address, 0),
                init=self.wallet.state_init,
                body=external.body,
            )
        await self.remote.send(external)
        deadline = time.monotonic() + timeout
        while True:
            after, now_nonce = await self.state()
            if now_nonce is not None and now_nonce > (nonce or 0):
                return balance - after
            if time.monotonic() >= deadline:
                raise RuntimeError(f"the bench wallet never executed the {what} request")
            await asyncio.sleep(self.remote.poll)


def window_counts(result: dict[str, Any]) -> dict[str, Any]:
    stats = result["conservation"]["stats"]
    return {
        "window_transactions": stats["window_transactions"],
        "run_owned_messages": stats["run_owned_emitted"],
        "delivered": stats["delivered"],
        "window_blocks": result["continuity"]["stats"]["window_blocks"],
    }


# ─── the run ─────────────────────────────────────────────────────────


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="run_shard_bench.py --remote",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--remote", action="store_true", required=True)
    p.add_argument("--rpc", action="append", required=True, help="JSON-RPC URL (repeatable)")
    p.add_argument("--rpc-share", type=float, default=0.25, help="share of the per-IP budget")
    p.add_argument("--out", type=Path, required=True, help="new directory for all outputs")
    p.add_argument(
        "--key-file", type=Path, required=True, help="bench wallet key (JSON, mode 0600)"
    )
    p.add_argument("--signer", type=Path, required=True, help="bench-pq-signer executable")
    p.add_argument("--auth-tag", required=True, help="the network's 32-byte AUTH tag (hex)")
    p.add_argument("--build", type=Path, default=hopbench.ROOT / "build")
    p.add_argument("--hop-code", type=Path, help="precompiled hop.fc BOC instead of --build")
    p.add_argument("--wallet-code", type=Path, help="precompiled wallet BOC instead of --build")
    p.add_argument("--accounts", type=int, required=True)
    p.add_argument("--chains", type=int, required=True)
    p.add_argument("--forks", type=int, required=True)
    p.add_argument("--hops", type=int, required=True, help="hop cap of every chain")
    p.add_argument("--local", type=float, default=0.0)
    p.add_argument("--account-funding", type=float, required=True, help="TOS per hop account")
    p.add_argument("--load-funding", type=float, required=True, help="TOS attached to the burst")
    p.add_argument("--wallet-fee-cap", type=float, default=1.0, help="TOS per wallet external")
    p.add_argument("--max-cost", type=float, required=True, help="TOS the run may cost at most")
    p.add_argument("--max-messages", type=int, required=True)
    p.add_argument("--duration", type=int, default=60, help="seconds the chains may run")
    p.add_argument("--with-init", action="store_true")
    p.add_argument("--verify-sender", action="store_true")
    p.add_argument("--payload", type=int, default=0)
    p.add_argument("--seed", default="tos-shard-bench-remote", help="public run seed")
    p.add_argument("--deploy-wait", type=float, default=900)
    p.add_argument("--drain-wait", type=float, default=900)
    p.add_argument("--poll", type=float, default=2.0)
    a = p.parse_args(argv)
    if not 0 < a.rpc_share <= 1:
        p.error("--rpc-share must be in (0, 1]")
    if a.duration < 1:
        p.error("--duration must be positive")
    try:
        a.auth = bytes.fromhex(a.auth_tag)
    except ValueError:
        p.error("--auth-tag must be hex")
    if len(a.auth) != 32:
        p.error("--auth-tag must be 32 bytes")
    return a


def nano(value: float) -> int:
    return round(value * NANO)


def caps_of(a: argparse.Namespace) -> Caps:
    return Caps(
        a.chains,
        a.forks,
        a.hops,
        a.accounts,
        nano(a.account_funding),
        nano(a.load_funding),
        nano(a.wallet_fee_cap),
    )


def load_code(path: Path | None, build: Path, compile_to: Path, which: str) -> Cell:
    if path is not None:
        return Cell.one_from_boc(path.read_bytes())
    if which == "hop":
        return hopbench.build(build, compile_to)
    from pqbench import contracts

    return contracts.build(build, compile_to)["quantum"]


async def run(a: argparse.Namespace) -> int:
    try:
        caps = validate_caps(caps_of(a))
    except ValueError as error:
        print(f"refused: {error}", file=sys.stderr)
        return REFUSED
    bound = work_bound(caps)
    print(json.dumps({"work_bound": bound.as_dict(), "caps": asdict(caps)}, indent=2), flush=True)
    why = refusal(bound, a.max_messages, nano(a.max_cost))
    if why is not None:
        print(f"refused: {why}", file=sys.stderr)
        return REFUSED

    a.out = a.out.resolve()
    a.out.mkdir(parents=True, exist_ok=False)
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s][%(asctime)s][%(name)s] %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(a.out / "bench.log")],
        force=True,
    )
    key = load_key(a.key_file)
    signer = Signer(a.signer, key)
    hop_code = load_code(a.hop_code, a.build, a.out / "contracts", "hop")
    wallet_code = load_code(a.wallet_code, a.build, a.out / "contracts", "wallet")
    rpcs = [PacedRpc(url, a.rpc_share) for url in a.rpc]
    remote = Remote(rpcs, a.poll)

    header = await remote.mc_header()
    global_id = int(header["global_id"])
    cp12 = await remote.rpc.call("getConfigParam", {"param": 12})
    wallet = bench_wallet(wallet_code, global_id, a.auth, key, signer.public_key())
    bench = BenchWallet(wallet, signer, remote)
    log.info("bench wallet %s on global id %d", raw(wallet.address), global_id)
    balance, _ = await bench.state()
    if balance < bound.cost:
        log.error("the bench wallet holds %d nanotos; the run may cost %d", balance, bound.cost)
        return REFUSED

    seed = hashlib.sha256(a.seed.encode()).digest()
    family = hopbench.HopFamily(hop_code, int.from_bytes(seed[:8], "big"), caps.accounts)
    addresses = family.addresses()
    deploy_value = caps.accounts * caps.account_funding
    spent_deploy = await bench.send(
        [
            transfer_message(
                wallet.address,
                addresses[0],
                deploy_value,
                body=hopbench.deploy_body(0, caps.accounts),
                init=family.state_init(0),
            )
        ],
        "deployment",
        a.deploy_wait,
    )
    deploy_fee = spent_deploy - deploy_value
    record: dict[str, Any] = {
        "scope": "REMOTE: bounded hop burst over JSON-RPC",
        "source_commit": source_commit(),
        "endpoints": a.rpc,
        "global_id": global_id,
        "config_param_12": cp12,
        "caps": asdict(caps),
        "work_bound": bound.as_dict(),
        "bench_wallet": raw(wallet.address),
        "hop_code_hash": hop_code.hash.hex(),
        "deployment_wallet_fee": deploy_fee,
    }
    out_record = a.out / "results.json"
    if deploy_fee > caps.wallet_fee_cap:
        record["stopped"] = "the deployment's wallet fee exceeded --wallet-fee-cap"
        out_record.write_text(json.dumps(record, indent=2) + "\n")
        log.error("%s: %d > %d", record["stopped"], deploy_fee, caps.wallet_fee_cap)
        return REFUSED
    missing = await remote.wait_active(addresses, a.deploy_wait)
    if missing:
        record["stopped"] = f"{len(missing)} hop accounts never became active"
        out_record.write_text(json.dumps(record, indent=2) + "\n")
        log.error(record["stopped"])
        return REFUSED
    before = await remote.balances(addresses)

    opening = await t2collect.wait_empty_queue(remote.rpc, a.drain_wait, a.poll)
    log.info("opening boundary: %s", opening)
    deadline = await remote.now() + a.duration
    flags = (hopbench.FLAG_WITH_INIT if a.with_init else 0) | (
        hopbench.FLAG_VERIFY_SENDER if a.verify_sender else 0
    )
    spent_start = await bench.send(
        [
            transfer_message(
                wallet.address,
                addresses[0],
                caps.load_funding,
                body=hopbench.start_body(
                    caps.chains,
                    caps.hops,
                    caps.forks,
                    hopbench.local_scaled(a.local),
                    0,
                    deadline,
                    caps.accounts,
                    flags,
                    hopbench.payload_cell(a.payload),
                ),
            )
        ],
        "start",
        a.drain_wait,
    )
    while await remote.now() <= deadline + 5:
        await asyncio.sleep(a.poll)
    closing = await t2collect.wait_empty_queue(remote.rpc, a.drain_wait, a.poll)
    log.info("closing boundary: %s", closing)
    result = await t2collect.check_window(
        remote.rpc,
        opening,
        closing,
        {raw(x) for x in addresses},
        {raw(wallet.address)},
        a.out / "t2",
        finality=rpcs,
    )
    after = await remote.balances(addresses)
    wallet_after, _ = await bench.state()
    record |= {
        "start_wallet_fee": spent_start - caps.load_funding,
        "deadline": deadline,
        "boundaries": {"opening": asdict(opening), "closing": asdict(closing)},
        "counts": window_counts(result),
        "t2_status": result["status"],
        "finalized_mc": result["finalized_mc"],
        "stranded": {
            "hop_accounts_total": sum(after.values()),
            "burst_left_in_hop_accounts": sum(after.values()) - sum(before.values()),
            "account_funding_total": deploy_value,
            "recoverable": 0,
        },
        "wallet_balance": {
            "before": balance,
            "after": wallet_after,
            "spent": balance - wallet_after,
        },
        "rpc": [r.stats() for r in rpcs],
    }
    out_record.write_text(json.dumps(record, indent=2) + "\n")
    log.info(
        "T2 %s; stranded %d nanotos", result["status"], record["stranded"]["hop_accounts_total"]
    )
    return 0


def source_commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=hopbench.ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main(argv: list[str]) -> int:
    os.umask(0o077)
    return asyncio.run(run(parse_args(argv)))
