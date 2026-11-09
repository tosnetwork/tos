"""Shard bench remote mode: burst caps, the work bound, the key, and the JSON-RPC-only path.

Run: uv run python bench/tests/test_remote.py

The end-to-end test runs ``run_shard_bench.py --remote`` in a child process
against a fake JSON-RPC node served over loopback HTTP, with liteserver and
local-net modules made unimportable, a fake signer, and a key made of test
material only.
"""

import asyncio
import hashlib
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "bench"), str(ROOT / "test/tostester/src")]

import base64  # noqa: E402

from pytosiq_core import Builder, Cell, HashMap  # noqa: E402
from shard import remote  # noqa: E402

NANO = remote.NANO


def caps(**kw: int) -> remote.Caps:
    base = dict(
        chains=4,
        forks=2,
        hops=10,
        accounts=8,
        account_funding=NANO,
        load_funding=10 * NANO,
    )
    base.update(kw)
    return remote.Caps(**base)


# ─── an exact count by simulating hop.fc's recv_internal ────────────


def simulate(
    chains: int, remaining: int, forks: int, max_depth: int | None = None
) -> dict[str, int]:
    """Messages and transactions of one burst, hop by hop as hop.fc executes them.

    ``max_depth`` ends every lineage after that many hops, as a deadline or
    exhausted value would.
    """
    transactions = 2  # the wallet's external and the start message
    messages = 1  # the start message
    queue = [(remaining, forks, 0)] * chains
    messages += chains
    while queue:
        r, f, depth = queue.pop()
        transactions += 1
        if r == 0 or (max_depth is not None and depth >= max_depth):
            continue
        r -= 1
        children = [(r, f - 1, depth + 1)] * 2 if f > 0 else [(r, 0, depth + 1)]
        messages += len(children)
        queue.extend(children)
    return {"messages": messages, "transactions": transactions}


class Bound(unittest.TestCase):
    def test_tree_size_matches_the_contract_exactly(self):
        for r in range(0, 13):
            for f in range(0, 15):
                exact = simulate(1, r, f)["transactions"] - 2
                self.assertEqual(remote.hop_transactions(r, f), exact, (r, f))

    def test_burst_bound_is_exact_without_cuts_and_an_upper_bound_with_them(self):
        for c in (caps(), caps(chains=7, forks=0, hops=30), caps(chains=1, forks=12, hops=5)):
            bound = remote.work_bound(c)
            exact = simulate(c.chains, c.hops, c.forks)
            self.assertEqual(bound.burst_messages, exact["messages"])
            self.assertEqual(bound.burst_transactions, exact["transactions"])
            for depth in range(0, c.hops + 2):
                cut = simulate(c.chains, c.hops, c.forks, max_depth=depth)
                self.assertLessEqual(cut["messages"], bound.burst_messages)
                self.assertLessEqual(cut["transactions"], bound.burst_transactions)

    def test_bound_totals_and_cost(self):
        c = caps()
        b = remote.work_bound(c, 12345)
        self.assertEqual(b.deploy_messages, c.accounts)
        self.assertEqual(b.messages, b.deploy_messages + b.burst_messages)
        self.assertEqual(b.attached_value, c.accounts * c.account_funding + c.load_funding)
        self.assertEqual(b.wallet_fees, 12345)
        self.assertEqual(b.cost, b.attached_value + 12345)

    def test_a_fee_bound_not_covered_by_max_cost_is_refused(self):
        fees = 400_123_456
        b = remote.work_bound(caps(), fees)
        covered = b.attached_value + fees
        self.assertIsNone(remote.refusal(b, b.messages, covered))
        self.assertIn("cost bound", remote.refusal(b, b.messages, covered - 1) or "")
        # The attached value alone fits, so only the fee bound makes it refuse.
        self.assertIsNone(remote.refusal(remote.work_bound(caps()), b.messages, covered - 1))

    def test_bound_over_a_cap_is_refused(self):
        b = remote.work_bound(caps())
        self.assertIsNone(remote.refusal(b, b.messages, b.cost))
        self.assertIn("message bound", remote.refusal(b, b.messages - 1, b.cost) or "")
        self.assertIn("cost bound", remote.refusal(b, b.messages, b.cost - 1) or "")

    def test_caps_outside_their_bounds_are_refused(self):
        for bad in (
            dict(chains=0),
            dict(chains=256),
            dict(forks=-1),
            dict(forks=remote.MAX_FORKS + 1),
            dict(hops=0),
            dict(hops=remote.MAX_HOPS + 1),
            dict(accounts=1),
            dict(accounts=remote.MAX_ACCOUNTS + 1),
            dict(account_funding=0),
            dict(load_funding=0),
            dict(load_funding=1 << 120),
        ):
            with self.assertRaises(ValueError, msg=bad):
                remote.validate_caps(caps(**bad))
        remote.validate_caps(caps(chains=255, forks=12, hops=remote.MAX_HOPS))


# ─── the wallet fee bound from hand-built ConfigParams ───────────────


def ceil16(value: int) -> int:
    return -(-value // 65536)


def gas_cell(
    price: int = 26_214_400,
    limit: int = 1_000_000,
    flat: tuple[int, int] | None = (100, 40_000),
    ext: bool = True,
) -> Cell:
    """ConfigParam 21 as block.tlb lays it out: [gas_flat_pfx#d1] gas_prices[_ext]."""
    b = Builder()
    if flat is not None:
        b.store_uint(0xD1, 8).store_uint(flat[0], 64).store_uint(flat[1], 64)
    if ext:
        b.store_uint(0xDE, 8).store_uint(price, 64).store_uint(limit, 64).store_uint(limit, 64)
    else:
        b.store_uint(0xDD, 8).store_uint(price, 64).store_uint(limit, 64)
    b.store_uint(10_000, 64)  # gas_credit
    for value in (10_000_000, 100 * NANO, 1000 * NANO):  # block gas, freeze due, delete due
        b.store_uint(value, 64)
    return b.end_cell()


def fwd_cell(lump: int = 100_000, bit: int = 655_361, cell: int = 65_536_000) -> Cell:
    """ConfigParam 25: msg_forward_prices#ea."""
    return (
        Builder()
        .store_uint(0xEA, 8)
        .store_uint(lump, 64)
        .store_uint(bit, 64)
        .store_uint(cell, 64)
        .store_uint(98_304, 32)
        .store_uint(21_845, 16)
        .store_uint(21_845, 16)
        .end_cell()
    )


def storage_cell(entries: dict[int, tuple[int, int]]) -> Cell:
    """ConfigParam 18: Hashmap 32 StoragePrices; values are (bit_price_ps, cell_price_ps)."""

    def store(value: tuple[int, int, int], dest: Builder) -> None:
        since, bit, cell = value
        dest.store_uint(0xCC, 8).store_uint(since, 32).store_uint(bit, 64).store_uint(cell, 64)
        dest.store_uint(bit * 1000, 64).store_uint(cell * 1000, 64)

    prices = HashMap(32, value_serializer=store)
    for key, (bit, cell) in entries.items():
        prices.set_int_key(key, (key, bit, cell))
    out = prices.serialize()
    assert out is not None
    return out


STORAGE_ENTRIES = {0: (1, 500), 1_000: (3, 200)}


def fake_fee_config() -> remote.FeeConfig:
    return remote.fee_config(0, gas_cell(), fwd_cell(), storage_cell(STORAGE_ENTRIES))


def all_cells(roots: list[Cell]) -> dict[bytes, Cell]:
    found: dict[bytes, Cell] = {}
    stack = list(roots)
    while stack:
        cell = stack.pop()
        if cell.hash not in found:
            found[cell.hash] = cell
            stack.extend(cell.refs)
    return found


class FeeBound(unittest.TestCase):
    def test_gas_bound_from_a_hand_built_config_param_21(self):
        # Flat prefix: 40,000 for the first 100 gas, then 400 nanotos a gas (26,214,400 / 2^16).
        gas = remote.parse_gas_prices(gas_cell())
        self.assertEqual(
            (gas.gas_price, gas.gas_limit, gas.flat_gas_limit, gas.flat_gas_price),
            (26_214_400, 1_000_000, 100, 40_000),
        )
        self.assertEqual(gas.max_fee(), 40_000 + 400 * (1_000_000 - 100))
        self.assertEqual(gas.fee(100), 40_000)
        # Without a flat prefix, and with a price that does not divide 2^16: rounded up.
        plain = remote.parse_gas_prices(gas_cell(price=65_537, limit=1_000, flat=None, ext=False))
        self.assertEqual(plain.max_fee(), ceil16(65_537 * 1_000))
        self.assertEqual(plain.max_fee(), 1_001)
        with self.assertRaises(ValueError):
            remote.parse_gas_prices(Builder().store_uint(0xDF, 8).end_cell())

    def test_forward_fee_from_a_hand_built_config_param_25(self):
        prices = remote.parse_msg_prices(fwd_cell())
        self.assertEqual(prices.fee(3, 1_000), 100_000 + ceil16(655_361 * 1_000 + 65_536_000 * 3))
        self.assertEqual(prices.fee(3, 1_000), 113_001)
        self.assertEqual(prices.first_frac, 21_845)
        with self.assertRaises(ValueError):
            remote.parse_msg_prices(Builder().store_uint(0xEB, 8).end_cell())

    def test_external_bound_is_import_plus_gas_plus_every_forward(self):
        config = fake_fee_config()
        key = remote.WalletKey(remote.Secret(TEST_SEED), TEST_RESCUE, 0)
        wallet = remote.bench_wallet(WALLET_CODE, GLOBAL_ID, AUTH, key, fake_public_key(TEST_SEED))
        bench = remote.BenchWallet(wallet, cast(Any, None), cast(Any, None))
        target = remote.Address((0, bytes(range(32))))
        actions = [
            remote.transfer_message(wallet.address, target, NANO, body=HOP_CODE),
            remote.transfer_message(wallet.address, target, 2 * NANO),
        ]
        external = bench.unsigned_external(actions, deploy=True)
        fee = remote.external_fee_bound(config, "deployment", external, actions)
        # Import: every cell but the root, every bit (the root's too, which is conservative).
        root = external.serialize()
        cells = all_cells([root])
        self.assertEqual(fee.import_cells, len(cells) - 1)
        self.assertEqual(fee.import_bits, sum(len(c.bits) for c in cells.values()))
        self.assertGreater(fee.import_cells, 30)  # the ML-DSA-44 signature and the StateInit
        self.assertEqual(fee.import_fee, config.forwarding.fee(fee.import_cells, fee.import_bits))
        self.assertEqual(fee.gas_fee, 400_000_000)
        expected_out = [
            {"cells": 1, "bits": 16, "fee": 100_000 + ceil16(655_361 * 16 + 65_536_000)},
            {"cells": 1, "bits": 0, "fee": 100_000 + ceil16(65_536_000)},
        ]
        self.assertEqual(fee.out_messages, expected_out)
        self.assertEqual(
            fee.total, fee.import_fee + 400_000_000 + sum(x["fee"] for x in expected_out)
        )
        # A deploying external carries the StateInit, so it costs more to import.
        plain = remote.external_fee_bound(
            config, "start", bench.unsigned_external(actions, deploy=False), actions
        )
        self.assertLess(plain.import_fee, fee.import_fee)
        # A message to another workchain is priced by other ConfigParams: refused.
        away = [remote.transfer_message(wallet.address, remote.Address((-1, bytes(32))), 1)]
        with self.assertRaises(ValueError):
            remote.external_fee_bound(config, "x", bench.unsigned_external(away, False), away)

    def test_storage_bound_takes_the_highest_rate_and_the_due_payment(self):
        config = fake_fee_config()
        self.assertEqual(len(config.storage), 2)
        bound = remote.storage_fee_bound(config, 10, 2_000, 1_000, 1_100, 7)
        rate = max(1 * 2_000 + 500 * 10, 3 * 2_000 + 200 * 10)
        self.assertEqual(bound.fee, ceil16(rate * 100) + 7)
        none = remote.fee_config(0, gas_cell(), fwd_cell(), None)
        self.assertEqual(remote.storage_fee_bound(none, 10, 2_000, 0, 10**9, 7).fee, 7)
        with self.assertRaises(ValueError):
            remote.storage_fee_bound(config, 1, 1, 10, 9, 0)


# ─── test key material and a fake signer ─────────────────────────────

TEST_SEED = hashlib.sha256(b"shard bench remote test seed, not a key").digest()
TEST_RESCUE = hashlib.sha256(b"shard bench remote test rescue").digest()
AUTH = bytes([0x42]) * 32
GLOBAL_ID = 3
WALLET_CODE = Builder().store_uint(0xBEEF, 16).end_cell()
HOP_CODE = Builder().store_uint(0xC0DE, 16).end_cell()

FAKE_SIGNER = """#!/usr/bin/env python3
import hashlib, sys
args = sys.argv[1:]
line = sys.stdin.readline().split()
seed = bytes.fromhex(line[0])
if args[0] == "public":
    print((hashlib.sha256(seed).digest() * 41)[:1312].hex())
else:
    print((hashlib.sha256(seed + bytes.fromhex(line[1])).digest() * 76)[:2420].hex())
"""


def fake_public_key(seed: bytes) -> bytes:
    return (hashlib.sha256(seed).digest() * 41)[:1312]


def secret_forms(seed: bytes) -> list[str]:
    return [seed.hex(), seed.hex().upper(), base64.b64encode(seed).decode(), str(list(seed))]


def write_key(directory: Path) -> Path:
    path = directory / "bench-wallet.json"
    path.write_text(
        json.dumps({"mldsa44_seed": TEST_SEED.hex(), "rescue_public_key": TEST_RESCUE.hex()})
    )
    path.chmod(0o600)
    return path


class Key(unittest.TestCase):
    def test_key_file_is_parsed_and_hidden(self):
        with tempfile.TemporaryDirectory() as d:
            key = remote.load_key(write_key(Path(d)))
        self.assertEqual(key.seed.reveal(), TEST_SEED)
        for form in secret_forms(TEST_SEED):
            self.assertNotIn(form, repr(key))
            self.assertNotIn(form, str(key.seed))

    def test_key_file_must_be_private_and_well_formed(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_key(Path(d))
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                remote.load_key(path)
            path.write_text(json.dumps({"mldsa44_seed": "zz", "rescue_public_key": "00"}))
            path.chmod(0o600)
            with self.assertRaises(ValueError) as caught:
                remote.load_key(path)
            self.assertNotIn("zz", str(caught.exception))


# ─── a fake JSON-RPC node ────────────────────────────────────────────

# The node's fee ConfigParams: a computation bound of 0.4 TOS per external,
# far above the 0.01 TOS the fake node charges, and forwarding prices that
# alone stay below it.
FAKE_CONFIG = {18: storage_cell(STORAGE_ENTRIES), 21: gas_cell(), 25: fwd_cell()}

ROOT_SHARD = -(1 << 63)


def b64h(*parts: object) -> str:
    return base64.b64encode(hashlib.sha256(repr(parts).encode()).digest()).decode()


def block_id(workchain: int, seqno: int) -> dict[str, Any]:
    return {
        "@type": "tos.blockIdExt",
        "workchain": workchain,
        "shard": str(ROOT_SHARD),
        "seqno": seqno,
        "root_hash": b64h("root", workchain, seqno),
        "file_hash": b64h("file", workchain, seqno),
    }


def wallet_data(nonce: int) -> Cell:
    return (
        Builder()
        .store_uint(1, 8)
        .store_uint(0, 32)
        .store_uint(0, 32)
        .store_uint(0, 16)
        .store_uint(0, 64)
        .store_uint(nonce, 64)
        .store_uint(0, 64)
        .store_ref(Cell.empty())
        .end_cell()
    )


def tx_json(account: str, lt: int, in_msg: dict[str, Any], out: list[dict[str, Any]]):
    return {
        "account": account.split(":", 1)[1],
        "lt": str(lt),
        "hash": b64h("tx", account, lt),
        "in_msg": in_msg,
        "out_msgs": out,
        "aborted": False,
        "compute": {"skipped": False, "success": True, "account_activated": False},
        "action": {"success": True, "skipped_actions": 0, "messages_created": len(out)},
    }


class FakeNode:
    """One basechain shard, one masterchain block per masterchain-info read.

    The start request puts the wallet's start transaction in the next shard
    block and the first hop account's import of it in the one after. Other
    blocks, masterchain blocks included, carry no transactions.

    Every wallet external costs the wallet ``fee`` on top of the value it
    attaches. With ``stall``, chain time stops at the first send, as on a
    network whose block production has stopped.
    """

    def __init__(
        self,
        wallet: str,
        wallet_balance: int,
        account_funding: int,
        hop0: str = "",
        fee: int = NANO // 100,
        stall: bool = False,
    ):
        self.lock = threading.Lock()
        self.fee, self.stall = fee, stall
        self.last_time = 0
        self.frozen_time: int | None = None
        self.hop0 = hop0
        self.txs: dict[tuple[int, int], list[dict[str, Any]]] = {}
        self.tx_reads: list[tuple[int, int]] = []
        # The start message sits in the outbound queue until this masterchain block.
        self.in_flight_until = 0
        self.mc = 100
        self.wallet, self.wallet_balance = wallet, wallet_balance
        self.account_funding = account_funding
        self.nonce: int | None = None
        self.sends: list[str] = []
        self.bodies: list[bytes] = []
        self.methods: list[str] = []

    def answer(self, method: str, p: dict[str, Any]) -> Any:
        if method == "getMasterchainInfo":
            self.mc += 1
            return {"last": block_id(-1, self.mc)}
        if method == "getBlockHeader":
            seqno, wc = p["seqno"], p["workchain"]
            out: dict[str, Any] = {"id": block_id(wc, seqno), "gen_utime": 1_000_000 + 5 * seqno}
            if wc == -1:
                out["global_id"] = GLOBAL_ID
                if self.frozen_time is not None:
                    out["gen_utime"] = self.frozen_time
                self.last_time = out["gen_utime"]
            else:
                out |= {"after_merge": False, "after_split": False, "before_split": False}
                out["prev_blocks"] = [block_id(0, seqno - 1)]
            return out
        if method == "getShards":
            return {"shards": [block_id(0, p["seqno"])]}
        if method == "getOutMsgQueueSize":
            # As the node does: each reading is taken at the newest masterchain block, whose
            # own queue comes first, then each shard top it references.
            self.mc += 1
            size = 1 if self.mc < self.in_flight_until else 0
            return {
                "shards": [
                    {"id": block_id(-1, self.mc), "size": 0},
                    {"id": block_id(0, self.mc), "size": size},
                ]
            }
        if method == "getConsensusBlock":
            return {"consensus_block": self.mc}
        if method == "getConfigParam":
            cell = FAKE_CONFIG.get(p["param"])
            if cell is None:
                return {"config": {"bytes": "AA=="}}
            return {"config": {"bytes": base64.b64encode(cell.to_boc()).decode()}}
        if method == "getBlockTransactionsExt":
            where = (p["workchain"], p["seqno"])
            self.tx_reads.append(where)
            return {
                "id": block_id(*where),
                "incomplete": False,
                "transactions": self.txs.get(where, []),
            }
        if method == "getAddressInformation":
            if p["address"] == self.wallet:
                active = self.nonce is not None
                return {
                    "balance": str(self.wallet_balance),
                    "state": "active" if active else "uninitialized",
                    "data": base64.b64encode(wallet_data(self.nonce or 0).to_boc()).decode()
                    if active
                    else "",
                    "storage_stat": {
                        "@type": "storage.stat",
                        "used_cells": "3",
                        "used_bits": "900",
                        "last_paid": 1_000_000,
                        "due_payment": "17",
                    },
                }
            deployed = len(self.sends) >= 1
            return {
                "balance": str(self.account_funding if deployed else 0),
                "state": "active" if deployed else "uninitialized",
            }
        if method == "sendBoc":
            self.sends.append(p["boc"])
            if self.stall and self.frozen_time is None:
                self.frozen_time = self.last_time
            if len(self.sends) == 2 and self.hop0:
                self.start_traffic()
            self.nonce = (self.nonce or 0) + 1
            self.wallet_balance -= self.fee + (
                8 * self.account_funding if len(self.sends) == 1 else 10 * NANO
            )
            return {"@type": "ok"}
        raise KeyError(method)

    def start_traffic(self) -> None:
        start = {
            "hash": b64h("start message"),
            "kind": "internal",
            "source": self.wallet,
            "destination": self.hop0,
            "bounced": False,
        }
        external = {"hash": b64h("start external"), "kind": "external"}
        self.txs[(0, self.mc + 1)] = [tx_json(self.wallet, 1, external, [start])]
        self.txs[(0, self.mc + 2)] = [tx_json(self.hop0, 2, start, [])]
        self.in_flight_until = self.mc + 2

    def serve(self) -> tuple[http.server.ThreadingHTTPServer, str]:
        node = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                request = json.loads(body)
                with node.lock:
                    node.bodies.append(body)
                    node.methods.append(request["method"])
                    try:
                        result = node.answer(request["method"], request.get("params") or {})
                        reply = {"jsonrpc": "2.0", "id": request["id"], "result": result}
                    except KeyError:
                        reply = {"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32601}}
                data = json.dumps(reply).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: Any) -> None:
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, f"http://127.0.0.1:{server.server_address[1]}/jsonRPC"


# Modules on the liteserver and local-net path; remote mode must import none of them.
BLOCKED = ("toslib", "tosapi", "tostester.network", "tostester.install", "pqbench.chain")
DRIVER = """
import importlib.abc, runpy, sys
BLOCKED = {blocked!r}

class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if any(name == b or name.startswith(b + ".") for b in BLOCKED):
            raise ImportError("remote mode imported " + name)
        return None

sys.meta_path.insert(0, Block())
sys.argv = [{script!r}] + sys.argv[1:]
try:
    runpy.run_path({script!r}, run_name="__main__")
finally:
    loaded = sorted(m for m in sys.modules if any(m == b or m.startswith(b + ".") for b in BLOCKED))
    print("LOADED-BLOCKED-MODULES", loaded, file=sys.stderr)
"""


class RemoteRun(unittest.TestCase):
    def run_remote(self, d: Path, url: str, extra: list[str] | None = None, timeout: float = 300):
        signer = d / "signer.py"
        signer.write_text(FAKE_SIGNER)
        signer.chmod(0o700)
        (d / "hop.boc").write_bytes(HOP_CODE.to_boc())
        (d / "wallet.boc").write_bytes(WALLET_CODE.to_boc())
        driver = d / "driver.py"
        driver.write_text(
            DRIVER.format(blocked=BLOCKED, script=str(ROOT / "bench/shard/run_shard_bench.py"))
        )
        argv = [
            "--remote",
            "--rpc",
            url,
            "--rpc-share",
            "0.5",
            "--out",
            str(d / "out"),
            "--key-file",
            str(write_key(d)),
            "--signer",
            str(signer),
            "--auth-tag",
            AUTH.hex(),
            "--hop-code",
            str(d / "hop.boc"),
            "--wallet-code",
            str(d / "wallet.boc"),
            "--accounts",
            "8",
            "--chains",
            "4",
            "--forks",
            "2",
            "--hops",
            "10",
            "--account-funding",
            "1",
            "--load-funding",
            "10",
            "--max-cost",
            "100",
            "--max-messages",
            "10000",
            "--duration",
            "1",
            "--poll",
            "0",
            *(extra or []),
        ]
        env = os.environ | {"PYTHONDONTWRITEBYTECODE": "1"}
        return subprocess.run(
            [sys.executable, str(driver), *argv],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=d,
        )

    def hop0(self) -> str:
        from shard import hopbench

        seed = hashlib.sha256(b"tos-shard-bench-remote").digest()
        family = hopbench.HopFamily(HOP_CODE, int.from_bytes(seed[:8], "big"), 8)
        return remote.raw(family.address(0))

    def wallet_address(self) -> str:
        key = remote.WalletKey(remote.Secret(TEST_SEED), TEST_RESCUE, 0)
        w = remote.bench_wallet(WALLET_CODE, GLOBAL_ID, AUTH, key, fake_public_key(TEST_SEED))
        return remote.raw(w.address)

    def test_remote_run_uses_json_rpc_only_and_never_leaks_the_key(self):
        node = FakeNode(self.wallet_address(), 1000 * NANO, NANO, self.hop0())
        server, url = node.serve()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                result = self.run_remote(d, url)
                self.assertEqual(result.returncode, 0, result.stderr[-3000:])
                self.assertIn("LOADED-BLOCKED-MODULES []", result.stderr)
                record = json.loads((d / "out/results.json").read_text())
                verdict = (d / "out/t2/t2-verdict.json").read_text()
                written = {p: p.read_bytes() for p in (d / "out").rglob("*") if p.is_file()}
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(len(node.sends), 2)
        self.assertEqual(record["t2_status"], "PASS", verdict)
        # Counted by the chain walk: the funder's start message and its one import.
        self.assertEqual(record["counts"]["run_owned_messages"], 1)
        self.assertEqual(record["counts"]["delivered"]["entry"], 1)
        self.assertEqual(record["counts"]["window_transactions"], 2)
        # The masterchain blocks of the window are read too, for a funder there.
        self.assertTrue(any(wc == -1 for wc, _ in node.tx_reads))
        self.assertEqual(record["stranded"]["hop_accounts_total"], 8 * NANO)
        self.assertEqual(record["stranded"]["recoverable"], 0)
        self.assertIsNotNone(record["finalized_mc"])
        self.assertEqual(
            record["work_bound"]["burst_messages"], 1 + 4 * remote.hop_transactions(10, 2)
        )
        self.assertEqual(record["outcome"], "COUNTED")
        # The fee bound, derived from the node's ConfigParams before any send, covers the
        # fee the node really charged for each external and for the run.
        fees = record["wallet_fee_bound"]
        deployment, start = fees["externals"]
        self.assertEqual(deployment["gas_fee"], 400_000_000)
        self.assertGreaterEqual(deployment["total"], record["deployment_wallet_fee"])
        self.assertGreaterEqual(start["total"], record["start_wallet_fee"])
        self.assertEqual(record["deployment_wallet_fee"], node.fee)
        self.assertEqual(record["wallet_balance"]["fees_spent"], 2 * node.fee)
        self.assertGreaterEqual(fees["total"], record["wallet_balance"]["fees_spent"])
        self.assertEqual(record["work_bound"]["wallet_fees"], fees["total"])
        self.assertEqual(fees["storage"]["due_payment"], 17)
        self.assertEqual(fees["storage"]["since"], 1_000_000)
        self.assertEqual(
            record["fee_config"]["config_param_hashes"],
            {str(k): v.hash.hex() for k, v in FAKE_CONFIG.items()},
        )
        self.assertTrue(set(node.methods) <= set(FakeNode_methods()), node.methods)
        texts = [result.stdout, result.stderr] + [
            b.decode(errors="replace") for b in written.values()
        ]
        texts += [b.decode() for b in node.bodies]
        # JSON records again in one canonical layout, so a seed stored as a
        # number list or in any other JSON shape is found whatever the indent.
        for path, blob in written.items():
            if path.suffix == ".json":
                texts.append(json.dumps(json.loads(blob)))
        for form in secret_forms(TEST_SEED):
            for text in texts:
                self.assertNotIn(form, text)
        for blob in list(written.values()) + node.bodies:
            self.assertNotIn(TEST_SEED, blob)

    def test_over_the_cap_is_refused_before_any_request(self):
        node = FakeNode(self.wallet_address(), 1000 * NANO, NANO)
        server, url = node.serve()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                over_cost = self.run_remote(d, url, ["--max-cost", "5"])
                over_messages = self.run_remote(d, url, ["--max-messages", "50"])
                bad_cap = self.run_remote(d, url, ["--forks", "13"])
                self.assertFalse((d / "out").exists())
        finally:
            server.shutdown()
            server.server_close()
        for result, reason in (
            (over_cost, "cost bound"),
            (over_messages, "message bound"),
            (bad_cap, "forks must be"),
        ):
            self.assertEqual(result.returncode, remote.REFUSED, result.stderr[-2000:])
            self.assertIn(reason, result.stderr)
        self.assertIn("work_bound", over_cost.stdout)
        self.assertEqual(node.methods, [])

    def test_a_fee_bound_over_max_cost_is_refused_before_any_send(self):
        # 1-nanotos funding: the attached value (9 nanotos) fits an 11-nanotos cost cap,
        # and only the fee bound from the node's ConfigParams shows the run cannot.
        node = FakeNode(self.wallet_address(), 1000 * NANO, 1)
        server, url = node.serve()
        tiny = ["--account-funding", "0.000000001", "--load-funding", "0.000000001"]
        try:
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                result = self.run_remote(d, url, [*tiny, "--max-cost", "0.000000011"])
                out_exists = (d / "out").exists()
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(result.returncode, remote.REFUSED, result.stderr[-2000:])
        self.assertIn("cost bound", result.stderr)
        self.assertIn("wallet_fee_bound", result.stdout)
        self.assertFalse(out_exists)
        self.assertEqual(node.sends, [])
        self.assertNotIn("sendBoc", node.methods)
        self.assertIn("getConfigParam", node.methods)

    def test_a_deployment_fee_over_its_bound_stops_before_the_start(self):
        node = FakeNode(self.wallet_address(), 1000 * NANO, NANO, self.hop0(), fee=10 * NANO)
        server, url = node.serve()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                result = self.run_remote(d, url)
                record = json.loads((d / "out/results.json").read_text())
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(result.returncode, remote.REFUSED, result.stderr[-2000:])
        self.assertEqual(len(node.sends), 1)
        self.assertEqual(record["outcome"], "REFUSED")
        self.assertIn("derived bound", record["stopped"])
        self.assertEqual(record["deployment_wallet_fee"], 10 * NANO)

    def test_a_nonzero_local_is_refused_before_any_request(self):
        node = FakeNode(self.wallet_address(), 1000 * NANO, NANO)
        server, url = node.serve()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                result = self.run_remote(d, url, ["--local", "0.5"])
                out_exists = (d / "out").exists()
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(result.returncode, remote.REFUSED, result.stderr[-2000:])
        self.assertIn("--local 0.5 has no effect", result.stderr)
        self.assertFalse(out_exists)
        self.assertEqual(node.methods, [])

    def test_stalled_chain_time_ends_the_run_inconclusive(self):
        node = FakeNode(self.wallet_address(), 1000 * NANO, NANO, self.hop0(), stall=True)
        server, url = node.serve()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                result = self.run_remote(d, url, ["--drain-wait", "1"], timeout=90)
                record = json.loads((d / "out/results.json").read_text())
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(result.returncode, remote.INCONCLUSIVE, result.stderr[-2000:])
        self.assertEqual(record["outcome"], "INCONCLUSIVE")
        self.assertIn("chain time did not pass the deadline", record["stopped"])
        self.assertEqual(len(node.sends), 2)
        self.assertNotIn("counts", record)


class LocalAndWaits(unittest.TestCase):
    def test_only_local_zero_runs_remotely(self):
        self.assertIsNone(remote.local_refusal(0.0))
        for value in (0.25, 1.0):
            self.assertIn("has no effect", remote.local_refusal(value) or "")

    def test_the_wait_for_chain_time_ends_when_time_stops(self):
        class Frozen(remote.Remote):
            reads = 0

            async def now(self) -> int:
                self.reads += 1
                return 1_000

        frozen = Frozen([remote.PacedRpc("http://127.0.0.1:9/jsonRPC")], 0.01)

        async def wait() -> int | None:
            return await asyncio.wait_for(frozen.wait_past(1_000, 0.2), timeout=10)

        started = time.monotonic()
        self.assertIsNone(asyncio.run(wait()))
        self.assertLess(time.monotonic() - started, 5)
        self.assertGreater(frozen.reads, 1)

    def test_the_wait_for_chain_time_returns_once_time_passes(self):
        class Ticking(remote.Remote):
            t = 990

            async def now(self) -> int:
                self.t += 5
                return self.t

        ticking = Ticking([remote.PacedRpc("http://127.0.0.1:9/jsonRPC")], 0)
        self.assertEqual(asyncio.run(ticking.wait_past(1_000, 0)), 1_005)


def FakeNode_methods() -> list[str]:
    return [
        "getMasterchainInfo",
        "getBlockHeader",
        "getShards",
        "getOutMsgQueueSize",
        "getConsensusBlock",
        "getConfigParam",
        "getBlockTransactionsExt",
        "getAddressInformation",
        "sendBoc",
    ]


class Signing(unittest.TestCase):
    def test_signer_gets_the_seed_on_stdin_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            argv_log = d / "argv.txt"
            script = d / "signer.py"
            script.write_text(
                FAKE_SIGNER.replace(
                    "args = sys.argv[1:]",
                    f"args = sys.argv[1:]\nopen({str(argv_log)!r}, 'a').write(' '.join(args))",
                )
            )
            script.chmod(0o700)
            key = remote.WalletKey(remote.Secret(TEST_SEED), TEST_RESCUE, 0)
            signer = remote.Signer(script, key)
            self.assertEqual(signer.public_key(), fake_public_key(TEST_SEED))
            self.assertEqual(len(signer.sign(b"m" * 32)), remote.SIGNATURE_BYTES)
            self.assertNotIn(TEST_SEED.hex(), argv_log.read_text())


if __name__ == "__main__":
    unittest.main()
