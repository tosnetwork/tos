"""Shard bench remote mode: burst caps, the work bound, the key, and the JSON-RPC-only path.

Run: uv run python bench/tests/test_remote.py

The end-to-end test runs ``run_shard_bench.py --remote`` in a child process
against a fake JSON-RPC node served over loopback HTTP, with liteserver and
local-net modules made unimportable, a fake signer, and a key made of test
material only.
"""

import hashlib
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "bench"), str(ROOT / "test/tostester/src")]

import base64  # noqa: E402

from pytosiq_core import Builder, Cell  # noqa: E402
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
        wallet_fee_cap=NANO,
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
        b = remote.work_bound(c)
        self.assertEqual(b.deploy_messages, c.accounts)
        self.assertEqual(b.messages, b.deploy_messages + b.burst_messages)
        self.assertEqual(b.attached_value, c.accounts * c.account_funding + c.load_funding)
        self.assertEqual(b.cost, b.attached_value + 2 * c.wallet_fee_cap)

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
            dict(wallet_fee_cap=0),
            dict(load_funding=1 << 120),
        ):
            with self.assertRaises(ValueError, msg=bad):
                remote.validate_caps(caps(**bad))
        remote.validate_caps(caps(chains=255, forks=12, hops=remote.MAX_HOPS))


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


class FakeNode:
    """One basechain shard, one masterchain block per masterchain-info read, no transactions."""

    def __init__(self, wallet: str, wallet_balance: int, account_funding: int):
        self.lock = threading.Lock()
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
            else:
                out |= {"after_merge": False, "after_split": False, "before_split": False}
                out["prev_blocks"] = [block_id(0, seqno - 1)]
            return out
        if method == "getShards":
            return {"shards": [block_id(0, p["seqno"])]}
        if method == "getOutMsgQueueSize":
            return {"shards": [{"id": block_id(0, self.mc), "size": 0}]}
        if method == "getConsensusBlock":
            return {"consensus_block": self.mc}
        if method == "getConfigParam":
            return {"config": {"bytes": "AA=="}}
        if method == "getBlockTransactionsExt":
            return {"id": block_id(0, p["seqno"]), "incomplete": False, "transactions": []}
        if method == "getAddressInformation":
            if p["address"] == self.wallet:
                active = self.nonce is not None
                return {
                    "balance": str(self.wallet_balance),
                    "state": "active" if active else "uninitialized",
                    "data": base64.b64encode(wallet_data(self.nonce or 0).to_boc()).decode()
                    if active
                    else "",
                }
            deployed = len(self.sends) >= 1
            return {
                "balance": str(self.account_funding if deployed else 0),
                "state": "active" if deployed else "uninitialized",
            }
        if method == "sendBoc":
            self.sends.append(p["boc"])
            self.nonce = (self.nonce or 0) + 1
            self.wallet_balance -= NANO // 100 + (
                8 * self.account_funding if len(self.sends) == 1 else 10 * NANO
            )
            return {"@type": "ok"}
        raise KeyError(method)

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
    def run_remote(self, d: Path, url: str, extra: list[str] | None = None):
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
            timeout=300,
            env=env,
            cwd=d,
        )

    def wallet_address(self) -> str:
        key = remote.WalletKey(remote.Secret(TEST_SEED), TEST_RESCUE, 0)
        w = remote.bench_wallet(WALLET_CODE, GLOBAL_ID, AUTH, key, fake_public_key(TEST_SEED))
        return remote.raw(w.address)

    def test_remote_run_uses_json_rpc_only_and_never_leaks_the_key(self):
        node = FakeNode(self.wallet_address(), 1000 * NANO, NANO)
        server, url = node.serve()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                result = self.run_remote(d, url)
                self.assertEqual(result.returncode, 0, result.stderr[-3000:])
                self.assertIn("LOADED-BLOCKED-MODULES []", result.stderr)
                record = json.loads((d / "out/results.json").read_text())
                written = {p: p.read_bytes() for p in (d / "out").rglob("*") if p.is_file()}
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(len(node.sends), 2)
        self.assertEqual(record["t2_status"], "PASS")
        self.assertEqual(record["stranded"]["hop_accounts_total"], 8 * NANO)
        self.assertEqual(record["stranded"]["recoverable"], 0)
        self.assertIsNotNone(record["finalized_mc"])
        self.assertEqual(
            record["work_bound"]["burst_messages"], 1 + 4 * remote.hop_transactions(10, 2)
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
