"""Hop accounts, message bodies and per-shard block accounting for the shard-scaling bench.

The bench deploys ``accounts`` copies of ``hop.fc`` that differ only in their
id. Load is a set of message chains between those copies, so after the start
message no client is in the loop: the chain itself generates every
transaction, and the measured rate is what the validators can execute,
collate and agree on, shard by shard.
"""

import base64
import hashlib
import json
import statistics
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pytosiq_core import Address, Builder, Cell, StateInit

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).resolve().parent / "hop.fc"

OP_DEPLOY = 0x64706C79
OP_START = 0x73746172
OP_HOP = 0x686F7031
LOCAL_BASE = 65536
MAX_CHAINS = 255
MAX_DEPTH = 60
U64 = (1 << 64) - 1


def build(build_dir: Path, out: Path) -> Cell:
    """Compile hop.fc with the tree's FunC and Fift; record its code hash."""
    out.mkdir(parents=True, exist_ok=True)
    func, fift = build_dir / "crypto/func", build_dir / "crypto/fift"
    for tool in (func, fift):
        if not tool.is_file():
            raise FileNotFoundError(f"required compiler not built: {tool}")
    asm, boc = out / "hop.fif", out / "hop.boc"
    subprocess.run(
        [str(func), "-SPA", "-o", str(asm), str(ROOT / "crypto/smartcont/stdlib.fc"), str(SOURCE)],
        check=True,
    )
    script = out / "hop.run.fif"
    script.write_text(f'"Asm.fif" include\n"{asm}" include\n2 boc+>B "{boc}" B>file\n')
    subprocess.run([str(fift), "-I", str(ROOT / "crypto/fift/lib"), "-s", str(script)], check=True)
    raw = boc.read_bytes()
    code = Cell.one_from_boc(raw)
    manifest = {
        "source": str(SOURCE.relative_to(ROOT)),
        "code_hash": code.hash.hex(),
        "boc_sha256": hashlib.sha256(raw).hexdigest(),
    }
    (out / "contracts.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return code


def _uint(value: int, bits: int, what: str) -> int:
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ValueError(f"{what} must be an integer in [0, 2^{bits})")
    return value


@dataclass(frozen=True)
class HopFamily:
    """The copies of one run: same code and salt, ids 0 .. accounts-1."""

    code: Cell
    salt: int
    accounts: int

    def __post_init__(self):
        _uint(self.salt, 64, "salt")
        if type(self.accounts) is not int or not 2 <= self.accounts < (1 << 32):
            raise ValueError("a family needs at least two accounts and fewer than 2^32")

    def data(self, index: int) -> Cell:
        _uint(index, 32, "account id")
        return (
            Builder()
            .store_uint(index, 32)
            .store_uint(self.salt, 64)
            .store_ref(self.code)
            .end_cell()
        )

    def state_init(self, index: int) -> StateInit:
        return StateInit(code=self.code, data=self.data(index))

    def address(self, index: int) -> Address:
        return Address((0, self.state_init(index).serialize().hash))

    def addresses(self) -> list[Address]:
        return [self.address(i) for i in range(self.accounts)]


def hop_params(
    remaining: int, forks: int, local: int, depth: int, deadline: int, accounts: int
) -> Builder:
    if not 0 <= local <= LOCAL_BASE - 1:
        raise ValueError("local is a probability scaled to 2^16 - 1")
    if not 0 <= depth <= MAX_DEPTH:
        raise ValueError(f"depth must be in [0, {MAX_DEPTH}]")
    if accounts < 1:
        raise ValueError("accounts must be positive")
    return (
        Builder()
        .store_uint(_uint(remaining, 32, "remaining"), 32)
        .store_uint(_uint(forks, 8, "forks"), 8)
        .store_uint(local, 16)
        .store_uint(depth, 8)
        .store_uint(_uint(deadline, 32, "deadline"), 32)
        .store_uint(_uint(accounts, 32, "accounts"), 32)
    )


def deploy_body(lo: int, hi: int) -> Cell:
    if not 0 <= lo < hi:
        raise ValueError("a deployment range needs lo < hi")
    return (
        Builder()
        .store_uint(OP_DEPLOY, 32)
        .store_uint(_uint(lo, 32, "lo"), 32)
        .store_uint(_uint(hi, 32, "hi"), 32)
        .end_cell()
    )


def start_body(
    chains: int, remaining: int, forks: int, local: int, depth: int, deadline: int, accounts: int
) -> Cell:
    if not 1 <= chains <= MAX_CHAINS:
        raise ValueError(f"chains must be in [1, {MAX_CHAINS}]")
    params = hop_params(remaining, forks, local, depth, deadline, accounts)
    return (
        Builder()
        .store_uint(OP_START, 32)
        .store_uint(chains, 8)
        .store_cell(params.end_cell())
        .end_cell()
    )


def local_scaled(fraction: float) -> int:
    if not 0.0 <= fraction <= 1.0:
        raise ValueError("--local is a fraction in [0, 1]")
    return min(LOCAL_BASE - 1, round(fraction * LOCAL_BASE))


def shard_of(account_hash: bytes, depth: int) -> int:
    """The signed 64-bit id of the depth-``depth`` basechain shard holding an account."""
    if len(account_hash) != 32 or not 0 <= depth <= MAX_DEPTH:
        raise ValueError("an account hash is 32 bytes and depth is in [0, 60]")
    top = int.from_bytes(account_hash[:8], "big")
    tag = 1 << (63 - depth)
    unsigned = (top & ~((tag << 1) - 1) & U64) | tag
    return to_signed(unsigned)


def to_signed(shard: int) -> int:
    shard &= U64
    return shard - (1 << 64) if shard >> 63 else shard


def shard_depth(shard: int) -> int:
    unsigned = shard & U64
    if unsigned == 0:
        raise ValueError("shard id 0 is not a shard")
    return 63 - ((unsigned & -unsigned).bit_length() - 1)


def shard_label(shard: int) -> str:
    return f"{shard & U64:016x}"


@dataclass
class Collation:
    """One validator's record of a collated basechain block (session-logs)."""

    shard: int
    seqno: int
    transactions: int
    bytes: int
    gas: int
    lt_delta: int
    categories: dict[str, int]
    cpu_seconds: float
    cross_shard_in: int
    queue_after: int


def collations(network_dir: Path) -> dict[bytes, Collation]:
    """Every node's collatedBlock records for the basechain, keyed by block root hash.

    A candidate that never became a block has a root hash no scanned block
    carries, so keying by root hash counts only blocks the chain accepted.
    """
    out: dict[bytes, Collation] = {}
    for path in sorted(network_dir.glob("node*/session-logs")):
        with path.open(errors="replace") as f:
            for line in f:
                if '"validatorStats.collatedBlock"' not in line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                block = d["block_id"]
                if block["workchain"] != 0:
                    continue
                shard = int(block["shard"])
                stats = d.get("block_stats", {})
                limits = d.get("block_limits", {})
                cross = 0
                for n in stats.get("neighbors", []):
                    ns = n.get("shard", {})
                    if ns.get("workchain") == 0 and int(ns.get("shard", 0)) != shard:
                        cross += int(n.get("processed_msgs", 0))
                out[base64.b64decode(block["root_hash"])] = Collation(
                    shard=shard,
                    seqno=int(block["seqno"]),
                    transactions=int(stats.get("transactions", 0)),
                    bytes=int(d.get("bytes", 0)),
                    gas=int(limits.get("gas", 0)),
                    lt_delta=int(limits.get("lt_delta", 0)),
                    categories={
                        k: int(limits.get(f"cat_{k}", 0))
                        for k in ("bytes", "gas", "lt_delta", "collated_data_bytes")
                    },
                    cpu_seconds=float(d.get("cpu_work_time", 0.0)),
                    cross_shard_in=cross,
                    queue_after=int(stats.get("new_out_msg_queue_size", 0)),
                )
    return out


@dataclass
class ScannedBlock:
    shard: int
    seqno: int
    gen_utime: int
    root_hash: bytes
    transactions: int | None = None
    collation: Collation | None = None


@dataclass
class ShardSummary:
    shard: str
    blocks: int
    transactions: int
    tx_per_second: float
    block_interval_mean: float
    tx_per_block_median: float | None
    bytes_median: float | None
    gas_median: float | None
    cross_shard_in: int
    full_by: dict[str, int] = field(default_factory=dict)
    cpu_seconds_median: float | None = None
    queue_after_max: int | None = None


# validatorStats categories: 0 underload, 1 normal, 2 soft limit, 3 hard limit.
FULL_CATEGORY = 2


def summarize(blocks: list[ScannedBlock], lo: int, hi: int) -> dict[str, Any]:
    """Per-shard and total rates over blocks generated in [lo, hi)."""
    if hi <= lo:
        raise ValueError("the measurement window is empty")
    seconds = hi - lo
    window = [b for b in blocks if lo <= b.gen_utime < hi]
    by_shard: dict[int, list[ScannedBlock]] = {}
    for b in window:
        by_shard.setdefault(b.shard, []).append(b)
    shards: list[ShardSummary] = []
    for shard in sorted(by_shard, key=lambda s: s & U64):
        rows = sorted(by_shard[shard], key=lambda b: b.seqno)
        txs = [b.transactions or 0 for b in rows]
        cols = [b.collation for b in rows if b.collation is not None]
        full: dict[str, int] = {}
        for c in cols:
            for k, v in c.categories.items():
                if v >= FULL_CATEGORY:
                    full[k] = full.get(k, 0) + 1
        shards.append(
            ShardSummary(
                shard=shard_label(shard),
                blocks=len(rows),
                transactions=sum(txs),
                tx_per_second=sum(txs) / seconds,
                # gen_utime has one-second resolution, so the interval is the
                # window's length over its block count, not a per-pair median.
                block_interval_mean=seconds / len(rows),
                tx_per_block_median=statistics.median(txs) if txs else None,
                bytes_median=statistics.median(c.bytes for c in cols) if cols else None,
                gas_median=statistics.median(c.gas for c in cols) if cols else None,
                cross_shard_in=sum(c.cross_shard_in for c in cols),
                full_by=full,
                cpu_seconds_median=(
                    statistics.median(c.cpu_seconds for c in cols) if cols else None
                ),
                queue_after_max=max((c.queue_after for c in cols), default=None),
            )
        )
    total = sum(s.transactions for s in shards)
    cross = sum(s.cross_shard_in for s in shards)
    return {
        "window": {"from": lo, "to": hi, "seconds": seconds},
        "shards": [s.__dict__ for s in shards],
        "shard_count": len(shards),
        "blocks": len(window),
        "transactions": total,
        "tx_per_second": total / seconds,
        "cross_shard_messages_in": cross,
        "unmatched_blocks": sum(1 for b in window if b.collation is None),
    }


def tail_ratio(blocks: list[ScannedBlock], lo: int, hi: int, tail: int = 10) -> float | None:
    """Rate over the window's last ``tail`` seconds against the whole window.

    Chains end when their value runs out; a ratio well below 1 says the load
    thinned out before the window closed, so the window rate understates
    capacity.
    """
    if hi - lo <= tail:
        return None
    whole = sum(b.transactions or 0 for b in blocks if lo <= b.gen_utime < hi) / (hi - lo)
    end = sum(b.transactions or 0 for b in blocks if hi - tail <= b.gen_utime < hi) / tail
    return end / whole if whole else None
