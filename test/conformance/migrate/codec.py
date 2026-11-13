#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Contexts of the codec, tl and fee families, and the cross-checks of the migrated ones.

codec.py contexts --out-dir DIR [--rtos-git REPO --rtos-commit SHA] [--replay TOOL]
    Write one <harness>/<family>.jsonl of create-ready contexts per family and a families.json
    index. Only contexts are taken from the sources; every effect is filled by the C++ reference
    (runner/conformance.py create). The rtos-* families read the RTOS fixture files at a commit with
    ``git show``; the corpus families also need test-epoch-replay (--replay) for the REL-02 export.
codec.py create --reference CLI --contexts-dir DIR --vectors VECTORS
    Fill every family of DIR with runner/conformance.py create into VECTORS.
codec.py check --vectors VECTORS --varuint-driver BIN --gas-driver BIN
               --storage-encoding-driver BIN --tl-driver BIN --work-dir DIR
    Require each migrated family's frozen effects to equal, row for row, both the original driver's
    output and the frozen file or authored rows it was checked against: varuint-codec (330),
    storage-encoding (284), gas-purchase (6,602), storage-fee-vectors and tl-cli-fixtures (98).
codec.py rtos-compare --vectors VECTORS --rtos-git REPO --rtos-commit SHA
    Informational: count where the refilled rtos-* effects agree with the verdicts recorded in the
    RTOS files. Those verdicts are not expectations here; disagreements are listed for review.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import itertools
import json
import re
import subprocess
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[3]
CONFORMANCE = ROOT / "test/conformance"

Json = dict[str, Any]
MAX_LINE = 16 << 20


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def entry(fixture_id: str, context: Json, note: str | None = None) -> Json:
    out: Json = {"fixture_id": fixture_id, "context": context}
    if note:
        out["note"] = note
    return out


@dataclass
class Family:
    harness: str
    family: str
    source: str
    entries: list[Json] = field(default_factory=lambda: [])


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The ordinary-cell helper of the authentication harness builds the authored cells; it is loaded by path
# because it lives outside the runner's import roots.
_CELLS: Any = load_module("cells", ROOT / "test/auth-extensions/cells.py")
Cell: Any = _CELLS.Cell
from_boc: Any = _CELLS.from_boc
read_dict: Any = _CELLS.read_dict
CellT = Any


def git_show(repo: Path, commit: str, path: str) -> bytes:
    done = subprocess.run(
        ["git", "-C", str(repo), "show", f"{commit}:{path}"], capture_output=True, check=False
    )
    if done.returncode != 0:
        raise SystemExit(f"git show {commit}:{path}: {done.stderr.decode().strip()}")
    return done.stdout


def data_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line and not line.startswith("#")]


# ---------------------------------------------------------------------------------------------
# Cells: an ordinary cell from bits and references, a canonical dictionary as the node writes it, and
# raw bags of cells for exotic content the ordinary-cell helper does not model.


def bits_of(data: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in data)


def label_bits(label: str, max_len: int) -> str:
    """Dictionary edge label, choosing the encoding exactly as vm::append_dict_label does."""
    n = len(label)
    k = max_len.bit_length()
    if n > 0 and label == label[0] * n:
        same = label[0]
        if n > 1 and k < 2 * n - 1:
            return "11" + same + f"{n:0{k}b}"
        if k < n:
            return "10" + f"{n:0{k}b}" + same * n
        return "0" + "1" * n + "0" + same * n
    if k < n:
        return "10" + f"{n:0{k}b}" + label
    return "0" + "1" * n + "0" + label


def make_dict(entries: dict[int, CellT], width: int) -> CellT | None:
    """Hashmap root of width-bit keys with canonical labels; None when empty."""

    def build(items: dict[str, CellT], n: int) -> CellT:
        keys = sorted(items)
        prefix = keys[0]
        for key in keys[1:]:
            common = 0
            while common < len(prefix) and prefix[common] == key[common]:
                common += 1
            prefix = prefix[:common]
        node = label_bits(prefix, n)
        if len(prefix) == n:
            value = items[keys[0]]
            return Cell(node + value.bits, value.refs)
        rest = n - len(prefix) - 1
        children = [
            build(
                {k[len(prefix) + 1 :]: v for k, v in items.items() if k[len(prefix)] == bit}, rest
            )
            for bit in "01"
        ]
        return Cell(node, children)

    if not entries:
        return None
    return build({f"{k:0{width}b}": v for k, v in entries.items()}, width)


@dataclass
class RawCell:
    d1: int
    d2: int
    payload: bytes
    refs: list[int]


def parse_raw_boc(data: bytes) -> tuple[list[RawCell], list[int]]:
    """Every cell of a bag as stored, without interpreting exotic content."""
    if data[:4] != bytes.fromhex("b5ee9c72"):
        raise SystemExit("not a bag of cells")
    flags, offset_size = data[4], data[5]
    size = flags & 7
    pos = 6

    def read(width: int) -> int:
        nonlocal pos
        value = int.from_bytes(data[pos : pos + width], "big")
        pos += width
        return value

    count, roots, _absent, _total = read(size), read(size), read(size), read(offset_size)
    root_list = [read(size) for _ in range(roots)]
    if flags & 128:
        pos += count * offset_size
    cells: list[RawCell] = []
    for _ in range(count):
        d1, d2 = data[pos], data[pos + 1]
        pos += 2
        if d1 & 16:
            raise SystemExit("bags with stored hashes are not supported")
        length = (d2 + 1) // 2
        payload = data[pos : pos + length]
        pos += length
        cells.append(RawCell(d1, d2, payload, [read(size) for _ in range(d1 & 7)]))
    return cells, root_list


def raw_subgraph_boc(cells: list[RawCell], root: int) -> bytes:
    """A one-root bag of the cells reachable from root, each stored exactly as it was."""
    order: list[int] = []
    seen: set[int] = set()
    stack: list[tuple[int, bool]] = [(root, False)]
    while stack:
        index, done = stack.pop()
        if done:
            order.append(index)
            continue
        if index in seen:
            continue
        seen.add(index)
        stack.append((index, True))
        for ref in reversed(cells[index].refs):
            if ref not in seen:
                stack.append((ref, False))
    order.reverse()
    position = {index: i for i, index in enumerate(order)}
    size = max(1, (len(order).bit_length() + 7) // 8)
    body = b"".join(
        bytes([cells[i].d1, cells[i].d2])
        + cells[i].payload
        + b"".join(position[r].to_bytes(size, "big") for r in cells[i].refs)
        for i in order
    )
    offset_size = max(1, (len(body).bit_length() + 7) // 8)
    return (
        bytes.fromhex("b5ee9c72")
        + bytes([size, offset_size])
        + len(order).to_bytes(size, "big")
        + (1).to_bytes(size, "big")
        + bytes(size)
        + len(body).to_bytes(offset_size, "big")
        + bytes(size)
        + body
    )


def pq_bytes(data: bytes) -> CellT:
    """crypto/pq/pq-bytes.cpp pack_pq_bytes: a 32-bit length over a snake of 127-byte chunks."""
    chunks = [data[i : i + 127] for i in range(0, len(data), 127)]
    tail: CellT | None = None
    for chunk in reversed(chunks):
        cell = Cell(bits_of(chunk))
        if tail is not None:
            cell.ref(tail)
        tail = cell
    root = Cell().uint(len(data), 32)
    return root.ref(tail) if tail is not None else root


# ---------------------------------------------------------------------------------------------
# Families migrated from this repository


def varuint_codec() -> Family:
    module = load_module("varuint_codec", ROOT / "test/executor-parity/varuint_codec.py")
    out = Family("codec", "varuint-codec", "migrated:executor-parity/varuint_codec")
    for row in module.cases():
        data = "" if row["data"] == "-" else row["data"]
        ctx: Json = {"type": "VarUInteger", "n": row["n"]}
        if row["op"] == "read":
            ctx["bits"] = data
        else:
            ctx.update(op="write", value=data)
        out.entries.append(entry(row["name"], ctx))
    return out


STORAGE_DIR = ROOT / "tosctl/src/block/src/tests/data/storage_stat"
STORAGE_NOW = 1780000000


def storage_rows() -> tuple[list[list[str]], list[list[str]]]:
    accepted = data_lines((STORAGE_DIR / "storage-encoding.tsv").read_text())
    rejected = data_lines((STORAGE_DIR / "storage-encoding-rejected.tsv").read_text())
    return [x.split("\t") for x in accepted], [x.split("\t") for x in rejected]


def storage_encoding() -> Family:
    out = Family("codec", "storage-encoding", "migrated:executor-parity/storage_encoding")
    accepted, rejected = storage_rows()
    for fields in accepted + rejected:
        ctx = {"type": "account_storage", "boc": b64(bytes.fromhex(fields[1])), "now": STORAGE_NOW}
        out.entries.append(entry(fields[0], ctx))
    return out


def gas_purchase() -> Family:
    module = load_module("gas_purchase", ROOT / "test/executor-parity/gas_purchase.py")
    out = Family("fee", "gas-purchase", "migrated:executor-parity/gas_purchase")
    for name, (price, limit, flat, fee, value), _ in module.cases():
        ctx = {
            "kind": "gas_purchase",
            "gas_price": str(price),
            "gas_limit": str(limit),
            "flat_gas_limit": str(flat),
            "flat_gas_price": str(fee),
            "balance": str(value),
        }
        out.entries.append(entry(name, ctx))
    return out


STORAGE_FEE_FILE = ROOT / "crypto/block/storage-fee-vectors.tsv"


def storage_fee_rows() -> list[list[str]]:
    return [line.split("\t") for line in data_lines(STORAGE_FEE_FILE.read_text())]


def storage_periods(text: str) -> list[Json]:
    if text == "-":
        return []
    names = ("since", "bit_price", "cell_price", "mc_bit_price", "mc_cell_price")
    out: list[Json] = []
    for period in text.split(","):
        fields = period.split(":")
        out.append(
            {name: int(fields[0]) if name == "since" else fields[i] for i, name in enumerate(names)}
        )
    return out


def storage_fee_vectors() -> Family:
    out = Family("fee", "storage-fee-vectors", "migrated:crypto/block/storage-fee-vectors")
    for f in storage_fee_rows():
        ctx = {
            "kind": "storage",
            "now": int(f[1]),
            "last_paid": int(f[2]),
            "cells": f[3],
            "bits": f[4],
            "special": f[5] == "1",
            "masterchain": f[6] == "1",
            "periods": storage_periods(f[7]),
        }
        # Fixture ids are [A-Za-z0-9._:/+-]; the file's names may also use '^'.
        out.entries.append(entry(f[0].replace("^", "pow"), ctx, f"vector {f[0]}"))
    return out


TL_FIXTURES = ROOT / "test/tl-cli/fixtures.tsv"
TL_SCHEMES = {
    "tos_api": ROOT / "tl/generate/scheme/tos_api.tl",
    "lite_api": ROOT / "tl/generate/scheme/lite_api.tl",
    "toslib_api": ROOT / "tl/generate/scheme/toslib_api.tl",
}
# A declaration starts at the first column; continuation lines are indented.
TL_DECL = re.compile(r"^([A-Za-z_][A-Za-z0-9_.]*)(?:#[0-9a-f]+)?(?:\s|$)")


def tl_names() -> dict[str, tuple[str, str]]:
    """Constructor or function name -> (schema, object|function), read from the schema files."""
    names: dict[str, tuple[str, str]] = {}
    for schema, path in TL_SCHEMES.items():
        kind = "object"
        for line in path.read_text().splitlines():
            stripped = line.strip()
            if stripped == "---functions---":
                kind = "function"
            elif stripped == "---types---":
                kind = "object"
            match = TL_DECL.match(line)
            if match:
                names.setdefault(match.group(1), (schema, kind))
    return names


def tl_kind(name: str, names: dict[str, tuple[str, str]]) -> tuple[str, str]:
    base = name.split("/")[0]
    if name.startswith("control/"):
        base = "engine.validator.controlQuery"
    if base not in names:
        raise SystemExit(f"tl fixture {name}: not declared in the schema files")
    return names[base]


def tl_cli_fixtures() -> Family:
    out = Family("tl", "tl-cli-fixtures", "migrated:tl-cli/fixtures")
    names = tl_names()
    for line in TL_FIXTURES.read_text().splitlines():
        name, wire = line.split("\t")
        schema, kind = tl_kind(name, names)
        out.entries.append(entry(name, {"schema": schema, "kind": kind, "bytes": wire}))
    return out


def tl_proven_reads() -> Family:
    out = Family("tl", "tl-proven-reads", "migrated:tl-cli/binary-fixtures")
    index = json.loads((ROOT / "test/tl-cli/binary-fixtures.json").read_text())
    for path, digest in sorted(index.items()):
        raw = (ROOT / path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise SystemExit(f"{path}: digest differs from binary-fixtures.json")
        name = path.split("proven-reads/")[1].removesuffix(".tl")
        out.entries.append(
            entry(name, {"schema": "lite_api", "kind": "object", "bytes": raw.hex()})
        )
    return out


# ---------------------------------------------------------------------------------------------
# Authored families: reject paths of each harness, and real chain data as decoder inputs


def ordinary_boc(cell: CellT) -> str:
    return b64(cell.boc())


def crc32c(data: bytes) -> int:
    """CRC-32C (Castagnoli), the checksum of bags of cells with the crc flag."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def root_refs(raw: bytes) -> int:
    cells, roots = parse_raw_boc(raw)
    return len(cells[roots[0]].refs) if len(roots) == 1 else 0


def codec_negative() -> Family:
    out = Family("codec", "codec-negative", "authored")
    add = out.entries.append
    one = Cell().uint(0x97, 8)
    good = one.boc()
    parent = Cell().uint(0xAB, 8).ref(one)
    # Bag-of-cells framing.
    add(entry("boc-bad-magic", {"type": "cell", "boc": b64(b"\x00" + good[1:])}))
    add(entry("boc-truncated", {"type": "cell", "boc": b64(good[:-1])}))
    add(entry("boc-trailing-byte", {"type": "cell", "boc": b64(good + b"\x00")}))
    add(entry("boc-header-only", {"type": "cell", "boc": b64(good[:6])}))
    bad_root = bytearray(parent.boc())
    bad_root[10] = 5  # root index beyond the cell count
    add(entry("boc-root-out-of-range", {"type": "cell", "boc": b64(bytes(bad_root))}))
    self_ref = bytearray(parent.boc())
    self_ref[-4] = 0  # the parent's reference points back at the parent
    add(entry("boc-self-reference", {"type": "cell", "boc": b64(bytes(self_ref))}))
    huge = bytearray(good)
    huge[6] = 0xFF  # claims 255 cells
    add(entry("boc-cell-count-oversize", {"type": "cell", "boc": b64(bytes(huge))}))
    wide = (
        bytes.fromhex("b5ee9c72")
        + bytes([2, 1])
        + (1).to_bytes(2, "big")
        + (1).to_bytes(2, "big")
        + bytes(2)
        + bytes([3])
        + bytes(2)
        + bytes([0, 2, 0x97])
    )
    add(entry("boc-noncanonical-index-width", {"type": "cell", "boc": b64(wide)}))
    for mode in (0, 1, 2, 3, 31):
        add(entry(f"boc-mode-{mode}", {"type": "cell", "boc": b64(good), "mode": mode}))
    with_crc = bytearray(good)
    with_crc[4] |= 0x40
    with_crc += crc32c(bytes(with_crc)).to_bytes(4, "little")
    add(entry("boc-crc", {"type": "cell", "boc": b64(bytes(with_crc))}))
    with_crc[-1] ^= 1
    add(entry("boc-bad-crc", {"type": "cell", "boc": b64(bytes(with_crc))}))
    two_roots = (
        bytes.fromhex("b5ee9c72")
        + bytes([1, 1, 2, 2, 0, 6, 0, 1])
        + bytes([0, 2, 0x97, 0, 2, 0x98])
    )
    add(entry("boc-two-roots-as-cell", {"type": "cell", "boc": b64(two_roots)}))
    add(entry("boc-two-roots-as-account", {"type": "Account", "boc": b64(two_roots)}))
    # TL-B: wrong tags, trailing data, extra references, non-minimal integers, budgets.
    add(entry("account-none", {"type": "Account", "bits": "0"}))
    add(entry("account-none-trailing-bit", {"type": "Account", "bits": "00"}))
    add(entry("account-empty-bits", {"type": "Account", "bits": ""}))
    add(entry("message-random-tag", {"type": "Message", "bits": "11111111"}))
    add(entry("transaction-wrong-tag", {"type": "Transaction", "bits": "0110" + "0" * 60}))
    add(entry("block-zero-cell", {"type": "Block", "bits": "0" * 32}))
    add(entry("shardstate-zero-cell", {"type": "ShardStateUnsplit", "bits": "0" * 32}))
    add(entry("mcstateextra-zero-cell", {"type": "McStateExtra", "bits": "0" * 16}))
    coins_cases = {
        "coins-zero": "0000",
        "coins-one": "0001" + "00000001",
        "coins-leading-zero": "0010" + "00000000" + "00000001",
        "coins-truncated": "0010" + "00000001",
        "coins-trailing-bit": "0001" + "00000001" + "1",
        "coins-max": "1111" + "1" * 120,
    }
    for name, bits in coins_cases.items():
        add(entry(name, {"type": "Coins", "bits": bits}))
    with_ref = Cell("0001" + "00000001", [one])
    add(entry("coins-extra-ref", {"type": "Coins", "boc": ordinary_boc(with_ref)}))
    std_addr = Cell().addr((0, 0x1234))
    add(entry("address-std", {"type": "MsgAddressInt", "boc": ordinary_boc(std_addr)}))
    add(entry("address-wrong-tag", {"type": "MsgAddressInt", "bits": "00" + "0" * 265}))
    add(entry("address-truncated", {"type": "MsgAddressInt", "bits": std_addr.bits[:-1]}))
    anycast = Cell().uint(0b10, 2).uint(1, 1).uint(3, 5).uint(5, 3).uint(0, 8).uint(7, 256)
    add(entry("address-anycast", {"type": "MsgAddressInt", "boc": ordinary_boc(anycast)}))
    currencies = Cell().coins(5).uint(0, 1)
    add(entry("currency-plain", {"type": "CurrencyCollection", "boc": ordinary_boc(currencies)}))
    leaf = Cell().uint(2, 5).raw(b"\x00\x05")
    nonminimal = make_dict({7: leaf}, 32)
    padded = Cell().coins(5).maybe(nonminimal)
    add(
        entry(
            "currency-extra-leading-zero",
            {"type": "CurrencyCollection", "boc": ordinary_boc(padded)},
        )
    )
    add(entry("config-param-unknown-index", {"type": "ConfigParam", "n": 999, "bits": "0" * 8}))
    add(entry("config-param-43-truncated", {"type": "ConfigParam", "n": 43, "bits": "00000001"}))
    chain = make_dict({k: extra_leaf(bytes([k + 1])) for k in range(16)}, 32)
    assert chain is not None
    chain_extra = Cell().uint(1, 1).ref(chain)
    add(
        entry(
            "extra-currency-within-budget",
            {"type": "ExtraCurrencyCollection", "boc": ordinary_boc(chain_extra)},
        )
    )
    add(
        entry(
            "extra-currency-over-budget",
            {"type": "ExtraCurrencyCollection", "boc": ordinary_boc(chain_extra), "max_cells": 3},
        )
    )
    add(entry("varuint-len-equals-n", {"type": "VarUInteger", "n": 16, "bits": "1111" + "1" * 120}))
    add(entry("varuint-n1-empty", {"type": "VarUInteger", "n": 1, "bits": ""}))
    add(entry("varuint-n1-zero-length", {"type": "VarUInteger", "n": 1, "bits": "0"}))
    add(
        entry(
            "varuint-n2-trailing", {"type": "VarUInteger", "n": 2, "bits": "1" + "00000001" + "1"}
        )
    )
    for value in ("0", "1", "-1", str((1 << 248) - 1), str(1 << 248), str(-(1 << 255))):
        add(
            entry(
                f"varuint-write-32-{value}",
                {"type": "VarUInteger", "n": 32, "op": "write", "value": value},
            )
        )
    add(entry("validator-descr-empty", {"type": "ValidatorDescr", "bits": ""}))
    add(entry("validator-set-zero-cell", {"type": "ValidatorSet", "bits": "0" * 8}))
    add(
        entry(
            "storage-used-trailing",
            {"type": "StorageUsed", "bits": "001" + "00000001" + "000" + "1"},
        )
    )
    add(entry("account-storage-none", {"type": "account_storage", "bits": "0", "now": 1}))
    return out


def raw_shard_dump(replay: Path, work: Path) -> list[list[str]]:
    corpus = ROOT / "test/rel02/corpus"
    manifest = json.loads((corpus / "manifest.json").read_text())
    lists: list[str] = []
    work.mkdir(parents=True, exist_ok=True)
    for name in ("blocks", "supplements"):
        listing = work / name
        listing.write_text("".join(str(corpus / p) + "\n" for p in manifest[name]))
        lists.append(str(listing))
    dump = work / "dump.tsv"
    done = subprocess.run(
        [str(replay), "--dump", *lists, str(dump)],
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    if done.returncode != 0:
        raise SystemExit(f"replay export failed: {done.stderr.strip()[-2000:]}")
    lines = dump.read_text().splitlines()
    if not lines or lines[0] != "#rel02-v2":
        raise SystemExit("replay export: #rel02-v2 header required")
    return [line.split("\t") for line in lines[1:]]


def config_address(config_hex: str) -> str:
    """ConfigParam 0, the configuration smart contract address, read from the dictionary."""
    params = read_dict(from_boc(bytes.fromhex(config_hex)), 32)
    return f"{int(params[0].refs[0].bits, 2):064x}"


BLOCK_DATA = ROOT / "tosctl/src/block/src/tests/data"
CORPUS_TYPES = (
    "cell",
    "Block",
    "ShardStateUnsplit",
    "ShardState",
    "Message",
    "Transaction",
    "Account",
    "ShardAccount",
    "ConfigParams",
    "ValidatorSet",
)
CORPUS_MAX_BYTES = 120_000


def codec_corpus(replay: Path, work: Path) -> Family:
    """Real chain data through every decoder that could apply; what each refuses is a verdict too."""
    out = Family("codec", "codec-corpus", "authored")
    add = out.entries.append
    files = sorted(BLOCK_DATA.glob("*.boc")) + sorted(
        (BLOCK_DATA / "block_with_transaction").glob("*.boc")
    )
    files += sorted((ROOT / "tosctl/src/block/src/tests/test_data").glob("*.boc"))
    for path in files:
        raw = path.read_bytes()
        if len(raw) > CORPUS_MAX_BYTES:
            continue
        name = path.relative_to(ROOT / "tosctl/src/block/src/tests").as_posix().removesuffix(".boc")
        name = name.replace("block_with_transaction/", "bwt/")[:40]
        for kind in CORPUS_TYPES:
            ctx: Json = {"type": kind, "boc": b64(raw)}
            if kind != "cell":
                ctx["max_cells"] = 1 << 24
            add(entry(f"{name}/{kind}", ctx))
        try:
            refs = root_refs(raw)
        except (SystemExit, IndexError):
            refs = 0
        for kind, path_to in (("BlockInfo", [0]), ("McStateExtra", [3])):
            if refs > path_to[0]:
                ctx = {"type": kind, "boc": b64(raw), "path": path_to, "max_cells": 1 << 24}
                add(entry(f"{name}/{kind}", ctx))
    blocks = sorted((ROOT / "test/rel02/corpus/blocks").glob("*.boc"))
    for path in blocks[::9]:
        raw = path.read_bytes()
        add(
            entry(
                f"rel02-block/{path.stem}", {"type": "Block", "boc": b64(raw), "max_cells": 1 << 24}
            )
        )
        add(
            entry(
                f"rel02-block/{path.stem}/BlockInfo",
                {"type": "BlockInfo", "boc": b64(raw), "path": [0]},
            )
        )
    for path in sorted((ROOT / "test/rel02/corpus/account-preimages").glob("*.boc")):
        for kind in ("Account", "ShardAccount"):
            add(
                entry(
                    f"rel02-account/{path.stem}/{kind}",
                    {"type": kind, "boc": b64(path.read_bytes())},
                )
            )
    rows = raw_shard_dump(replay, work)
    seen: set[str] = set()
    accounts = 0
    for f in rows:
        key = f"{f[12]}:{f[13]}:{f[14]}:{f[9].upper()[:16]}"
        if f[11] not in seen:
            seen.add(f[11])
            add(entry(f"rel02-tx/{key}", {"type": "Transaction", "boc": b64(bytes.fromhex(f[11]))}))
        if f[5] != "-" and f[5] not in seen:
            seen.add(f[5])
            add(entry(f"rel02-msg/{key}", {"type": "Message", "boc": b64(bytes.fromhex(f[5]))}))
        if f[4] not in seen and accounts < 40:
            seen.add(f[4])
            accounts += 1
            shard = b64(bytes.fromhex(f[4]))
            add(entry(f"rel02-shard-account/{key}", {"type": "ShardAccount", "boc": shard}))
            wc = int(f[12])
            add(
                entry(
                    f"rel02-account-storage/{key}",
                    {
                        "type": "account_storage",
                        "boc": shard,
                        "now": int(f[1]),
                        "workchain": wc,
                        "address": shard_account_address(f[4]),
                    },
                )
            )
        if f[6] not in seen:
            seen.add(f[6])
            config = b64(bytes.fromhex(f[6]))
            address = config_address(f[6])
            add(entry(f"rel02-config/{key}", {"type": "config", "boc": config, "address": address}))
            add(
                entry(
                    f"rel02-config/{key}/relax",
                    {"type": "config", "boc": config, "address": address, "relax": True},
                )
            )
            add(
                entry(
                    f"rel02-config-params/{key}",
                    {"type": "ConfigParams", "boc": config, "address": address, "max_cells": 10000},
                )
            )
            add(
                entry(
                    f"rel02-config-params/{key}/budget",
                    {"type": "ConfigParams", "boc": config, "address": address, "max_cells": 16},
                )
            )
    return out


def shard_account_address(shard_hex: str) -> str:
    """The account id stored in a ShardAccount's account (addr_std), or zero for account_none."""
    account = from_boc(bytes.fromhex(shard_hex)).refs[0]
    bits = account.bits
    if not bits or bits[0] == "0":
        return "0" * 64
    if bits[1:3] != "10" or bits[3] != "0":
        raise SystemExit("rel02 account: only addr_std without anycast is expected")
    return f"{int(bits[12:268], 2):064x}"


def tl_negative(fixtures: Family) -> Family:
    """Mutations of the tl-cli fixtures that every TL decoder has to refuse or canonicalize alike."""
    out = Family("tl", "tl-negative", "authored")
    add = out.entries.append
    by_name = {e["fixture_id"]: e["context"] for e in fixtures.entries}

    def ctx(base: Json, wire: str, kind: str | None = None) -> Json:
        return {"schema": base["schema"], "kind": kind or base["kind"], "bytes": wire}

    for name in (
        "engine.validator.getConfig",
        "engine.validator.sign",
        "liteServer.sendMessage",
        "engine.validator.getElectorState/with-block",
        "liteserver.descV2",
        "raw.extMessageInfo",
        "adnl.stats.localId",
        "engine.validator.config",
    ):
        base = by_name[name]
        wire = base["bytes"]
        tag = name.replace("/", "-")
        add(entry(f"{tag}/truncated-4", ctx(base, wire[:-8])))
        add(entry(f"{tag}/truncated-1", ctx(base, wire[:-2])))
        add(entry(f"{tag}/trailing-4", ctx(base, wire + "00000000")))
        add(entry(f"{tag}/trailing-1", ctx(base, wire + "00")))
        add(entry(f"{tag}/unknown-constructor", ctx(base, "deadbeef" + wire[8:])))
        if base["schema"] != "toslib_api":
            other = "object" if base["kind"] == "function" else "function"
            add(entry(f"{tag}/as-{other}", ctx(base, wire, other)))
    add(entry("empty/tos_api-object", {"schema": "tos_api", "kind": "object", "bytes": ""}))
    add(entry("empty/lite_api-function", {"schema": "lite_api", "kind": "function", "bytes": ""}))
    add(entry("empty/toslib_api-object", {"schema": "toslib_api", "kind": "object", "bytes": ""}))
    sign = by_name["engine.validator.sign/bytes-1"]["bytes"]
    # engine.validator.sign key_hash:int256 data:bytes: the one-byte string is 01 xx 00 00.
    add(
        entry(
            "sign/string-padding-nonzero",
            {"schema": "tos_api", "kind": "function", "bytes": sign[:-4] + "ffff"},
        )
    )
    add(
        entry(
            "sign/string-length-beyond-data",
            {"schema": "tos_api", "kind": "function", "bytes": sign[:-8] + "fe" + sign[-6:]},
        )
    )
    long_form = sign[:-8] + "fe010000" + sign[-6:-4] + "000000"
    add(
        entry(
            "sign/string-long-form-for-short",
            {"schema": "tos_api", "kind": "function", "bytes": long_form},
        )
    )
    stats = by_name["adnl.stats.localId"]["bytes"]
    add(
        entry(
            "adnl.stats.localId/vector-length-huge",
            {"schema": "tos_api", "kind": "object", "bytes": stats[:72] + "ffffff7f" + stats[80:]},
        )
    )
    with_block = by_name["engine.validator.getElectorState/with-block"]["bytes"]
    add(
        entry(
            "getElectorState/flags-without-block",
            {"schema": "tos_api", "kind": "function", "bytes": with_block[:16]},
        )
    )
    collator = by_name["engine.validator.collatorNodeSetWhitelistEnabled"]
    for name, value in (("true", "b5757299"), ("false", "379779bc"), ("bad", "01000000")):
        wire = collator["bytes"][:8] + value
        add(
            entry(
                f"collatorNodeSetWhitelistEnabled/bool-{name}",
                {"schema": "tos_api", "kind": "function", "bytes": wire},
            )
        )
    return out


def fee_edges() -> Family:
    out = Family("fee", "fee-edges", "authored")
    add = out.entries.append
    one_period = [
        {
            "since": 0,
            "bit_price": "1",
            "cell_price": "500",
            "mc_bit_price": "1000",
            "mc_cell_price": "500000",
        }
    ]
    max64 = str((1 << 64) - 1)
    storage = {
        "now-before-last-paid": (100, 200, "1", "100", one_period),
        "now-equals-last-paid": (100, 100, "1", "100", one_period),
        "no-periods": (100, 0, "1", "100", []),
        "period-in-the-future": (100, 0, "1", "100", [dict(one_period[0], since=1000)]),
        "zero-usage": (100000, 0, "0", "0", one_period),
        "max-usage": (0xFFFFFFFF, 0, max64, max64, one_period),
        "max-prices": (
            0xFFFFFFFF,
            0,
            max64,
            max64,
            [
                {
                    "since": 0,
                    "bit_price": max64,
                    "cell_price": max64,
                    "mc_bit_price": max64,
                    "mc_cell_price": max64,
                }
            ],
        ),
    }
    for name, (now, last, cells, bits, periods) in storage.items():
        for special, master in itertools.product((False, True), repeat=2):
            add(
                entry(
                    f"storage/{name}/s{int(special)}m{int(master)}",
                    {
                        "kind": "storage",
                        "now": now,
                        "last_paid": last,
                        "cells": cells,
                        "bits": bits,
                        "special": special,
                        "masterchain": master,
                        "periods": periods,
                    },
                )
            )
    prices = {
        "basechain": ("400000", "26214400", "2621440000", 98304, 21845, 21845),
        "masterchain": ("10000000", "655360000", "65536000000", 98304, 21845, 21845),
        "zero": ("0", "0", "0", 0, 0, 0),
        "max": (max64, max64, max64, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF),
        "full-first": ("1000", "65536", "65536", 65536, 65536, 0),
    }
    for (pname, p), (cells, bits), ihr in itertools.product(
        prices.items(),
        (("0", "0"), ("1", "1"), ("3", "1000"), ("1000", "1000000"), (max64, max64)),
        (False, True),
    ):
        add(
            entry(
                f"forward/{pname}/{cells}-{bits}/ihr-off-{int(ihr)}",
                {
                    "kind": "forward",
                    "lump_price": p[0],
                    "bit_price": p[1],
                    "cell_price": p[2],
                    "ihr_factor": p[3],
                    "first_frac": p[4],
                    "next_frac": p[5],
                    "cells": cells,
                    "bits": bits,
                    "ihr_disabled": ihr,
                },
            )
        )
    # Prices that are not multiples of 2^16, so every rounding step (ceil of the 2^-16 sum, the IHR
    # factor, the first and next parts) has a remainder to round.
    for (bit_price, cell_price), (cells, bits) in itertools.product(
        (("1", "0"), ("3", "7"), ("65535", "65537")),
        (("0", "1"), ("0", "2"), ("0", "65535"), ("0", "65536"), ("0", "65537"), ("1", "131073")),
    ):
        add(
            entry(
                f"forward/rounding/{bit_price}-{cell_price}/{cells}-{bits}",
                {
                    "kind": "forward",
                    "lump_price": "5",
                    "bit_price": bit_price,
                    "cell_price": cell_price,
                    "ihr_factor": 98305,
                    "first_frac": 21845,
                    "next_frac": 21845,
                    "cells": cells,
                    "bits": bits,
                },
            )
        )
    for balance in ("0", str((1 << 128) - 1), str(1 << 64), str((1 << 64) - 1)):
        add(
            entry(
                f"gas/balance-{balance}",
                {
                    "kind": "gas_purchase",
                    "gas_price": "65536",
                    "gas_limit": "1000000",
                    "flat_gas_limit": "100",
                    "flat_gas_price": "40000",
                    "balance": balance,
                },
            )
        )
    return out


# ---------------------------------------------------------------------------------------------
# RTOS fixture families: contexts only, refilled from C++


RTOS_DATA = "block/tests/data"


def rtos_varuint(show: Callable[[str], bytes]) -> Family:
    path = f"{RTOS_DATA}/varuint-reference-verdicts.tsv"
    out = Family("codec", "rtos-varuint-reference-verdicts", f"migrated:rtos/{path}")
    for line in data_lines(show(path).decode()):
        f = line.split("\t")
        bits = "" if f[2] == "-" else f[2]
        out.entries.append(entry(f[0], {"type": "VarUInteger", "n": int(f[1]), "bits": bits}))
    return out


def rtos_boc_repeated_roots(show: Callable[[str], bytes]) -> Family:
    path = "block/src/tests/data/boc-repeated-roots.tsv"
    out = Family("codec", "rtos-boc-repeated-roots", f"migrated:rtos/{path}")
    for line in data_lines(show(path).decode()):
        f = line.split("\t")
        ctx = {"type": "cell", "boc": b64(bytes.fromhex(f[4])), "mode": int(f[1])}
        out.entries.append(entry(f"roots-{f[0]}/mode-{f[1]}", ctx))
    return out


def size_limits_wire(tag: int, loads: int | None, bits: int, cells: int) -> CellT:
    """The ConfigParam 43 cell of the RTOS size-limits rows (its size_limits_wire)."""
    c = Cell().uint(tag, 8)
    for n in (1000, 100, 1000):
        c.uint(n, 32)
    c.uint(512, 16).uint(65535, 32).uint(512, 16)
    if tag >= 2:
        for n in (5000, 10000, 256, 256, 32):
            c.uint(n, 32)
        c.uint(8, 8).uint(1024, 32)
    if tag == 3:
        c.uint(loads is not None, 1)
        if loads is not None:
            c.uint(loads, 32)
        c.uint(bits, 32).uint(cells, 32)
    return c


def rtos_size_limits(show: Callable[[str], bytes]) -> Family:
    path = f"{RTOS_DATA}/size-limits.tsv"
    out = Family("codec", "rtos-size-limits", f"migrated:rtos/{path}")
    for line in data_lines(show(path).decode()):
        f = line.split("\t")
        loads = None if f[1] == "-1" else int(f[1])
        cell = size_limits_wire(int(f[0]), loads, int(f[2]), int(f[3]))
        if cell.hash.hex().upper() != f[4]:
            raise SystemExit(
                f"size-limits {f[:4]}: rebuilt cell hash differs from the recorded wire hash"
            )
        ctx = {"type": "ConfigParam", "n": 43, "boc": ordinary_boc(cell)}
        out.entries.append(entry(f"tag{f[0]}-loads{f[1]}-{f[2]}-{f[3]}", ctx))
    return out


def rtos_config_param_39(show: Callable[[str], bytes]) -> Family:
    path = f"{RTOS_DATA}/config-param-39-vectors.tsv"
    out = Family("codec", "rtos-config-param-39", f"migrated:rtos/{path}")
    for line in data_lines(show(path).decode()):
        f = line.split("\t")
        out.entries.append(
            entry(f[0], {"type": "ConfigParam", "n": 39, "boc": b64(bytes.fromhex(f[2]))})
        )
    return out


def extra_leaf(data: bytes, trailing_bit: bool = False, extra_ref: bool = False) -> CellT:
    leaf = Cell().uint(len(data), 5).raw(data)
    if trailing_bit:
        leaf.uint(1, 1)
    if extra_ref:
        leaf.ref(Cell())
    return leaf


def extra_currency_cell(entries: dict[int, CellT]) -> CellT:
    root = make_dict(entries, 32)
    return Cell().maybe(root)


def rtos_extra_currency(show: Callable[[str], bytes]) -> Family:
    """The cells of the RTOS extra_currency_codec_rows, rebuilt with the node's dictionary layout."""
    path = f"{RTOS_DATA}/extra-currency-codec.tsv"
    out = Family("codec", "rtos-extra-currency-codec", f"migrated:rtos/{path}")
    padded = bytes(30) + bytes([100])
    rows: dict[str, CellT] = {
        "empty": extra_currency_cell({}),
        "min100": extra_currency_cell({7: extra_leaf(b"\x64")}),
        "lead100": extra_currency_cell({7: extra_leaf(b"\x00\x64")}),
        "len31v100": extra_currency_cell({7: extra_leaf(padded)}),
        "len0": extra_currency_cell({7: extra_leaf(b"")}),
        "zero1": extra_currency_cell({7: extra_leaf(b"\x00")}),
        "max31": extra_currency_cell({7: extra_leaf(b"\xff" * 31)}),
        "trail": extra_currency_cell({7: extra_leaf(b"\x64", trailing_bit=True)}),
        "extra-ref": extra_currency_cell({7: extra_leaf(b"\x64", extra_ref=True)}),
        "two-one-lead": extra_currency_cell({7: extra_leaf(b"\x64"), 9: extra_leaf(b"\x00\x05")}),
        "two-min": extra_currency_cell(
            {7: extra_leaf(b"\x64"), 1 << 31: extra_leaf(b"\x01\x02\x03")}
        ),
        "short": extra_currency_cell({7: Cell().uint(3, 5).raw(b"\x01\x02")}),
    }
    two = extra_currency_cell({7: extra_leaf(b"\x64"), 9: extra_leaf(b"\x05")})
    fork = two.refs[0]
    rows["fork-trailing-bit"] = Cell("1", [Cell(fork.bits + "1", fork.refs)])
    for count in (512, 513):
        rows[f"entries{count}"] = extra_currency_cell(
            {k * 7 + 1: extra_leaf(b"\x01") for k in range(count)}
        )
    recorded = [line.split("\t")[0] for line in data_lines(show(path).decode())]
    if sorted(recorded) != sorted(rows):
        raise SystemExit(
            f"extra-currency rows differ from the RTOS file: {sorted(set(recorded) ^ set(rows))}"
        )
    for name in recorded:
        ctx = {"type": "ExtraCurrencyCollection", "boc": ordinary_boc(rows[name])}
        out.entries.append(entry(name, ctx))
    return out


def rtos_validator_descr_vectors(show: Callable[[str], bytes]) -> Family:
    path = f"{RTOS_DATA}/validator-descr-vectors.txt"
    out = Family("codec", "rtos-validator-descr-vectors", f"migrated:rtos/{path}")
    for number, line in enumerate(data_lines(show(path).decode())):
        f = line.split(" ")
        out.entries.append(
            entry(f"vector-{number}", {"type": "ValidatorDescr", "boc": b64(bytes.fromhex(f[7]))})
        )
    return out


def descriptor(tag: int) -> CellT:
    """test/pq-native/validator-descr-tags-test.cpp: a body well formed apart from the tag."""
    c = Cell().uint(tag, 8)
    if tag == 0xB3:
        c.raw(b"\x01" * 32).uint(1, 16).raw(b"\x02" * 32).ref(pq_bytes(b"\x03" * 1312))
        c.uint(1234, 64).raw(b"\x09" * 32)
    else:
        c.uint(0x8E81278A, 32).raw(b"\x07" * 32).uint(1234, 64)
        if tag != 0x53:
            c.raw(b"\x09" * 32)
    return c


def rtos_validator_descr_tags(show: Callable[[str], bytes]) -> Family:
    path = f"{RTOS_DATA}/validator-descr-tags.tsv"
    out = Family("codec", "rtos-validator-descr-tags", f"migrated:rtos/{path}")
    for line in data_lines(show(path).decode()):
        tag = int(line.split("\t")[0], 16)
        out.entries.append(
            entry(
                f"tag-{tag:02x}", {"type": "ValidatorDescr", "boc": ordinary_boc(descriptor(tag))}
            )
        )
    return out


def rtos_validator_set_cases(show: Callable[[str], bytes]) -> Family:
    path = f"{RTOS_DATA}/validator-set-cases.txt"
    out = Family("codec", "rtos-validator-set-cases", f"migrated:rtos/{path}")
    for line in data_lines(show(path).decode()):
        f = line.split(" ")
        out.entries.append(entry(f[0], {"type": "ValidatorSet", "boc": b64(bytes.fromhex(f[2]))}))
    return out


def lz4_block(data: bytes) -> bytes:
    """Decompress an LZ4 block with the 4-byte little-endian size prefix the RTOS corpus uses."""
    size = int.from_bytes(data[:4], "little")
    src, out, i = data[4:], bytearray(), 0
    while i < len(src):
        token = src[i]
        i += 1
        literal = token >> 4
        if literal == 15:
            while True:
                literal += src[i]
                i += 1
                if src[i - 1] != 255:
                    break
        out += src[i : i + literal]
        i += literal
        if i >= len(src):
            break
        offset = src[i] | (src[i + 1] << 8)
        i += 2
        length = token & 15
        if length == 15:
            while True:
                length += src[i]
                i += 1
                if src[i - 1] != 255:
                    break
        length += 4
        start = len(out) - offset
        for k in range(length):
            out.append(out[start + k])
    if len(out) != size:
        raise SystemExit(f"lz4: {len(out)} bytes decompressed, {size} declared")
    return bytes(out)


# Size limits of the converted part of config-param-schema; docs/codec.md gives the reasons.
SCHEMA_PER_INDEX = 40
SCHEMA_WHOLE_CONFIG_BYTES = 10_000
MERKLE_PROOF = 3


def rtos_config_param_schema(show: Callable[[str], bytes], stats: dict[str, int]) -> Family:
    base = "block/src/tests/data/config-param-schema"
    out = Family("codec", "rtos-config-param-schema", f"migrated:rtos/{base}")
    cells, roots = parse_raw_boc(lz4_block(show(f"{base}.boc.lz4")))
    leaves: list[int] = []

    def walk(index: int, depth: int) -> None:
        if depth == 0:
            leaves.append(index)
            return
        for ref in cells[index].refs:
            walk(ref, depth - 1)

    walk(roots[0], 8)
    sizes: dict[int, int] = {}

    def size(index: int) -> int:
        if index not in sizes:
            sizes[index] = len(raw_subgraph_boc(cells, index))
        return sizes[index]

    def case_boc(field: str) -> tuple[str, bool]:
        index = leaves[int(field)]
        is_proof = bool(cells[index].d1 & 8) and cells[index].payload[:1] == bytes([MERKLE_PROOF])
        return b64(raw_subgraph_boc(cells, index)), is_proof

    per_index: dict[str, int] = {}
    for line in data_lines(lz4_block(show(f"{base}.tsv.lz4")).decode()):
        f = line.split("\t")
        case_id, kind, index, relax, addr, root, mparams = f[0], f[1], f[2], f[3], f[4], f[5], f[6]
        stats[f"total-{kind}"] = stats.get(f"total-{kind}", 0) + 1
        if root == "-":
            stats[f"skipped-no-root-{kind}"] = stats.get(f"skipped-no-root-{kind}", 0) + 1
            continue
        if kind == "p":
            if per_index.get(index, 0) >= SCHEMA_PER_INDEX:
                stats["skipped-p-per-index"] = stats.get("skipped-p-per-index", 0) + 1
                continue
            per_index[index] = per_index.get(index, 0) + 1
            boc, proof = case_boc(root)
            ctx: Json = {"type": "ConfigParam", "n": int(index), "boc": boc, "max_cells": 1024}
        elif kind == "s":
            boc, proof = case_boc(root)
            ctx = {"type": "ConfigParams", "address": addr, "boc": boc, "max_cells": 10000}
        else:
            total = size(leaves[int(root)]) + (size(leaves[int(mparams)]) if mparams != "-" else 0)
            if total > SCHEMA_WHOLE_CONFIG_BYTES:
                stats["skipped-c-size"] = stats.get("skipped-c-size", 0) + 1
                continue
            boc, proof = case_boc(root)
            ctx = {"type": "config", "address": addr, "boc": boc, "relax": relax == "1"}
            if mparams != "-":
                old, old_proof = case_boc(mparams)
                ctx["old_mparams"] = old
                if old_proof:
                    ctx["old_mparams_proof_child"] = True
        if proof:
            ctx["proof_child"] = True
        stats[f"converted-{kind}"] = stats.get(f"converted-{kind}", 0) + 1
        out.entries.append(entry(case_id, ctx))
    return out


RTOS_NOT_CONVERTED = {
    "validator-set-hash-vectors": "a consensus commitment (TL preimage and short hash) over descriptor fields, not a decoding verdict",
}


# ---------------------------------------------------------------------------------------------
# Commands


def write_families(out_dir: Path, families: Iterable[Family]) -> None:
    index: list[Json] = []
    for family in families:
        path = out_dir / family.harness / f"{family.family}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        ids = [e["fixture_id"] for e in family.entries]
        if len(ids) != len(set(ids)) or not ids:
            raise SystemExit(f"{family.family}: empty or duplicate fixture ids")
        path.write_text(
            "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in family.entries)
        )
        index.append(
            {
                "harness": family.harness,
                "family": family.family,
                "source": family.source,
                "contexts": str(path.relative_to(out_dir)),
                "count": len(ids),
            }
        )
        print(f"{family.harness}/{family.family}: {len(ids)} contexts")
    (out_dir / "families.json").write_text(json.dumps(index, indent=1) + "\n")


def command_contexts(args: argparse.Namespace) -> int:
    out_dir = cast(Path, args.out_dir)
    families: list[Family] = [
        varuint_codec(),
        storage_encoding(),
        gas_purchase(),
        storage_fee_vectors(),
        fee_edges(),
        codec_negative(),
    ]
    tl_fixtures = tl_cli_fixtures()
    families += [tl_fixtures, tl_proven_reads(), tl_negative(tl_fixtures)]
    if args.replay:
        families.append(codec_corpus(args.replay, out_dir / "replay"))
    if args.rtos_git:

        def show(path: str) -> bytes:
            return git_show(args.rtos_git, args.rtos_commit, path)

        stats: dict[str, int] = {}
        families += [
            rtos_varuint(show),
            rtos_boc_repeated_roots(show),
            rtos_size_limits(show),
            rtos_config_param_39(show),
            rtos_extra_currency(show),
            rtos_validator_descr_vectors(show),
            rtos_validator_descr_tags(show),
            rtos_validator_set_cases(show),
            rtos_config_param_schema(show, stats),
        ]
        print("config-param-schema: " + json.dumps(stats, sort_keys=True))
        for name, reason in RTOS_NOT_CONVERTED.items():
            print(f"not converted: {name}: {reason}")
    write_families(out_dir, families)
    return 0


# The blob store takes any long base64-alphabet string for a BOC, which TL hex is too; TL bytes stay inline.
BLOB_OPTIONS = {"tl": ["--blob-threshold", str(MAX_LINE)]}


def command_create(args: argparse.Namespace) -> int:
    contexts_dir = cast(Path, args.contexts_dir)
    for item in json.loads((contexts_dir / "families.json").read_text()):
        out = args.vectors / item["harness"] / "fixtures" / f"{item['family']}.jsonl"
        done = subprocess.run(
            [
                sys.executable,
                "-B",
                str(CONFORMANCE / "runner/conformance.py"),
                "create",
                "--reference",
                str(args.reference),
                "--harness",
                item["harness"],
                "--family",
                item["family"],
                "--source",
                item["source"],
                *BLOB_OPTIONS.get(item["harness"], []),
                *(["--allow-dirty"] if args.allow_dirty else []),
                str(contexts_dir / item["contexts"]),
                str(out),
            ],
            check=False,
        )
        if done.returncode != 0:
            return done.returncode
    return 0


def fixtures_of(vectors: Path, harness: str, family: str) -> list[Json]:
    path = vectors / harness / "fixtures" / f"{family}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()]


def run_driver(argv: list[str], work: Path, label: str) -> str:
    done = subprocess.run(argv, capture_output=True, text=True, timeout=900, check=False, cwd=work)
    if done.returncode != 0:
        raise SystemExit(f"{label} driver exited {done.returncode}: {done.stderr.strip()[-2000:]}")
    return done.stdout


class Tally:
    def __init__(self) -> None:
        self.rows = 0
        self.differences = 0

    def compare(
        self, family: str, fixture_id: str, expected: object, actual: object, against: str
    ) -> None:
        self.rows += 1
        if expected != actual:
            self.differences += 1
            if self.differences <= 20:
                print(
                    f"DIFF {family}/{fixture_id} vs {against}: expected {expected} fixture {actual}"
                )


def present(value: object) -> bool:
    return value is not None


def check_varuint(vectors: Path, driver: Path, work: Path, tally: Tally) -> None:
    module = load_module("varuint_codec", ROOT / "test/executor-parity/varuint_codec.py")
    cases = module.cases()
    fixtures = fixtures_of(vectors, "codec", "varuint-codec")
    if [f["metadata"]["fixture_id"] for f in fixtures] != [c["name"] for c in cases]:
        raise SystemExit("varuint-codec: fixture ids differ from the driver rows")
    inputs = work / "varuint-inputs.tsv"
    inputs.write_text("".join(f"{c['name']}\t{c['op']}\t{c['n']}\t{c['data']}\n" for c in cases))
    driver_rows = [
        line.split("\t")
        for line in run_driver([str(driver), str(inputs)], work, "varuint").splitlines()
    ]
    authored_rows = [line.split("\t") for line in module.expected_output().decode().splitlines()]
    for fixture, case, native, authored in zip(
        fixtures, cases, driver_rows, authored_rows, strict=True
    ):
        eff = fixture["effects"]
        facts = eff["facts"]
        accepted = (
            eff["outcome"] == "accepted"
            if case["op"] == "write"
            else present(facts["validate_bits"])
        )
        value = facts["value"] if case["op"] == "read" else (case["data"] if accepted else None)
        canonical = facts.get("canonical_hash")
        row = [
            fixture["metadata"]["fixture_id"],
            str(int(accepted)),
            value if accepted and value is not None else "-",
            canonical.lower() if accepted and canonical else "-",
        ]
        tally.compare("varuint-codec", row[0], native[:4], row, "test-varuint-codec")
        tally.compare("varuint-codec", row[0], authored[:4], row, "varuint_codec.py authored rows")
        if case["op"] == "read":
            skip = str(int(present(facts["skip_bits"])))
            tally.compare("varuint-codec", row[0], native[4], skip, "test-varuint-codec skip")
            tally.compare("varuint-codec", row[0], authored[4], skip, "varuint_codec.py skip")


def check_storage_encoding(vectors: Path, driver: Path, work: Path, tally: Tally) -> None:
    accepted, rejected = storage_rows()
    fixtures = fixtures_of(vectors, "codec", "storage-encoding")
    rows = accepted + rejected
    if [f["metadata"]["fixture_id"] for f in fixtures] != [r[0] for r in rows]:
        raise SystemExit("storage-encoding: fixture ids differ from the frozen files")
    inputs = work / "storage-inputs.tsv"
    inputs.write_text("".join(f"{r[0]}\t{r[1]}\n" for r in rows))
    native = [
        line.split("\t")
        for line in run_driver([str(driver), str(inputs)], work, "storage").splitlines()
    ]
    for fixture, frozen, driver_row in zip(fixtures, rows, native, strict=True):
        eff = fixture["effects"]
        name = fixture["metadata"]["fixture_id"]
        if eff["outcome"] == "accepted":
            facts = eff["facts"]
            got = [name, "1", str(facts["storage_bits"]), facts["storage_hash"]]
        else:
            got = [name, "0", "-", "-"]
        tally.compare("storage-encoding", name, driver_row, got, "test-storage-encoding")
        # The file's fifth column lists only the StateInit references the rows were authored with; the
        # storage hash already commits to every reference, so it is not compared separately.
        if len(frozen) == 5:
            want = [frozen[0], "1", frozen[2], frozen[3].upper()]
            tally.compare("storage-encoding", name, want, got, "storage-encoding.tsv")
        else:
            tally.compare(
                "storage-encoding",
                name,
                [frozen[0], "0", "-", "-"],
                got,
                "storage-encoding-rejected.tsv",
            )


def check_gas_purchase(vectors: Path, driver: Path, work: Path, tally: Tally) -> None:
    module = load_module("gas_purchase", ROOT / "test/executor-parity/gas_purchase.py")
    cases = module.cases()
    fixtures = fixtures_of(vectors, "fee", "gas-purchase")
    inputs = work / "gas-inputs.tsv"
    inputs.write_text(
        "".join("\t".join([name, *map(str, values)]) + "\n" for name, values, _ in cases)
    )
    native = [
        line.split("\t")
        for line in run_driver([str(driver), str(inputs)], work, "gas").splitlines()
    ]
    authored = [line.split("\t") for line in module.expected_output().decode().splitlines()]
    for fixture, driver_row, authored_row in zip(fixtures, native, authored, strict=True):
        eff = fixture["effects"]
        got = [
            fixture["metadata"]["fixture_id"],
            eff["threshold"],
            eff["gas_bought"],
            eff["fee"],
            eff["simple_fee"],
        ]
        tally.compare("gas-purchase", got[0], driver_row, got, "test-gas-purchase")
        tally.compare("gas-purchase", got[0], authored_row, got, "gas_purchase.py authored rows")
    if len(fixtures) != len(cases):
        raise SystemExit(f"gas-purchase: {len(fixtures)} fixtures for {len(cases)} rows")


def check_storage_fee(vectors: Path, tally: Tally) -> None:
    rows = storage_fee_rows()
    fixtures = fixtures_of(vectors, "fee", "storage-fee-vectors")
    if len(rows) != len(fixtures):
        raise SystemExit(f"storage-fee-vectors: {len(fixtures)} fixtures for {len(rows)} rows")
    for fixture, row in zip(fixtures, rows, strict=True):
        got = [fixture["metadata"]["fixture_id"], fixture["effects"]["fee"]]
        want = [row[0].replace("^", "pow"), row[8]]
        tally.compare("storage-fee-vectors", got[0], want, got, "storage-fee-vectors.tsv")


def check_tl(vectors: Path, driver: Path, work: Path, tally: Tally) -> None:
    frozen = [line.split("\t") for line in TL_FIXTURES.read_text().splitlines()]
    emitted = [line.split("\t") for line in run_driver([str(driver)], work, "tl").splitlines()]
    fixtures = fixtures_of(vectors, "tl", "tl-cli-fixtures")
    for fixture, frozen_row, driver_row in zip(fixtures, frozen, emitted, strict=True):
        eff = fixture["effects"]
        got = [
            fixture["metadata"]["fixture_id"],
            eff["bytes"] if eff["outcome"] == "accepted" else "rejected",
        ]
        tally.compare("tl-cli-fixtures", got[0], frozen_row, got, "fixtures.tsv")
        tally.compare("tl-cli-fixtures", got[0], driver_row, got, "test-tl-cli-fixtures output")
    if not (len(fixtures) == len(frozen) == len(emitted)):
        raise SystemExit("tl-cli-fixtures: fixture, frozen and driver row counts differ")


def command_check(args: argparse.Namespace) -> int:
    work = cast(Path, args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    tally = Tally()
    check_varuint(args.vectors, args.varuint_driver, work, tally)
    check_storage_encoding(args.vectors, args.storage_encoding_driver, work, tally)
    check_gas_purchase(args.vectors, args.gas_driver, work, tally)
    check_storage_fee(args.vectors, tally)
    check_tl(args.vectors, args.tl_driver, work, tally)
    print(f"checked {tally.rows} comparisons, {tally.differences} differences")
    return 1 if tally.differences or tally.rows == 0 else 0


def rtos_compare(args: argparse.Namespace) -> int:
    def show(path: str) -> bytes:
        return git_show(args.rtos_git, args.rtos_commit, path)

    report: dict[str, list[int]] = {}

    def note(column: str, agree: bool) -> None:
        report.setdefault(column, [0, 0])[0 if agree else 1] += 1

    varuint = {
        f["metadata"]["fixture_id"]: f
        for f in fixtures_of(args.vectors, "codec", "rtos-varuint-reference-verdicts")
    }
    for line in data_lines(show(f"{RTOS_DATA}/varuint-reference-verdicts.tsv").decode()):
        r = line.split("\t")
        facts = varuint[r[0]]["effects"]["facts"]
        total = 0 if r[2] == "-" else len(r[2])

        def exact(key: str) -> bool:
            return facts[key] == total

        def value(key: str, bits_key: str) -> str:
            return facts[key] if facts[key] is not None and facts[bits_key] == total else "-"

        note("handwritten_validate", r[3] == str(int(exact("validate_bits"))))
        note("handwritten_as_integer", r[4] == value("value", "value_bits"))
        note("handwritten_skip", r[5] == str(int(exact("skip_bits"))))
        note("generated_validate", r[7] == str(int(exact("gen_validate_bits"))))
        note("generated_unpack", r[8] == value("gen_value", "gen_value_bits"))
        if r[9] != "n/a":
            note("positive32_validate", r[9] == str(int(exact("pos_validate_bits"))))
            note("positive32_as_integer", r[10] == value("pos_value", "pos_value_bits"))
        note("vm_load_var_integer", r[11] == value("vm_value", "vm_bits"))
        if r[12] != "n/a":
            note("storage_used_validate", r[12] == str(int(bool(facts["storage_used"]))))
    for name, path in (
        ("validator-set-cases", f"{RTOS_DATA}/validator-set-cases.txt"),
        ("validator-descr-tags", f"{RTOS_DATA}/validator-descr-tags.tsv"),
    ):
        family = {
            f["metadata"]["fixture_id"]: f
            for f in fixtures_of(args.vectors, "codec", f"rtos-{name}")
        }
        for line in data_lines(show(path).decode()):
            if name == "validator-set-cases":
                case_id, verdict = line.split(" ")[:2]
            else:
                tag, verdict = line.split("\t")[:2]
                case_id = f"tag-{int(tag, 16):02x}"
            note(
                name, (family[case_id]["effects"]["outcome"] == "accepted") == (verdict == "accept")
            )
    extra = {
        f["metadata"]["fixture_id"]: f
        for f in fixtures_of(args.vectors, "codec", "rtos-extra-currency-codec")
    }
    for line in data_lines(show(f"{RTOS_DATA}/extra-currency-codec.tsv").decode()):
        f = line.split("\t")
        facts = extra[f[0]]["effects"]["facts"]
        note("extra-currency strict", f[2] == str(int(facts["handwritten"])))
        note("extra-currency structural", f[3] == str(int(facts["gen"])))
    schema = {
        f["metadata"]["fixture_id"]: f
        for f in fixtures_of(args.vectors, "codec", "rtos-config-param-schema")
    }
    base = "block/src/tests/data/config-param-schema"
    for line in data_lines(lz4_block(show(f"{base}.tsv.lz4")).decode()):
        f = line.split("\t")
        if f[0] in schema:
            note(
                f"config-param-schema {f[1]}",
                (schema[f[0]]["effects"]["outcome"] == "accepted") == (f[8] == "1"),
            )
    for column, (agree, disagree) in sorted(report.items()):
        print(f"{column}: {agree} agree, {disagree} disagree")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    contexts = sub.add_parser("contexts")
    contexts.add_argument("--out-dir", type=Path, required=True)
    contexts.add_argument("--rtos-git", type=Path)
    contexts.add_argument("--rtos-commit", default="42b39d44")
    contexts.add_argument("--replay", type=Path)
    create = sub.add_parser("create")
    create.add_argument("--reference", type=Path, required=True)
    create.add_argument("--contexts-dir", type=Path, required=True)
    create.add_argument("--vectors", type=Path, required=True)
    create.add_argument(
        "--allow-dirty", action="store_true", help="trial fills only, never committed"
    )
    check = sub.add_parser("check")
    check.add_argument("--vectors", type=Path, required=True)
    check.add_argument("--varuint-driver", type=Path, required=True)
    check.add_argument("--gas-driver", type=Path, required=True)
    check.add_argument("--storage-encoding-driver", type=Path, required=True)
    check.add_argument("--tl-driver", type=Path, required=True)
    check.add_argument("--work-dir", type=Path, required=True)
    compare = sub.add_parser("rtos-compare")
    compare.add_argument("--vectors", type=Path, required=True)
    compare.add_argument("--rtos-git", type=Path, required=True)
    compare.add_argument("--rtos-commit", default="42b39d44")
    args = parser.parse_args(argv)
    if args.command == "contexts":
        return command_contexts(args)
    if args.command == "create":
        return command_create(args)
    if args.command == "check":
        return command_check(args)
    return rtos_compare(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
