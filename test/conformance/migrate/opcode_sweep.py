#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Contexts that run every assigned codepage-0 instruction of global version 16 on several stack shapes.

    opcode_sweep.py contexts <opcode table> <contexts.jsonl>

The opcode table is the output of test-vm-opcode-table (first opcode as 24-bit hex, assigned, prefix bits,
first global version). For every assigned range active at version 16 the first, middle and last opcode of the
range are taken; each is followed by zero argument bytes and one referenced cell, and run on stack shapes
chosen so that most instructions get past their underflow and type checks: integers, cells and slices, a
tuple, null, dictionary arguments, and a full c7. Expected effects come from the C++ reference (create).
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

VERSION = 16
GAS = 100000
TOP = 1 << 24


def boc(root_bytes: bytes, child_bytes: bytes | None) -> str:
    """A bag of cells: a root with whole bytes of data and at most one referenced child."""
    cells = [(root_bytes, [1] if child_bytes is not None else [])]
    if child_bytes is not None:
        cells.append((child_bytes, []))
    body = b""
    for data, refs in cells:
        body += bytes([len(refs), 2 * len(data)]) + data + bytes(refs)
    header = bytes.fromhex("b5ee9c72") + bytes([1, 1, len(cells), 1, 0, len(body), 0])
    return base64.b64encode(header + body).decode("ascii")


def item_int(v: int) -> dict[str, Any]:
    return {"type": "int", "value": str(v)}


CELL = {"type": "cell", "boc": boc(b"\xab\xcd\xef\x01", b"\x55")}
SLICE = {"type": "slice", "boc": boc(b"\x80\x00\x00\x00\x00\x00\x00\x00\x10\x20", None)}
KEY = {"type": "slice", "boc": boc(b"\x00\x00\x00\x05", None)}
NULL = {"type": "null"}


def tuple_of(*items: dict[str, Any]) -> dict[str, Any]:
    return {"type": "tuple", "items": list(items)}


# A c7 shaped like a transaction's: magic, actions, messages, time, block and transaction lt, rand seed,
# balance, address, config, code, incoming value, storage fees, previous blocks, ... (nulls where unknown).
PARAMS = tuple_of(
    item_int(0x076EF1EA),
    item_int(0),
    item_int(0),
    item_int(1700000000),
    item_int(1000000),
    item_int(1000001),
    item_int(123456789),
    tuple_of(item_int(1000000000), NULL),
    SLICE,
    NULL,
    CELL,
    tuple_of(item_int(0), NULL),
    item_int(0),
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
)
C7 = tuple_of(PARAMS)

SHAPES: dict[str, list[dict[str, Any]]] = {
    "ints": [item_int(7), item_int(3), item_int(2), item_int(1)],
    "cells": [CELL, SLICE, item_int(8)],
    "tuple": [tuple_of(item_int(1), item_int(2), item_int(3)), item_int(1), item_int(2)],
    "null": [NULL, item_int(0)],
    "dict": [SLICE, KEY, NULL, item_int(32)],
    "c7": [item_int(5), item_int(1)],
}


def ranges(table: Path) -> list[tuple[int, int, int]]:
    """(first, end, bits) of every assigned range active at VERSION."""
    rows = []
    for line in table.read_text().splitlines():
        first, assigned, bits, version = line.split("\t")
        rows.append((int(first, 16), assigned == "1", int(bits), int(version)))
    out = []
    for i, (first, assigned, bits, version) in enumerate(rows):
        end = rows[i + 1][0] if i + 1 < len(rows) else TOP
        if assigned and version <= VERSION and first < end:
            out.append((first, end, bits))
    if not out:
        raise SystemExit(f"{table}: no assigned ranges")
    return out


def opcodes(first: int, end: int) -> list[int]:
    picks = sorted({first, first + (end - first) // 2, end - 1})
    return [p for p in picks if first <= p < end]


def contexts(table: Path) -> list[dict[str, Any]]:
    out = []
    for first, end, bits in ranges(table):
        for op in opcodes(first, end):
            code = boc(op.to_bytes(3, "big") + bytes(16), b"\x00\x01")
            for shape, stack in SHAPES.items():
                ctx: dict[str, Any] = {
                    "code": code,
                    "global_version": VERSION,
                    "gas": {"limit": GAS, "max": GAS},
                    "stack": stack,
                }
                if shape == "c7":
                    ctx["c7"] = C7
                out.append({"fixture_id": f"op{op:06x}-p{bits}-{shape}", "context": ctx})
    return out


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "contexts":
        entries = contexts(Path(argv[1]))
        Path(argv[2]).write_text(
            "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in entries)
        )
        print(f"{len(entries)} contexts")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
