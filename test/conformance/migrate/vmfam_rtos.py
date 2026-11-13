#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Convert the RTOS VM test families (vm/tests/data of the RTOS tree) into vm-harness contexts.

Only the contexts are taken from RTOS; the effects are filled from the C++ reference by
``conformance.py create``. Each family is converted the way its RTOS test builds the VM:

    vmfam_rtos.py build-asm <rtos-tree> <cargo-target-dir>
        Build the code-cell builder (vmfam_rtos_asm.rs) against an RTOS source tree, as a workspace
        member added to that tree; prints the binary path.
    vmfam_rtos.py contexts <family> <out.jsonl> --data <file> [--asm <builder>]
        --data is the family's data file, or for the families marked "export" below the JSON a
        test writes with its export variable set (it carries each case's code cell as the test
        built it). The builder is needed by the families that assemble code.
    vmfam_rtos.py agree <family> <fixtures.jsonl> --data <file>
        Diagnostic only: how many C++-filled fixtures agree with the RTOS file's own recorded
        values on exit code, gas and (where recorded) steps and committed. Those values were
        filled by older C++ builds; a difference is not a fixture error, but wide disagreement
        means the context was converted wrongly.

Families (RTOS test, data, VM set-up):

    opcode-gates        test_opcode_gates.rs, export RTOS_OPCODE_GATES_EXPORT; c7 = (), gas
                        limit = case gas, max = 10^9 (Gas::test_with_limit), empty stack
    opcode-stack        test_opcode_stack.rs, export RTOS_OPCODE_STACK_EXPORT; as opcode-gates
    continuation-save   test_continuation_save.rs, export RTOS_CONTINUATION_SAVE_EXPORT; as
                        opcode-gates, initial_stack zeros
    continuation-chain  test_continuation_chains.rs, export RTOS_CONT_CHAIN_EXPORT; as
                        opcode-gates
    bchk                test_bchk_parity.rs, export RTOS_BCHK_EXPORT; as opcode-gates
    library-budget      test_library_budget.rs, export RTOS_LIBRARY_BUDGET_EXPORT; no c7, the
                        inputs as cells, one library collection {a, b}; the cases without a
                        library load limit
    library-budget-limits  the same export, the cases with a load limit, as max_library_loads
    poseidon2           test_poseidon2.rs, export RTOS_POSEIDON_EXPORT; no c7, the inputs, the
                        case's library collection when it has one
    sendmsg             test_sendmsg_parity.rs, export RTOS_SENDMSG_EXPORT; c7 = (info) built from
                        the exported address, prices, limits and context name; stack message,
                        mode; cases whose context integer does not fit 257 signed bits are not
                        converted
    decode-matrix       test_decode_reference.rs, data decode-matrix-cases.json; code_cell(source)
                        (builder), c7 = (), gas limit = max = case gas
    decode-vectors      test_decode_reference.rs, data decode-vectors.json; as decode-matrix
    pq-falcon512        test_pq_falcon512.rs, data pq-falcon512.json; no c7, operands repeated,
    pq-suite            test_pq_suite.rs, data pq-suite.json;            code the opcode repeated
    pq-mldsa44          test_pq_mldsa44.rs, data pq-mldsa44.json;        with DROP between, or the
    lms-fee             test_lms_fee.rs, data lms-fee.json;              compiled program entered
                                                                         with 0 on top; the cases
                                                                         with ignore = false
    pq-chksig           the ignore = true cases of those four, --data the RTOS vm/tests/data
                        directory, ids <family>/<case>, chksig_always_succeed = true
    sha256c             test_sha256c.rs, data sha256c.json; no c7, the cell repeated, SHA256C
                        repeated with DROP between, the case's library collection
    short-code          test_cont.rs short_code_matches_reference, data short-code.tsv; c7 = (),
                        integers 1..n, the code bits

opcode-activation is not converted: its cases are a strict subset of opcode-gates.
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))

from cells import (  # noqa: E402  # pyright: ignore[reportMissingImports, reportUnknownVariableType]
    Cell,
    from_boc,
)

Json = dict[str, Any]
TEST_GAS_MAX = 1_000_000_000  # Gas::test_with_limit: the row's limit under the test maximum
INT257_MIN, INT257_MAX = -(1 << 256), (1 << 256) - 1
MAX_REPEATS = 12
EMPTY_TUPLE: Json = {"type": "tuple", "items": []}
OPCODES = {
    "pq-falcon512": "PQCHECKSIG_FALCON512_PADDED",
    "pq-suite": "PQCHECKSIG_SUITE",
    "pq-mldsa44": "PQCHECKSIG_MLDSA44",
    "lms-fee": "LMSCHECKFEEHASH",
}


class NotConvertible(Exception):
    pass


def b64(hex_text: str) -> str:
    return base64.b64encode(bytes.fromhex(hex_text)).decode("ascii")


def cell_b64(cell: Any) -> str:
    return base64.b64encode(cast(bytes, cell.boc())).decode("ascii")


def int_item(value: int) -> Json:
    if not INT257_MIN <= value <= INT257_MAX:
        raise NotConvertible(f"integer {value} does not fit 257 signed bits")
    return {"type": "int", "value": str(value)}


def cell_item(hex_text: str) -> Json:
    return {"type": "cell", "boc": b64(hex_text)}


def slice_of(cell: Any) -> Json:
    return {"type": "slice", "boc": cell_b64(cell)}


def tuple_of(items: Sequence[Json]) -> Json:
    return {"type": "tuple", "items": list(items)}


NULL: Json = {"type": "null"}
NAN: Json = {"type": "nan"}
EMPTY_SLICE: Json = {"type": "slice", "boc": base64.b64encode(Cell().boc()).decode("ascii")}


def context(
    code_b64: str,
    version: int,
    limit: int,
    gas_max: int,
    stack: Sequence[Json] = (),
    c7: Json | None = None,
    libraries: str | None = None,
) -> Json:
    out: Json = {
        "code": code_b64,
        "global_version": version,
        "gas": {"limit": limit, "max": gas_max},
        "stack": list(stack),
    }
    if c7 is not None:
        out["c7"] = c7
    if libraries is not None:
        out["libraries"] = [libraries]
    return out


# ---------------------------------------------------------------------------------------------
# The code-cell builder


class Builder:
    """Batch client of vmfam_rtos_asm.rs: requests are queued, then sent in one run."""

    def __init__(self, program: Path | None) -> None:
        self.program = program
        self.requests: list[str] = []
        self.index: dict[str, int] = {}
        self.results: list[str | None] = []

    def ask(self, request: Json) -> int:
        line = json.dumps(request, sort_keys=True, separators=(",", ":"))
        if line not in self.index:
            self.index[line] = len(self.requests)
            self.requests.append(line)
        return self.index[line]

    def run(self) -> None:
        if not self.requests:
            return
        if self.program is None:
            raise SystemExit("this family assembles code: --asm <vmfam-asm binary> required")
        done = subprocess.run(
            [str(self.program)],
            input="".join(r + "\n" for r in self.requests),
            capture_output=True,
            text=True,
            timeout=3600,
            check=False,
        )
        if done.returncode != 0:
            raise SystemExit(f"{self.program}: exit {done.returncode}: {done.stderr[-2000:]}")
        lines = done.stdout.splitlines()
        if len(lines) != len(self.requests):
            raise SystemExit(f"{self.program}: {len(lines)} responses for {len(self.requests)}")
        for request, line in zip(self.requests, lines, strict=True):
            response = json.loads(line)
            if "error" in response:
                raise SystemExit(f"builder refused {request}: {response['error']}")
            self.results.append(response["boc"])

    def boc(self, index: int) -> str | None:
        return self.results[index]

    def code(self, index: int) -> str:
        value = self.results[index]
        if value is None:
            raise SystemExit("builder returned no cell")
        return b64(value)


@dataclass
class Result:
    entries: list[Json] = field(default_factory=lambda: [])
    skipped: list[tuple[str, str]] = field(default_factory=lambda: [])


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


# ---------------------------------------------------------------------------------------------
# Families from test exports (code cells as the test built them)


def exported_rows(path: Path) -> list[Json]:
    rows = load_json(path)
    if not isinstance(rows, list) or not rows:
        raise SystemExit(f"{path}: a non-empty export list required")
    return cast(list[Json], rows)


def simple_export(path: Path, _: Builder) -> Result:
    """opcode-gates, opcode-stack, continuation-chain, bchk: c7 = (), no stack."""
    out = Result()
    for row in exported_rows(path):
        ctx = context(
            b64(row["code"]), int(row["version"]), int(row["gas"]), TEST_GAS_MAX, c7=EMPTY_TUPLE
        )
        out.entries.append({"fixture_id": row["name"], "context": ctx})
    return out


def continuation_save(path: Path, _: Builder) -> Result:
    out = Result()
    for row in exported_rows(path):
        stack = [int_item(0) for _ in range(int(row["initial_stack"]))]
        ctx = context(
            b64(row["code"]),
            int(row["version"]),
            int(row["gas"]),
            TEST_GAS_MAX,
            stack,
            EMPTY_TUPLE,
        )
        out.entries.append({"fixture_id": row["name"], "context": ctx})
    return out


def limit_id(name: str) -> str:
    """A fixture id for a library-budget case name: ``limitSome(2)`` becomes ``limitSome-2``."""
    return name.replace("(", "-").replace(")", "")


def library_budget(path: Path, builder: Builder, limits: bool = False) -> Result:
    """The cases without a library load limit, or with ``limits`` only those with one, which
    run with max_library_loads (rtos-library-budget-limits)."""
    out = Result()
    rows = exported_rows(path)
    pending: list[tuple[Json, int]] = []
    for row in rows:
        if (row["limit"] is not None) != limits:
            if not limits:
                out.skipped.append((row["name"], "library load limit: in library-budget-limits"))
            continue
        pending.append((row, builder.ask({"op": "libdict", "cells": row["libraries"]})))
    builder.run()
    for row, index in pending:
        libraries = builder.boc(index)
        ctx = context(
            b64(row["code"]),
            int(row["version"]),
            1_000_000,
            TEST_GAS_MAX,
            [cell_item(x) for x in row["inputs"]],
            libraries=None if libraries is None else b64(libraries),
        )
        if limits:
            limit = int(row["limit"])
            if not 0 <= limit <= 0xFFFFFFFF:
                raise SystemExit(f"{row['name']}: limit outside 32 bits")
            ctx["max_library_loads"] = limit
        out.entries.append({"fixture_id": limit_id(row["name"]), "context": ctx})
    return out


def poseidon_input(text: str) -> Json:
    if text.startswith("i:"):
        return int_item(int(text[2:]))
    if text.startswith("c:"):
        return cell_item(text[2:])
    simple = {"nan": NAN, "null": NULL, "tuple": EMPTY_TUPLE, "slice": EMPTY_SLICE}
    if text not in simple:
        raise SystemExit(f"unknown poseidon2 input {text!r}")
    return simple[text]


def poseidon2(path: Path, builder: Builder) -> Result:
    out = Result()
    pending: list[tuple[Json, int | None]] = []
    for row in exported_rows(path):
        libs = row["libraries"]
        pending.append((row, builder.ask({"op": "libdict", "cells": libs}) if libs else None))
    builder.run()
    for row, index in pending:
        libraries = None if index is None else builder.boc(index)
        try:
            stack = [poseidon_input(x) for x in row["inputs"]]
        except NotConvertible as exc:
            out.skipped.append((row["name"], str(exc)))
            continue
        ctx = context(
            b64(row["code"]),
            int(row["version"]),
            int(row["gas"]),
            TEST_GAS_MAX,
            stack,
            libraries=None if libraries is None else b64(libraries),
        )
        out.entries.append({"fixture_id": row["name"], "context": ctx})
    return out


# sendmsg: the c7 test_sendmsg_parity.rs builds for each context name.


def bits_cell(n: int) -> Any:
    """bits(n) of the test: n bits of the byte 0x55 repeated."""
    pattern = ("01010101" * ((n + 7) // 8))[:n]
    return Cell(pattern)


def myaddr_cell(kind: str, addr: Any) -> Any:
    b = Cell()
    if kind == "empty":
        pass
    elif kind == "one-bit":
        b.uint(1, 1)
    elif kind == "external":
        b.uint(0, 2)
    elif kind == "std-short":
        b.uint(4, 3)
    elif kind in ("std-prefix", "std-mc-prefix"):
        b.uint(4, 3).uint(255 if kind == "std-mc-prefix" else 0, 8)
    elif kind == "var-prefix":
        b.uint(6, 3).uint(1, 9).sint(-1, 32)
    elif kind in ("anycast-zero", "anycast-max"):
        b.uint(5, 3).uint(31 if kind == "anycast-max" else 0, 5).uint(0, 8)
    elif kind in ("std-extra", "std-ref"):
        b = Cell(addr.bits, list(addr.refs))
        if kind == "std-extra":
            b.uint(0, 8)
        else:
            b.ref(Cell())
    else:
        raise SystemExit(f"unknown myaddr context {kind}")
    return b


def balance_item(kind: str) -> Json:
    if kind == "null":
        return NULL
    if kind == "empty":
        return EMPTY_TUPLE
    values: dict[str, Callable[[], Json]] = {
        "value-null": lambda: NULL,
        "negative": lambda: int_item(-1),
        "nan": lambda: NAN,
        "max": lambda: int_item((1 << 256) - 1),
        "max-safe": lambda: int_item((1 << 256) - 10000001),
        "max-over": lambda: int_item((1 << 256) - 10000000),
        "wide": lambda: int_item(1 << 256),
    }
    if kind not in values:
        raise SystemExit(f"unknown balance context {kind}")
    return tuple_of([values[kind](), NULL])


def sendmsg_c7(row: Json) -> Json:
    name = cast(str, row["context"])
    prices = slice_of(from_boc(bytes.fromhex(row["prices"])))
    limits = slice_of(from_boc(bytes.fromhex(row["limits"])))
    addr = from_boc(bytes.fromhex(row["address"]))
    conf: list[Json] = [NULL] * 7
    conf[4] = prices
    conf[5] = prices
    conf[6] = limits
    info: list[Json] = [NULL] * 18
    info[7] = tuple_of([int_item(1000000000), NULL])
    info[8] = slice_of(addr)
    info[11] = info[7]
    if name.startswith(("prices-", "limits-")):
        changed = list(conf)
        tag = slice_of(bits_cell(8))
        replacements: dict[str, dict[int, Json]] = {
            "prices-null": {4: NULL, 5: NULL},
            "prices-int": {4: int_item(1), 5: int_item(1)},
            "prices-tag": {4: tag, 5: tag},
            "limits-tag": {6: tag},
            "prices-bad": {4: EMPTY_SLICE, 5: EMPTY_SLICE},
            "limits-int": {6: int_item(1)},
            "limits-bad": {6: EMPTY_SLICE},
        }
        if name == "limits-short":
            changed = changed[:6]
        elif name in replacements:
            for index, value in replacements[name].items():
                changed[index] = value
        else:
            raise SystemExit(f"unknown sendmsg context {name}")
        conf = changed
    if name.startswith(("balance-", "incoming-")):
        index = 7 if name.startswith("balance-") else 11
        info[index] = balance_item(name.split("-", 1)[1])
    if name.startswith("myaddr-"):
        kind = name[len("myaddr-") :]
        if kind == "int":
            info[8] = int_item(0)
        else:
            info[8] = slice_of(myaddr_cell(kind, addr))
            if kind in ("std-mc-prefix", "var-prefix"):
                conf = list(conf)
                conf[5] = NULL
    if name.startswith("legacy-extra-"):
        kind = name[len("legacy-extra-") :]
        extras = {
            "int": int_item(1),
            "slice": EMPTY_SLICE,
            "tuple": EMPTY_TUPLE,
            "cell": {"type": "cell", "boc": cell_b64(Cell())},
        }
        if kind not in extras:
            raise SystemExit(f"unknown sendmsg context {name}")
        info[7] = tuple_of([int_item(1000000000), extras[kind]])
        info[11] = info[7]
    info[14] = tuple_of(conf)
    known = name == "normal" or name.startswith(
        ("prices-", "limits-", "balance-", "incoming-", "myaddr-", "legacy-extra-")
    )
    if not known:
        raise SystemExit(f"unknown sendmsg context {name}")
    return tuple_of([tuple_of(info)])


def sendmsg(path: Path, _: Builder) -> Result:
    out = Result()
    for row in exported_rows(path):
        try:
            c7 = sendmsg_c7(row)
        except NotConvertible as exc:
            out.skipped.append((row["name"], str(exc)))
            continue
        stack = [cell_item(row["message"]), int_item(int(row["mode"]))]
        ctx = context(
            b64(row["code"]), int(row["version"]), int(row["gas"]), TEST_GAS_MAX, stack, c7
        )
        out.entries.append({"fixture_id": row["name"], "context": ctx})
    return out


# ---------------------------------------------------------------------------------------------
# Families from data files


def decode_cases(cases: Iterable[Json]) -> list[tuple[str, int, int, str]]:
    sources: dict[str, tuple[int, str]] = {}
    out: list[tuple[str, int, int, str]] = []
    for case in cases:
        name = case["name"]
        if "of" in case:
            version, source = sources[case["of"]]
        else:
            version, source = int(case["version"]), case["source"]
        sources[name] = (version, source)
        out.append((name, version, int(case["gas"]), source))
    return out


def decode(path: Path, builder: Builder) -> Result:
    out = Result()
    pending = [
        (name, version, gas, builder.ask({"op": "code_cell", "src": source}))
        for name, version, gas, source in decode_cases(load_json(path))
    ]
    builder.run()
    for name, version, gas, index in pending:
        # GasSetup::LimitIsMax: limit and maximum both the case's gas.
        ctx = context(builder.code(index), version, gas, gas, c7=EMPTY_TUPLE)
        out.entries.append({"fixture_id": name, "context": ctx})
    return out


def pq_operand(operand: Any, cells: Sequence[str], family: str) -> Json | None:
    if isinstance(operand, int) and not isinstance(operand, bool):
        return cell_item(cells[operand])
    if operand == "skip":
        return None
    if operand == "int" and family in ("pq-falcon512", "pq-mldsa44"):
        return int_item(1)
    if (
        isinstance(operand, str)
        and operand.startswith("int:")
        and family in ("pq-suite", "lms-fee")
    ):
        return int_item(int(operand[4:]))
    simple = {"nan": NAN, "null": NULL, "tuple": EMPTY_TUPLE, "slice": EMPTY_SLICE}
    allowed = {"pq-suite": {"nan"}, "lms-fee": {"nan", "null", "tuple", "slice"}}
    if isinstance(operand, str) and operand in allowed.get(family, set()):
        return simple[operand]
    raise SystemExit(f"{family}: unknown operand {operand!r}")


def pq_family(family: str, ignored: bool = False) -> Callable[[Path, Builder], Result]:
    """The cases with ignore = false, or with ``ignored`` only those with ignore = true, which run
    with chksig_always_succeed (rtos-pq-chksig)."""
    opcode = OPCODES[family]

    def convert(path: Path, builder: Builder) -> Result:
        data = load_json(path)
        cells = cast(list[str], data["cells"])
        out = Result()
        pending: list[tuple[Json, list[Json], str | int]] = []
        program_index = builder.ask({"op": "compile", "src": f"DROP {opcode}"})
        for case in data["cases"]:
            name = case["name"]
            if bool(case["ignore"]) != ignored:
                if not ignored:
                    out.skipped.append((name, "ignore = true: in rtos-pq-chksig"))
                continue
            repeats = int(case["repeats"])
            if not 1 <= repeats <= MAX_REPEATS:
                raise SystemExit(f"{name}: repeats outside 1..{MAX_REPEATS}")
            try:
                stack = [
                    item
                    for _ in range(repeats)
                    for item in (pq_operand(op, cells, family) for op in case["operands"])
                    if item is not None
                ]
            except NotConvertible as exc:
                out.skipped.append((name, str(exc)))
                continue
            if case["program"] is not None:
                # The test asserts that the compiled program equals this cell.
                stack.append(int_item(0))
                code: str | int = b64(cells[int(case["program"])])
            else:
                code = builder.ask({"op": "compile", "src": " DROP ".join([opcode] * repeats)})
            pending.append((case, stack, code))
        builder.run()
        compiled = builder.boc(program_index)
        for case, stack, code in pending:
            if case["program"] is not None and cells[int(case["program"])] != compiled:
                raise SystemExit(f"{case['name']}: the program cell is not DROP {opcode}")
            code_b64 = code if isinstance(code, str) else builder.code(code)
            ctx = context(code_b64, int(case["version"]), int(case["gas"]), TEST_GAS_MAX, stack)
            if ignored:
                ctx["chksig_always_succeed"] = True
            out.entries.append({"fixture_id": case["name"], "context": ctx})
        return out

    return convert


def pq_chksig(directory: Path, builder: Builder) -> Result:
    """rtos-pq-chksig: the ignore = true cases of the four PQ families, from the RTOS data
    directory; each id is ``<family>/<case>``."""
    out = Result()
    for family in sorted(OPCODES):
        part = pq_family(family, ignored=True)(
            directory / f"{family}.json", Builder(builder.program)
        )
        for entry in part.entries:
            out.entries.append({**entry, "fixture_id": f"{family}/{entry['fixture_id']}"})
        out.skipped.extend((f"{family}/{name}", reason) for name, reason in part.skipped)
    return out


def sha256c(path: Path, builder: Builder) -> Result:
    out = Result()
    pending: list[tuple[Json, list[Json], int, int | None]] = []
    for case in load_json(path):
        repeats = int(case["repeats"])
        if not 1 <= repeats <= MAX_REPEATS:
            raise SystemExit(f"{case['name']}: repeats outside 1..{MAX_REPEATS}")
        value = case["cell"]
        item = None if value == "skip" else int_item(1) if value == "int" else cell_item(value)
        stack = [item for _ in range(repeats) if item is not None]
        code = builder.ask({"op": "compile", "src": " DROP ".join(["SHA256C"] * repeats)})
        libs = builder.ask({"op": "libdict", "cells": case["libs"]}) if case["libs"] else None
        pending.append((case, stack, code, libs))
    builder.run()
    for case, stack, code, libs in pending:
        libraries = None if libs is None else builder.boc(libs)
        ctx = context(
            builder.code(code),
            int(case["version"]),
            int(case["gas"]),
            TEST_GAS_MAX,
            stack,
            libraries=None if libraries is None else b64(libraries),
        )
        out.entries.append({"fixture_id": case["name"], "context": ctx})
    return out


def short_code(path: Path, _: Builder) -> Result:
    out = Result()
    for line in path.read_text().splitlines():
        if line.startswith("#"):
            continue
        f = line.split("\t")
        if len(f) != 9:
            raise SystemExit(f"{path}: 9 columns required: {line[:80]}")
        bits, data = int(f[4]), bytes.fromhex(f[5])
        if len(data) != (bits + 7) // 8:
            raise SystemExit(f"{f[0]}: code length")
        pattern = "".join(f"{byte:08b}" for byte in data)
        if set(pattern[bits:]) - {"0"}:
            raise SystemExit(f"{f[0]}: nonzero padding")
        code = cell_b64(Cell(pattern[:bits]))
        stack = [int_item(i) for i in range(1, int(f[3]) + 1)]
        ctx = context(code, int(f[1]), int(f[2]), TEST_GAS_MAX, stack, EMPTY_TUPLE)
        out.entries.append({"fixture_id": f[0], "context": ctx})
    return out


CONVERTERS: dict[str, Callable[[Path, Builder], Result]] = {
    "opcode-gates": simple_export,
    "opcode-stack": simple_export,
    "continuation-save": continuation_save,
    "continuation-chain": simple_export,
    "bchk": simple_export,
    "library-budget": library_budget,
    "library-budget-limits": lambda path, builder: library_budget(path, builder, limits=True),
    "pq-chksig": pq_chksig,
    "poseidon2": poseidon2,
    "sendmsg": sendmsg,
    "decode-matrix": decode,
    "decode-vectors": decode,
    "pq-falcon512": pq_family("pq-falcon512"),
    "pq-suite": pq_family("pq-suite"),
    "pq-mldsa44": pq_family("pq-mldsa44"),
    "lms-fee": pq_family("lms-fee"),
    "sha256c": sha256c,
    "short-code": short_code,
}


# ---------------------------------------------------------------------------------------------
# Diagnostic agreement with the values recorded in the RTOS files


# Positions of exit, gas, steps and committed in the arrays the RTOS expectation maps hold.
RECORDED_POSITIONS: dict[str, dict[str, int]] = {
    "opcode-gates": {"exit": 0, "gas": 1, "committed": 3, "steps": 4},
    "opcode-stack": {"exit": 0, "gas": 1, "committed": 3, "steps": 4},
    "continuation-save": {"exit": 0, "gas": 1, "committed": 3, "steps": 4},
    "bchk": {"exit": 0, "gas": 1, "committed": 3, "steps": 4},
    "sendmsg": {"exit": 0, "gas": 1, "committed": 3, "steps": 4},
    "library-budget": {"exit": 0, "gas": 1, "committed": 3},
    "library-budget-limits": {"exit": 0, "gas": 1, "committed": 3},
    "poseidon2": {"exit": 0, "gas": 1, "committed": 3, "steps": 4},
    "continuation-chain": {"exit": 0, "gas": 1, "steps": 2, "committed": 3},
    "decode-matrix": {"exit": 0, "gas": 1, "steps": 2, "committed": 3},
}


def recorded(family: str, data: Path) -> dict[str, dict[str, Any]]:
    """Exit, gas and, where recorded, steps and committed, per case name.

    ``data`` is the family's expectation file: the name-keyed map (opcode-gates.json, ...,
    decode-matrix.json), or the case file for the families that keep expectations inline.
    """
    out: dict[str, dict[str, Any]] = {}
    if family == "pq-chksig":
        for part in sorted(OPCODES):
            for name, entry in recorded(part, data / f"{part}.json").items():
                out[f"{part}/{name}"] = entry
        return out
    if family == "short-code":
        for line in data.read_text().splitlines():
            if not line.startswith("#"):
                f = line.split("\t")
                out[f[0]] = {"exit": int(f[6]), "gas": int(f[7]), "steps": int(f[8])}
        return out
    value = load_json(data)
    if family in RECORDED_POSITIONS:
        positions = RECORDED_POSITIONS[family]
        for name, e in cast(Json, value).items():
            key = limit_id(name) if family == "library-budget-limits" else name
            out[key] = {k: (bool(e[i]) if k == "committed" else e[i]) for k, i in positions.items()}
    elif family == "decode-vectors":
        for row in cast(list[Json], value):
            e = row["expected"]
            out[row["name"]] = {k: e[k] for k in ("exit", "gas", "steps", "committed")}
    elif family in OPCODES:
        for case in cast(Json, value)["cases"]:
            e = case["expected"]
            entry = {"exit": e[0], "gas": e[1], "committed": bool(e[3])}
            if len(e) == 7:
                entry["steps"] = e[6]
            out[case["name"]] = entry
    elif family == "sha256c":
        for case in cast(list[Json], value):
            e = case["expected"]
            out[case["name"]] = {"exit": e[0], "gas": e[1], "committed": bool(e[3])}
    return out


def agree(family: str, fixtures_path: Path, data: Path) -> int:
    expected = recorded(family, data)
    fixtures = [json.loads(line) for line in fixtures_path.read_text().splitlines()]
    same = differ = absent = 0
    examples: list[str] = []
    for fixture in fixtures:
        name = fixture["metadata"]["fixture_id"]
        if name not in expected:
            absent += 1
            continue
        e = fixture["effects"]
        actual = {
            "exit": e["exit_code"],
            "gas": e["gas_used"],
            "steps": e["steps"],
            "committed": e["committed"],
        }
        want = expected[name]
        if all(actual[k] == v for k, v in want.items()):
            same += 1
        else:
            differ += 1
            if len(examples) < 5:
                examples.append(f"  {name}: rtos {want} c++ {actual}")
    fields = sorted({k for v in expected.values() for k in v})
    print(
        f"{family}: {len(fixtures)} fixtures; equal to the RTOS-recorded {'/'.join(fields)} for "
        f"{same}, different for {differ}, not recorded for {absent}"
    )
    for line in examples:
        print(line)
    return 0


# ---------------------------------------------------------------------------------------------


def build_asm(tree: Path, target: Path) -> int:
    crate = tree / "vmfam-asm"
    (crate / "src").mkdir(parents=True, exist_ok=True)
    (crate / "src/main.rs").write_text((HERE / "vmfam_rtos_asm.rs").read_text())
    (crate / "Cargo.toml").write_text(
        "[package]\nname = 'vmfam-asm'\nversion = '0.1.0'\nedition = '2021'\npublish = false\n\n"
        "[dependencies]\nhex = '0.4'\nserde_json = '1.0'\n"
        "rtos_assembler = { path = '../assembler' }\nrtos_block = { path = '../block' }\n"
    )
    manifest = tree / "Cargo.toml"
    text = manifest.read_text()
    if "'vmfam-asm'" not in text:
        if "    'vm',\n" not in text:
            raise SystemExit(f"{manifest}: workspace member list not recognised")
        manifest.write_text(text.replace("    'vm',\n", "    'vm',\n    'vmfam-asm',\n", 1))
    subprocess.run(
        ["cargo", "build", "--release", "-p", "vmfam-asm", "--target-dir", str(target)],
        cwd=tree,
        check=True,
    )
    print(target / "release/vmfam-asm")
    return 0


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build-asm")
    build.add_argument("tree", type=Path)
    build.add_argument("target", type=Path)
    contexts = sub.add_parser("contexts")
    contexts.add_argument("family", choices=sorted(CONVERTERS))
    contexts.add_argument("out", type=Path)
    contexts.add_argument("--data", type=Path, required=True)
    contexts.add_argument("--asm", type=Path)
    agreement = sub.add_parser("agree")
    agreement.add_argument("family", choices=sorted(CONVERTERS))
    agreement.add_argument("fixtures", type=Path)
    agreement.add_argument("--data", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "build-asm":
        return build_asm(args.tree, args.target)
    if args.command == "agree":
        return agree(args.family, args.fixtures, args.data)
    result = CONVERTERS[args.family](args.data, Builder(args.asm))
    ids = [e["fixture_id"] for e in result.entries]
    if len(set(ids)) != len(ids):
        raise SystemExit("duplicate fixture ids")
    args.out.write_text(
        "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in result.entries)
    )
    print(f"{args.family}: {len(result.entries)} contexts, {len(result.skipped)} not converted")
    reasons: dict[str, int] = {}
    for _, reason in result.skipped:
        reasons[reason] = reasons.get(reason, 0) + 1
    for reason, count in sorted(reasons.items()):
        print(f"  not converted: {count} ({reason})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
