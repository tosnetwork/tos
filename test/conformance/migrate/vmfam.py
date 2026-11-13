#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Migrate the tos-side VM scenario families to vm-harness contexts and cross-check them.

    vmfam.py contexts <family> <contexts.jsonl> [--input PATH]
        Write the family's contexts (one {"fixture_id", "context"[, "note"]} per line), ready for
        ``conformance.py create``. --input is the opcode table for vm-prefix (test-vm-opcode-table
        output) and the generated scenario file for pq-v16-parity, pq-falcon512-parity and
        native-cost; the other families are generated here from their scenario scripts or read
        from the scenario file committed beside them.
    vmfam.py check <family> <fixtures.jsonl> <driver-output>
        Require every fixture's effects to equal the original C++ driver's output row for the same
        id, on every field that driver reports, with 0 differences. Driver rows are matched by id
        (the driver may have run more rows, as test-vm-endstate on the whole vm_prefix_scenarios.py
        output does); every fixture must find its row. --rename OLD=NEW maps driver ids first.
    vmfam.py project <family> <fixtures.jsonl> <out.tsv>
        Write the fixtures' effects in that family's driver output format, so that a family's
        authored checker (vm_varuint_scenarios.py --check, vm_library_scenarios.py --check-native,
        vm_sha256c_scenarios.py, vm_datasize_scenarios.py) runs on the frozen effects.
    vmfam.py crosscheck <build-dir> <fixtures-dir> <scratch-dir>
        For every family whose scenarios are generated deterministically in this tree (vm-prefix,
        vm-ext, vm-family, vm-closure-fuzz, vm-varuint, vm-library, pq-suite-parity, pq-version):
        regenerate the contexts and require them to equal the frozen ones, run the original C++
        driver on the same scenarios and require 0 differences (``check``). vm-prefix, vm-ext and
        vm-family are checked against one run of test-vm-endstate on the whole
        vm_prefix_scenarios.py output, whose rows they partition with vm-closure-fuzz.
    vmfam.py authored <fixtures-dir> <scratch-dir>
        Run the authored checkers on the frozen effects: vm_varuint_scenarios.py --check on
        vm-varuint, vm_library_scenarios.py --check-native on vm-library, and
        vm_sha256c_scenarios.py and vm_datasize_scenarios.py on vm-endstate (which holds those rows).
    vmfam.py tamper-control <target> <fixtures-dir> <scratch-dir> <family> ...
        Red control of the frozen families: for each family, copy it, add 1 to the gas of its first
        fixture and require ``conformance.py run`` against the target to fail with exactly that
        fixture mismatched; the untampered copy must pass.
    vmfam.py families
        List the families with the driver each is checked against.

Formats, as each driver reads them:

- endstate (test-vm-endstate): id, version, budget, label, top, four lower values, code BOC; gas
  limit = max = budget; output id exit gas steps committed c4 c5 stack.
- suite (test-pq-suite-parity): id, version, budget, expect, suite, message, context, signature,
  public key[, code BOC]; operands pushed bottom first (message ... public key, suite last), code
  F93102 when absent; output id exit gas value steps, value = the single result integer on a
  normal exit and 99 otherwise.
- pq (test-pq-v16-parity, test-pq-falcon512-parity): id, version, budget, ignore, repeats,
  expect, four operands[, program BOC]; the operands are pushed ``repeats`` times ("int" pushes
  1), a program is entered with an extra 0 on top, otherwise the code is the opcode repeated
  with DROP between; output id exit gas value committed c4 c5. Rows with ignore = 1 run with
  set_chksig_always_succeed, which the vm harness does not take: they are not converted.
- native-cost (test-fee-native-cost): id, version, budget, code bytes, operands bottom first
  (int:<n>, hash:<32-byte hex>, or a BOC); output id exit gas value.
"""

from __future__ import annotations

import argparse
import base64
import importlib
import json
import subprocess
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RESCUE = ROOT / "test/rescue-fee-gate"
sys.path.insert(0, str(RESCUE))
sys.path.insert(0, str(ROOT / "test/auth-extensions"))

Json = dict[str, Any]
SUITE_OPCODE = 0xF93102
MAX_REPEATS = 12


def b64(hex_text: str) -> str:
    return base64.b64encode(bytes.fromhex(hex_text)).decode("ascii")


def entry(fixture_id: str, context: Json, note: str | None = None) -> Json:
    out: Json = {"fixture_id": fixture_id, "context": context}
    if note:
        out["note"] = note
    return out


def cell_item(hex_text: str) -> Json:
    return {"type": "cell", "boc": b64(hex_text)}


def int_item(value: int) -> Json:
    return {"type": "int", "value": str(value)}


def tsv_rows(path: Path, widths: Iterable[int]) -> list[list[str]]:
    allowed = set(widths)
    rows: list[list[str]] = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        fields = line.split("\t")
        if len(fields) not in allowed:
            raise SystemExit(f"{path}:{number}: {sorted(allowed)} columns required")
        rows.append(fields)
    if not rows:
        raise SystemExit(f"{path}: no scenarios")
    return rows


def code_of(opcode: int, repeats: int) -> str:
    """The opcode ``repeats`` times with DROP between, as a one-cell BOC (base64)."""
    from cells import Cell  # pyright: ignore[reportMissingImports]

    if not 1 <= repeats <= MAX_REPEATS:
        raise SystemExit(f"repeats {repeats} outside 1..{MAX_REPEATS}")
    cell = Cell()
    for j in range(repeats):
        cell.uint(opcode, 24)
        if j + 1 < repeats:
            cell.uint(0x30, 8)
    return base64.b64encode(cast(bytes, cell.boc())).decode("ascii")


# ---------------------------------------------------------------------------------------------
# endstate rows (test-vm-endstate)


def endstate_value(field: str) -> Json | None:
    if field == "skip":
        return None
    if field.startswith("int:"):
        return int_item(int(field[4:]))
    return cell_item(field)


def endstate_context(row: Sequence[str], libraries: str | None = None) -> Json:
    if len(row) != 10:
        raise SystemExit(f"{row[0]}: 10 columns required")
    budget = int(row[2])
    stack = [v for v in (endstate_value(x) for x in [*row[5:9], row[4]]) if v is not None]
    context: Json = {
        "code": b64(row[9]),
        "global_version": int(row[1]),
        "gas": {"limit": budget, "max": budget},
        "stack": stack,
    }
    if libraries is not None:
        context["libraries"] = [libraries]
    return context


def endstate_entries(rows: Iterable[Sequence[str]], libraries: str | None = None) -> list[Json]:
    return [entry(r[0], endstate_context(r, libraries), f"label {r[3]}") for r in rows]


def hexed(rows: Iterable[Sequence[Any]]) -> list[list[str]]:
    """Generator rows whose last column may still be a Cell; return the TSV text columns."""
    out: list[list[str]] = []
    for row in rows:
        fields = [str(x) for x in row[:9]]
        code = row[9]
        fields.append(code if isinstance(code, str) else code.boc().hex())
        out.append(fields)
    return out


def prefix_rows(table: Path | None) -> list[list[str]]:
    if table is None:
        raise SystemExit("vm-prefix: --input <test-vm-opcode-table output> required")
    import vm_prefix_scenarios as prefix  # pyright: ignore[reportMissingImports]

    return hexed(prefix.scenarios(prefix.read(str(table))))


def ext_rows(_: Path | None) -> list[list[str]]:
    import vm_ext_scenarios as ext  # pyright: ignore[reportMissingImports]

    return hexed(ext.scenarios())


def family_rows(_: Path | None) -> list[list[str]]:
    import vm_family_scenarios as fam  # pyright: ignore[reportMissingImports]

    # The fuzz family is the default seed set of vm_closure_fuzz.py: vm-closure-fuzz holds it.
    return hexed(fam.scenarios(tuple(name for name in fam.COMPARED if name != "fuzz")))


def fuzz_rows(_: Path | None) -> list[list[str]]:
    import vm_closure_fuzz as fuzz  # pyright: ignore[reportMissingImports]

    # The frozen seed set: the generator's default seeds and count.
    return hexed(fuzz.scenarios(fuzz.SEEDS, fuzz.COUNT))


def varuint_rows(_: Path | None) -> list[list[str]]:
    import vm_varuint_scenarios as varuint  # pyright: ignore[reportMissingImports]

    return [
        [name, "16", "1000000", "R", *(["skip"] * 5), code.boc().hex()]
        for name, code, _ in varuint.cases()
    ]


def library_entries(_: Path | None) -> list[Json]:
    import vm_library_scenarios as library  # pyright: ignore[reportMissingImports]

    collection, rows, _ = library.fixtures()
    return endstate_entries(rows, base64.b64encode(collection.boc()).decode("ascii"))


def endstate_family(rows: Callable[[Path | None], list[list[str]]]) -> Callable[..., list[Json]]:
    return lambda path: endstate_entries(rows(path))


# ---------------------------------------------------------------------------------------------
# suite rows (test-pq-suite-parity)


def suite_value(field: str) -> Json | None:
    if field == "skip":
        return None
    if field.startswith("int:"):
        return int_item(int(field[4:]))
    return cell_item(field)


def suite_entries(rows: Iterable[Sequence[str]]) -> list[Json]:
    out: list[Json] = []
    for row in rows:
        budget = int(row[2])
        stack = [v for v in (suite_value(x) for x in [*row[5:9], row[4]]) if v is not None]
        if len(row) == 10:
            code = b64(row[9])
        else:
            code = code_of(SUITE_OPCODE, 1)
        context: Json = {
            "code": code,
            "global_version": int(row[1]),
            "gas": {"limit": budget, "max": budget},
            "stack": stack,
        }
        out.append(entry(row[0], context, f"expect {row[3]}"))
    return out


def suite_rows() -> list[list[str]]:
    return tsv_rows(RESCUE / "suite-scenarios.tsv", (9, 10))


def version_rows() -> list[list[str]]:
    """version_scenarios.py, which expands the four valid suite rows over versions 0..19."""
    rows = suite_rows()
    fixtures = ("s1-valid", "s2-valid", "s3-valid", "s4-h20w4-valid")
    valid = {row[4]: row for row in rows if row[0] in fixtures}
    if set(valid) != {"int:1", "int:2", "int:3", "int:4"}:
        raise SystemExit("suite-scenarios.tsv: the four valid rows are missing")
    expanded: list[list[str]] = []
    for suite, fixture in sorted(valid.items()):
        for version in range(20):
            row = fixture.copy()
            row[0] = f"version-{version}-suite-{suite[4:]}"
            row[1] = str(version)
            row[3] = "E6" if version < 16 else "V"
            expanded.append(row)
    return expanded


# ---------------------------------------------------------------------------------------------
# pq rows (test-pq-v16-parity, test-pq-falcon512-parity)


@dataclass
class Skipped:
    fixture_id: str
    reason: str


SKIPPED: list[Skipped] = []


def pq_entries(path: Path | None, opcode: int, max_repeats: int) -> list[Json]:
    if path is None:
        raise SystemExit("--input <scenarios.tsv> required")
    out: list[Json] = []
    for row in tsv_rows(path, (10, 11)):
        if row[3] == "1":
            SKIPPED.append(Skipped(row[0], "set_chksig_always_succeed (ignore = 1)"))
            continue
        repeats = int(row[4])
        if not 1 <= repeats <= max_repeats:
            raise SystemExit(f"{row[0]}: repeats outside 1..{max_repeats}")
        stack: list[Json] = []
        for _ in range(repeats):
            for field in row[6:10]:
                if field == "skip":
                    continue
                stack.append(int_item(1) if field == "int" else cell_item(field))
        if len(row) == 11:
            code = b64(row[10])
            stack.append(int_item(0))
        else:
            code = code_of(opcode, repeats)
        budget = int(row[2])
        context: Json = {
            "code": code,
            "global_version": int(row[1]),
            "gas": {"limit": budget, "max": budget},
            "stack": stack,
        }
        out.append(entry(row[0], context, f"expect {row[5]}"))
    return out


# ---------------------------------------------------------------------------------------------
# native-cost rows (test-fee-native-cost)


def native_cost_entries(path: Path | None) -> list[Json]:
    if path is None:
        raise SystemExit("native-cost: --input <native-cost-scenarios.tsv> required")
    out: list[Json] = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        row = line.split("\t")
        if len(row) < 4:
            raise SystemExit(f"{path}:{number}: at least 4 columns required")
        stack: list[Json] = []
        for field in row[4:]:
            if field == "skip":
                continue
            if field.startswith("int:"):
                stack.append(int_item(int(field[4:])))
            elif field.startswith("hash:"):
                raw = bytes.fromhex(field[5:])
                if len(raw) != 32:
                    raise SystemExit(f"{row[0]}: hash operand must be 32 bytes")
                stack.append(int_item(int.from_bytes(raw, "big")))
            else:
                stack.append(cell_item(field))
        from cells import Cell  # pyright: ignore[reportMissingImports]

        code = base64.b64encode(Cell().raw(bytes.fromhex(row[3])).boc()).decode("ascii")
        budget = int(row[2])
        context: Json = {
            "code": code,
            "global_version": int(row[1]),
            "gas": {"limit": budget, "max": budget},
            "stack": stack,
        }
        out.append(entry(row[0], context))
    if not out:
        raise SystemExit(f"{path}: no scenarios")
    return out


# ---------------------------------------------------------------------------------------------
# Driver output projections: the driver's fields, and the same fields computed from a fixture.


def single_value(effects: Json) -> int:
    """The drivers' result column: the single integer left by a normal exit, else 99."""
    if effects["exit_code"] != 0:
        return 99
    stack = effects["stack"]
    if len(stack) != 1:
        return -(10**9)  # the drivers refuse this row; it can never compare equal
    try:
        return int(stack[0])
    except ValueError:
        return -(10**9)


def endstate_projection(effects: Json) -> list[str]:
    return [
        str(effects["exit_code"]),
        str(effects["gas_used"]),
        str(effects["steps"]),
        "1" if effects["committed"] else "0",
        effects["c4_hash"] or "-",
        effects["c5_hash"] or "-",
        " ".join(effects["stack"]) if effects["stack"] else "-",
    ]


def suite_projection(effects: Json) -> list[str]:
    return [
        str(effects["exit_code"]),
        str(effects["gas_used"]),
        str(single_value(effects)),
        str(effects["steps"]),
    ]


def pq_projection(effects: Json) -> list[str]:
    return [
        str(effects["exit_code"]),
        str(effects["gas_used"]),
        str(single_value(effects)),
        "1" if effects["committed"] else "0",
        effects["c4_hash"] or "-",
        effects["c5_hash"] or "-",
    ]


def native_cost_projection(effects: Json) -> list[str]:
    return [str(effects["exit_code"]), str(effects["gas_used"]), str(single_value(effects))]


@dataclass(frozen=True)
class Family:
    name: str
    driver: str
    entries: Callable[[Path | None], list[Json]]
    projection: Callable[[Json], list[str]]
    compared: str
    not_compared: str


ENDSTATE_FIELDS = "exit_code gas_used steps committed c4_hash c5_hash stack"
ALL = "-"

FAMILIES: dict[str, Family] = {
    f.name: f
    for f in (
        Family(
            "vm-prefix",
            "test-vm-endstate",
            endstate_family(prefix_rows),
            endstate_projection,
            ENDSTATE_FIELDS,
            ALL,
        ),
        Family(
            "vm-ext",
            "test-vm-endstate",
            endstate_family(ext_rows),
            endstate_projection,
            ENDSTATE_FIELDS,
            ALL,
        ),
        Family(
            "vm-family",
            "test-vm-endstate",
            endstate_family(family_rows),
            endstate_projection,
            ENDSTATE_FIELDS,
            ALL,
        ),
        Family(
            "vm-closure-fuzz",
            "test-vm-endstate",
            endstate_family(fuzz_rows),
            endstate_projection,
            ENDSTATE_FIELDS,
            ALL,
        ),
        Family(
            "vm-varuint",
            "test-vm-endstate",
            endstate_family(varuint_rows),
            endstate_projection,
            ENDSTATE_FIELDS,
            ALL,
        ),
        Family(
            "vm-library",
            "test-vm-endstate (with the library collection argument)",
            library_entries,
            endstate_projection,
            ENDSTATE_FIELDS,
            ALL,
        ),
        Family(
            "pq-suite-parity",
            "test-pq-suite-parity",
            lambda _: suite_entries(suite_rows()),
            suite_projection,
            "exit_code gas_used value steps",
            "committed c4_hash c5_hash, stack beyond the result value",
        ),
        Family(
            "pq-version",
            "test-pq-suite-parity",
            lambda _: suite_entries(version_rows()),
            suite_projection,
            "exit_code gas_used value steps",
            "committed c4_hash c5_hash, stack beyond the result value",
        ),
        Family(
            "pq-v16-parity",
            "test-pq-v16-parity",
            lambda path: pq_entries(path, 0xF93100, 12),
            pq_projection,
            "exit_code gas_used value committed c4_hash c5_hash",
            "steps, stack beyond the result value",
        ),
        Family(
            "pq-falcon512-parity",
            "test-pq-falcon512-parity",
            lambda path: pq_entries(path, 0xF93101, 11),
            pq_projection,
            "exit_code gas_used value committed c4_hash c5_hash",
            "steps, stack beyond the result value",
        ),
        Family(
            "native-cost",
            "test-fee-native-cost",
            native_cost_entries,
            native_cost_projection,
            "exit_code gas_used value",
            "steps committed c4_hash c5_hash, stack beyond the result value",
        ),
    )
}


def write_entries(path: Path, entries: Sequence[Json]) -> None:
    ids = [e["fixture_id"] for e in entries]
    if len(set(ids)) != len(ids):
        raise SystemExit("duplicate fixture ids")
    path.write_text("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in entries))


def driver_rows(text: str, renames: Sequence[str] = ()) -> dict[str, list[str]]:
    pairs = [r.split("=", 1) for r in renames]
    rows: dict[str, list[str]] = {}
    for line in text.splitlines():
        fields = line.split("\t")
        name = fields[0]
        for old, new in pairs:
            if name.startswith(old):
                name = new + name[len(old) :]
        if name in rows:
            raise SystemExit(f"duplicate driver row {name}")
        rows[name] = fields[1:]
    return rows


def read_fixtures(path: Path) -> list[Json]:
    fixtures = [json.loads(line) for line in path.read_text().splitlines()]
    if not fixtures:
        raise SystemExit(f"{path}: no fixtures")
    return fixtures


def compare(family: Family, fixtures: Sequence[Json], rows: dict[str, list[str]]) -> int:
    """Print the comparison; return the number of differences plus fixtures without a row."""
    differences = 0
    missing = 0
    for fixture in fixtures:
        fixture_id = fixture["metadata"]["fixture_id"]
        if fixture_id not in rows:
            missing += 1
            print(f"MISSING {fixture_id}: no driver row")
            continue
        actual = family.projection(fixture["effects"])
        expected = rows[fixture_id]
        if actual != expected:
            differences += 1
            if differences <= 20:
                print(f"DIFF {fixture_id}: driver {expected} fixture {actual}")
    unmatched = len(rows) - (len(fixtures) - missing)
    not_reported = (
        f"; not reported by the driver: {family.not_compared}" if family.not_compared != ALL else ""
    )
    print(
        f"{family.name}: checked {len(fixtures)} fixtures against {family.driver}: "
        f"{differences} differences, {missing} without a driver row, "
        f"{unmatched} driver rows not in this family; compared {family.compared}{not_reported}"
    )
    return differences + missing


def check(family: Family, fixtures_path: Path, output: Path, renames: Sequence[str]) -> int:
    rows = driver_rows(output.read_text(), renames)
    return 1 if compare(family, read_fixtures(fixtures_path), rows) else 0


def run_tool(command: Sequence[str | Path], cwd: Path | None = None) -> str:
    done = subprocess.run(
        [str(c) for c in command],
        capture_output=True,
        text=True,
        timeout=3600,
        check=False,
        cwd=cwd,
    )
    if done.returncode != 0:
        raise SystemExit(f"{command[0]} exited {done.returncode}: {done.stderr[-2000:]}")
    return done.stdout


def frozen_contexts(path: Path) -> dict[str, Json]:
    sys.path.insert(0, str(HERE.parent / "runner"))
    runner = cast(Any, importlib.import_module("conformance"))
    family = runner.load_family(path)
    return {
        f["metadata"]["fixture_id"]: ctx
        for f, ctx in zip(family.fixtures, family.contexts(), strict=True)
    }


def tsv(rows: Iterable[Sequence[str]]) -> str:
    return "".join("\t".join(r) + "\n" for r in rows)


def crosscheck(build: Path, fixtures_dir: Path, scratch: Path) -> int:
    scratch.mkdir(parents=True, exist_ok=True)
    tools = build / "crypto/pq"
    table = scratch / "cp0.tsv"
    table.write_text(run_tool([tools / "test-vm-opcode-table"]))
    failures = 0

    def same_contexts(name: str, entries: Sequence[Json]) -> None:
        nonlocal failures
        frozen = frozen_contexts(fixtures_dir / f"{name}.jsonl")
        fresh = {e["fixture_id"]: e["context"] for e in entries}
        if frozen != fresh:
            failures += 1
            changed = sorted(
                k for k in frozen.keys() | fresh.keys() if frozen.get(k) != fresh.get(k)
            )
            print(f"{name}: regenerated contexts differ from the frozen ones: {changed[:5]}")
        else:
            print(f"{name}: {len(fresh)} regenerated contexts equal the frozen ones")

    def driver(name: str, rows_text: str, program: str, *extra: Path) -> dict[str, list[str]]:
        scenarios = scratch / f"{name}.tsv"
        scenarios.write_text(rows_text)
        return driver_rows(run_tool([tools / program, scenarios, *extra]))

    def checked(name: str, rows: dict[str, list[str]]) -> None:
        nonlocal failures
        family = FAMILIES[name]
        if compare(family, read_fixtures(fixtures_dir / f"{name}.jsonl"), rows):
            failures += 1

    parts = {
        "vm-prefix": prefix_rows(table),
        "vm-ext": ext_rows(None),
        "vm-family": family_rows(None),
        "vm-closure-fuzz": fuzz_rows(None),
    }
    for name, rows in parts.items():
        same_contexts(name, endstate_entries(rows))
    import vm_ext_scenarios as ext  # pyright: ignore[reportMissingImports]
    import vm_family_scenarios as fam  # pyright: ignore[reportMissingImports]
    import vm_prefix_scenarios as prefix  # pyright: ignore[reportMissingImports]

    whole = hexed(prefix.scenarios(prefix.read(str(table))) + ext.scenarios() + fam.scenarios())
    covered = sum(len(rows) for rows in parts.values())
    if covered != len(whole):
        failures += 1
        print(f"the families hold {covered} rows of the {len(whole)} vm_prefix_scenarios.py rows")
    (scratch / "prefix.tsv").write_text(tsv(whole))
    whole_rows = driver_rows(run_tool([tools / "test-vm-endstate", scratch / "prefix.tsv"]))
    for name in ("vm-prefix", "vm-ext", "vm-family"):
        checked(name, whole_rows)
    renamed = {
        ("fuzz-" + k[len("family-fuzz-") :]): v
        for k, v in whole_rows.items()
        if k.startswith("family-fuzz-")
    }
    checked("vm-closure-fuzz", renamed)

    varuint = varuint_rows(None)
    same_contexts("vm-varuint", endstate_entries(varuint))
    checked("vm-varuint", driver("varuint", tsv(varuint), "test-vm-endstate"))

    library = library_entries(None)
    same_contexts("vm-library", library)
    import vm_library_scenarios as lib  # pyright: ignore[reportMissingImports]

    collection, library_rows, _ = lib.fixtures()
    boc = scratch / "libraries.boc"
    boc.write_bytes(collection.boc())
    checked("vm-library", driver("library", tsv(library_rows), "test-vm-endstate", boc))

    for name, rows in (("pq-suite-parity", suite_rows()), ("pq-version", version_rows())):
        same_contexts(name, suite_entries(rows))
        checked(name, driver(name, tsv(rows), "test-pq-suite-parity"))
    checked("pq-suite-parity", driver_rows((RESCUE / "suite-expected.tsv").read_text()))
    print(f"crosscheck: {failures} failing checks")
    return 1 if failures else 0


def authored(fixtures_dir: Path, scratch: Path, seed_dir: Path | None = None) -> int:
    scratch.mkdir(parents=True, exist_ok=True)

    def family_path(family: str) -> Path:
        # A family is in the vectors checkout or, like vm-endstate, in the in-tree seed set.
        for directory in (fixtures_dir, seed_dir):
            if directory is not None and (directory / f"{family}.jsonl").exists():
                return directory / f"{family}.jsonl"
        raise SystemExit(f"family {family} is in neither {fixtures_dir} nor {seed_dir}")

    def project_to(name: str, family: str, out: Path) -> Path:
        fixtures = read_fixtures(family_path(family))
        projection = FAMILIES[name].projection
        out.write_text(
            tsv([f["metadata"]["fixture_id"], *projection(f["effects"])] for f in fixtures)
        )
        return out

    python = sys.executable
    varuint = project_to("vm-varuint", "vm-varuint", scratch / "varuint.tsv")
    library = project_to("vm-library", "vm-library", scratch / "library.tsv")
    endstate = project_to("vm-varuint", "vm-endstate", scratch / "endstate.tsv")
    for command in (
        [python, RESCUE / "vm_varuint_scenarios.py", "--check", varuint],
        [python, RESCUE / "vm_library_scenarios.py", "--check-native", library],
        [python, RESCUE / "vm_sha256c_scenarios.py", endstate],
        [python, RESCUE / "vm_datasize_scenarios.py", endstate],
    ):
        print(run_tool(command, cwd=RESCUE).strip())
    return 0


def tamper_control(target: Path, fixtures_dir: Path, scratch: Path, names: Sequence[str]) -> int:
    runner = HERE.parent / "runner/conformance.py"
    failures = 0
    for name in names:
        source = fixtures_dir / f"{name}.jsonl"
        for tampered in (False, True):
            copy = scratch / ("tampered" if tampered else "clean") / name / "vm/fixtures"
            copy.mkdir(parents=True, exist_ok=True)
            lines = source.read_text().splitlines()
            first = json.loads(lines[0])
            if tampered:
                first["effects"]["gas_used"] += 1
                lines[0] = json.dumps(first, separators=(",", ":"), sort_keys=True)
            (copy / source.name).write_text("".join(line + "\n" for line in lines))
            blobs = source.with_name(f"{name}.blobs.json")
            if blobs.exists():
                (copy / blobs.name).write_text(blobs.read_text())
            done = subprocess.run(
                [sys.executable, runner, "run", "--target", str(target), str(copy.parent.parent)],
                capture_output=True,
                text=True,
                timeout=3600,
                check=False,
            )
            fixture_id = f"vm/{name}/{first['metadata']['fixture_id']}"
            red = done.returncode == 1 and f"MISMATCH {fixture_id}:" in done.stdout
            red = red and "mismatched 1," in done.stdout
            ok = red if tampered else done.returncode == 0
            failures += 0 if ok else 1
            state = "tampered" if tampered else "clean"
            verdict = "as required" if ok else "NOT as required"
            print(f"{name} {state}: exit {done.returncode} {verdict}: {done.stdout.strip()[-200:]}")
    return 1 if failures else 0


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    contexts = sub.add_parser("contexts")
    contexts.add_argument("family", choices=sorted(FAMILIES))
    contexts.add_argument("out", type=Path)
    contexts.add_argument("--input", type=Path)
    checker = sub.add_parser("check")
    checker.add_argument("family", choices=sorted(FAMILIES))
    checker.add_argument("fixtures", type=Path)
    checker.add_argument("output", type=Path)
    checker.add_argument("--rename", action="append", default=[])
    project = sub.add_parser("project")
    project.add_argument("family", choices=sorted(FAMILIES))
    project.add_argument("fixtures", type=Path)
    project.add_argument("out", type=Path)
    cross = sub.add_parser("crosscheck")
    cross.add_argument("build", type=Path)
    cross.add_argument("fixtures_dir", type=Path)
    cross.add_argument("scratch", type=Path)
    authored_parser = sub.add_parser("authored")
    authored_parser.add_argument("fixtures_dir", type=Path)
    authored_parser.add_argument("scratch", type=Path)
    authored_parser.add_argument("--seed-dir", type=Path, default=None)
    tamper = sub.add_parser("tamper-control")
    tamper.add_argument("target", type=Path)
    tamper.add_argument("fixtures_dir", type=Path)
    tamper.add_argument("scratch", type=Path)
    tamper.add_argument("names", nargs="+")
    sub.add_parser("families")
    args = parser.parse_args(argv)
    if args.command == "crosscheck":
        return crosscheck(args.build, args.fixtures_dir, args.scratch)
    if args.command == "authored":
        return authored(args.fixtures_dir, args.scratch, args.seed_dir)
    if args.command == "tamper-control":
        return tamper_control(args.target, args.fixtures_dir, args.scratch, args.names)
    if args.command == "families":
        for family in FAMILIES.values():
            print(f"{family.name}\t{family.driver}")
        return 0
    family = FAMILIES[args.family]
    if args.command == "project":
        fixtures = [json.loads(line) for line in args.fixtures.read_text().splitlines()]
        args.out.write_text(
            "".join(
                "\t".join([f["metadata"]["fixture_id"], *family.projection(f["effects"])]) + "\n"
                for f in fixtures
            )
        )
        print(f"{len(fixtures)} rows")
        return 0
    if args.command == "contexts":
        entries = family.entries(args.input)
        write_entries(args.out, entries)
        print(f"{family.name}: {len(entries)} contexts, {len(SKIPPED)} not converted")
        for skipped in SKIPPED:
            print(f"  not converted {skipped.fixture_id}: {skipped.reason}")
        return 0
    return check(family, args.fixtures, args.output, args.rename)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
