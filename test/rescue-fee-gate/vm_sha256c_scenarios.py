"""Authored v16 SHA256C conditions, appended to the frozen endstate suite.

Run with a native endstate transcript to check its SHA256C rows before freezing.
Expected gas/steps and stack contents are derived here independently of that run.
"""

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-extensions"))
from cells import Cell, LibraryReference  # noqa: E402
from suite_scenarios import op, prog  # noqa: E402

# Sources: crypto/vm/opctable.h (10 + encoded bits), vm.h (load/reload,
# hash-entry, exception, implicit RET), Hasher.cpp (33 SHA256 bytes/gas),
# tosops.cpp:exec_compute_sha256_snake (load -> validate -> charge hash).
# vm.cpp:run_inner/run increment steps once more on VmError/out-of-gas dispatch.
PUSHREF, SHA256C, DUP, SWAP = 18, 26, 18, 18
LOAD, RELOAD, HASH_ENTRY, EXCEPTION, RET = 100, 25, 1, 50, 5
EMPTY_HASH = Cell().hash.hex().upper()


def snake(parts):
    tail = None
    for part in reversed(parts):
        node = Cell().raw(part)
        if tail is not None:
            node.ref(tail)
        tail = node
    assert tail is not None
    return tail


def cases():
    rows = []

    def add(name, code, gas, steps, stack, *, exit_code=0, budget=1_000_000):
        committed = int(exit_code in (0, 1))
        state = EMPTY_HASH if committed else "-"
        expected = [str(exit_code), str(gas), str(steps), str(committed), state, state, stack]
        rows.append(("sha256c-" + name, code, budget, expected))

    for label, parts in [
        ("empty", [b""]),
        ("bytes-32", [b"x" * 32]),
        ("bytes-33", [b"x" * 33]),
        ("bytes-34", [b"x" * 34]),
        ("snake-12", [b"x" * 127] * 12),
    ]:
        cell = snake(parts)
        digest = str(int.from_bytes(hashlib.sha256(b"".join(parts)).digest(), "big"))
        hashing = sum(HASH_ENTRY + len(part) // 33 for part in parts)
        total = PUSHREF + SHA256C + len(parts) * LOAD + hashing + RET
        code = prog(op([0x88], cell), op([0xF9, 0x03]))
        add(label + "-cold", code, total, 3, digest)
        if label == "snake-12":
            add(label + "-exact", code, total, 3, digest, budget=total)
            # One short reaches the implicit RET, which consumes its price before
            # detecting exhaustion; out-of-gas leaves consumed gas on the stack.
            add(label + "-one-short", code, total, 4, str(total), exit_code=-14, budget=total - 1)
            first_load = PUSHREF + SHA256C + LOAD
            add(
                "first-load-out-of-gas",
                code,
                first_load,
                3,
                str(first_load),
                exit_code=-14,
                budget=first_load - 1,
            )
            # DUP retains the input cell; SWAP brings it back after the first hash.
            twice = prog(op([0x88], cell), op([0x20, 0xF9, 0x03, 0x01, 0xF9, 0x03]))
            gas = (
                PUSHREF
                + DUP
                + 2 * SHA256C
                + SWAP
                + len(parts) * (LOAD + RELOAD)
                + 2 * hashing
                + RET
            )
            add(label + "-warm", twice, gas, 6, digest + " " + digest)
            first_reload = PUSHREF + DUP + 2 * SHA256C + SWAP + len(parts) * LOAD + hashing + RELOAD
            add(
                "reload-out-of-gas",
                twice,
                first_reload,
                6,
                str(first_reload),
                exit_code=-14,
                budget=first_reload - 1,
            )

    for label, invalid in [
        ("unaligned", Cell().uint(1, 1)),
        ("two-refs", Cell().ref(Cell()).ref(Cell().raw(b"x"))),
        ("missing-library", LibraryReference(1)),
    ]:
        code = prog(op([0x88], invalid), op([0xF9, 0x03]))
        add(label, code, PUSHREF + SHA256C + LOAD + EXCEPTION, 3, "0", exit_code=9)
        # A valid first cell is charged before discovering the malformed second.
        root = Cell().raw(b"a").ref(invalid)
        code = prog(op([0x88], root), op([0xF9, 0x03]))
        add(
            label + "-tail",
            code,
            PUSHREF + SHA256C + 2 * LOAD + HASH_ENTRY + EXCEPTION,
            3,
            "0",
            exit_code=9,
        )
    return rows


def check_native(path):
    expected = {name: effect for name, _, _, effect in cases()}
    actual = {}
    for line in Path(path).read_text().splitlines():
        fields = line.split("\t")
        if fields[0].startswith("sha256c-"):
            assert len(fields) == 8, f"invalid native row: {fields[0]}"
            assert fields[0] not in actual, f"duplicate native row: {fields[0]}"
            actual[fields[0]] = fields[1:]
    assert actual.keys() == expected.keys(), "missing or unexpected SHA256C rows"
    for name, effect in expected.items():
        assert actual[name] == effect, f"{name}: native {actual[name]}, authored {effect}"
    print(f"PASS: {len(expected)} SHA256C native rows satisfy authored assertions")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: vm_sha256c_scenarios.py native-endstate.tsv")
    check_native(sys.argv[1])
