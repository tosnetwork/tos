"""Canonical module StateInit controls; not a successor-vault or POP acceptance test."""

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
import native  # noqa: E402
from cells import Cell, LibraryReference, from_boc  # noqa: E402
from native import (  # noqa: E402
    Emulator,
    account_data,
    active_account,
    compile_contract,
    internal,
    state_init,
)


def chain(data, chunk=127):
    result = None
    for offset in reversed(range(0, len(data), chunk)):
        result = (
            Cell().raw(data[offset : offset + chunk]).ref(result)
            if result
            else Cell().raw(data[offset : offset + chunk])
        )
    return result or Cell()


def module_data(version=1, global_id=42, network=123, daily=1, policy=1, key=None):
    if key is None:
        key = chain(bytes(range(256)) * 5 + bytes(range(32)))
    return (
        Cell()
        .uint(version, 8)
        .sint(global_id, 32)
        .uint(network, 256)
        .uint(daily, 8)
        .uint(456, 256)
        .uint(policy, 8)
        .ref(key)
    )


def send_with_library_fixture(emulator, shard, message):
    with patch.object(native, "from_boc", lambda data: from_boc(data, allow_library=True)):
        return emulator.send(shard, message)


def run(code, witness, expected, pinned=None, address=None):
    pinned = witness.refs[0] if pinned is None else pinned
    data = Cell().uint(int.from_bytes(pinned.hash, "big"), 256).uint(123, 256)
    e = Emulator(17)
    try:
        result = send_with_library_fixture(
            e,
            active_account((0, 100), code, data),
            internal(
                (0, 101),
                (0, 100),
                Cell()
                .uint(int.from_bytes(witness.hash, "big") if address is None else address, 256)
                .ref(witness),
                value=100_000_000_000,
            ),
        )
        assert result["success"], result
        actual = result["details"]["exit"]
        assert actual == expected, f"expected exit {expected}, got {actual}"
        after = account_data(from_boc(result["shard_account"]))[0]
        if expected:
            assert after.hash == data.hash, "invalid witness changed installed data"
        else:
            assert after.hash != data.hash
        return result["details"]
    finally:
        e.close()


def compile_driver(work, out, mutation=None):
    for name in ["wallet-v5r2-identity.fc", "pq-bytes.fc"]:
        shutil.copyfile(ROOT / "crypto/smartcont" / name, work / name)
    shutil.copyfile(ROOT / "test/wallet-v5r2/identity-driver.fc", work / "driver.fc")
    if mutation:
        p = work / "wallet-v5r2-identity.fc"
        s = p.read_text()
        assert s.count(mutation[0]) == 1
        p.write_text(s.replace(*mutation))
    try:
        return compile_contract(str(work / "driver.fc"), out)
    except Exception as e:
        if hasattr(e, "stderr"):
            print(e.stderr.decode(), file=sys.stderr)
        raise


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    out = ap.parse_args().output
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        code = compile_driver(work, out / "identity.boc")
        actual_module = compile_contract("rescue-dual-module.fc", out / "module.boc")
        witness = state_init(actual_module, module_data())
        cases = {"current_module": run(code, witness, 0)}
        cases["required_policy"] = run(code, state_init(actual_module, module_data(policy=2)), 0)
        for field, value in [
            ("version", 2),
            ("global_id", 43),
            ("network", 124),
            ("daily", 2),
            ("policy", 0),
            ("policy", 3),
        ]:
            cases[f"{field}_{value}"] = run(
                code, state_init(actual_module, module_data(**{field: value})), 1815
            )
        for bits in ("00111", "10110", "01110", "00010", "00100", "001100"):
            bad = Cell(bits=bits, refs=witness.refs)
            cases["shape_" + bits] = run(code, bad, 1815)
        cases["missing_data"] = run(code, Cell(bits=witness.bits, refs=witness.refs[:1]), 1815)
        cases["extra_reference"] = run(
            code, Cell(bits=witness.bits, refs=[*witness.refs, Cell()]), 1815
        )
        cases["wrong_address"] = run(code, witness, 1815, address=123)
        cases["wrong_code"] = run(code, witness, 1815, pinned=Cell().uint(123, 8))
        for length in (0, 1311, 1313):
            cases[f"key_length_{length}"] = run(
                code, state_init(actual_module, module_data(key=chain(b"x" * length))), 63
            )
        cases["key_short_chunks"] = run(
            code, state_init(actual_module, module_data(key=chain(b"x" * 1312, 126))), 63
        )
        bad = module_data()
        bad.bits += "0"
        cases["trailing_data"] = run(code, state_init(actual_module, bad), 9)
        # The traversal cap must reject a valid-shaped tree before parser work.
        wide = Cell()
        for _ in range(6):
            wide = Cell(refs=[wide] * 4)
        cases["bounded_visits"] = run(code, state_init(wide, module_data()), 1815)
        library = LibraryReference(0)
        # Codec stays fail-closed unless the library fixture is explicitly enabled.
        try:
            from_boc(library.boc())
        except AssertionError as error:
            assert "exotic cells" in str(error)
        else:
            raise AssertionError("ordinary decoder admitted an exotic fixture")
        assert from_boc(library.boc(), allow_library=True).hash == library.hash
        cases["library_state_init"] = run(code, library, 1815, pinned=actual_module)
        cases["library_code"] = run(code, state_init(library, module_data()), 1815)
        cases["library_data"] = run(code, state_init(actual_module, library), 1815)
        cases["library_key"] = run(code, state_init(actual_module, module_data(key=library)), 1815)
        deep = Cell()
        for _ in range(130):
            deep = Cell().ref(deep)
        cases["depth_bound"] = run(code, state_init(deep, module_data()), 1815)
        mutations = [
            (
                "ordinary_cells",
                "  throw_unless(r2id::invalid, (special == 0) & (r2id_level(c) == 0));",
                "",
                lambda c: run(c, state_init(library, module_data()), 1815),
            ),
            (
                "depth",
                "(remaining > 0) & (depth <= 128)",
                "remaining > 0",
                lambda c: run(c, state_init(deep, module_data()), 1815),
            ),
            (
                "address",
                "  throw_unless(r2id::invalid, cell_hash(witness) == expected_address);",
                "",
                lambda c: run(c, witness, 1815, address=123),
            ),
            (
                "code",
                "  throw_unless(r2id::invalid, cell_hash(code) == expected_code);",
                "",
                lambda c: run(c, witness, 1815, pinned=Cell().uint(123, 8)),
            ),
            (
                "namespace",
                "  throw_unless(r2id::invalid, s~load_uint(256) == network);",
                "  s~load_uint(256);",
                lambda c: run(c, state_init(actual_module, module_data(network=124)), 1815),
            ),
        ]
        killed = {}
        for name, old, new, test in mutations:
            mutant = compile_driver(work, out / (name + ".boc"), (old, new))
            try:
                test(mutant)
            except AssertionError as e:
                assert "got 0" in str(e), str(e)
                killed[name] = str(e)
            else:
                raise AssertionError("mutation survived: " + name)
            test(code)
        report = {"scope": __doc__, "cases": len(cases), "mutations": killed, "results": cases}
        (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({k: v for k, v in report.items() if k != "results"}, indent=2))


if __name__ == "__main__":
    main()
