"""Exercise the fee vault's actual cell guards, level inheritance, and deletion controls."""

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
import native  # noqa: E402
from cells import Cell, LibraryReference, from_boc  # noqa: E402
from test_identity import send_with_library_fixture  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    out = parser.parse_args().output
    out.mkdir(parents=True, exist_ok=True)
    results = {}
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        shutil.copyfile(ROOT / "crypto/smartcont/pq.fc", work / "pq.fc")
        source = (ROOT / "crypto/smartcont/wallet-v5r2-fee-vault.fc").read_text()
        source = source.replace("() recv_internal(", "() fee_deposit(").replace(
            "() recv_external(", "() fee_external("
        )
        driver = """
cell fixture_special(builder b, int special) asm "ENDXC";
() recv_internal(slice body) impure {
  int fixture = body~load_uint(8);
  cell input = body~load_ref();
  body.end_parse();
  if (fixture == 2) {
    ;; A genuine level-one pruned branch, created inside the VM. It never enters
    ;; the ordinary-only Python codec or a transaction's persistent outputs.
    cell pruned = fixture_special(begin_cell().store_uint(1, 8).store_uint(1, 8)
        .store_uint(123, 256).store_uint(0, 16), -1);
    cell child = begin_cell().store_uint(456, 16).store_ref(pruned).end_cell();
    input = begin_cell().store_ref(child).end_cell();
    throw_unless(777, (r2fee_level(input) == 1) & (r2fee_level(child) == 1));
  }
  slice parsed = r2fee_ordinary(input);
  if (fixture != 0) { parsed = r2fee_child(parsed~load_ref()); }
  set_data(begin_cell().store_uint(slice_bits(parsed), 16).end_cell());
}
"""
        guard = "throw_if(2012, special | r2fee_level(c));"
        child_guard = "throw_if(2012, special);"
        assert source.count(guard) == 1 and source.count(child_guard) == 1
        variants = {
            "production": source,
            "deleted_root_special": source.replace(guard, "throw_if(2012, r2fee_level(c));"),
            "deleted_root_level": source.replace(guard, "throw_if(2012, special);"),
            "deleted_child_special": source.replace(child_guard, ""),
        }
        for label, variant in variants.items():
            (work / "driver.fc").write_text(variant + driver)
            code = native.compile_contract(str(work / "driver.fc"), out / f"{label}.boc")
            emulator = native.Emulator(17)
            try:
                for name, fixture, candidate, output_bits, rejected_by in (
                    ("ordinary", 0, Cell().uint(123, 16), 16, None),
                    ("root_library", 0, LibraryReference(123), 264, "deleted_root_special"),
                    ("child_ordinary", 1, Cell().ref(Cell().uint(123, 16)), 16, None),
                    (
                        "child_library",
                        1,
                        Cell().ref(LibraryReference(123)),
                        264,
                        "deleted_child_special",
                    ),
                    ("inherited_nonzero_level", 2, Cell(), 16, "deleted_root_level"),
                ):
                    expected = 2012 if rejected_by and label != rejected_by else 0
                    initial = Cell().uint(999, 16)
                    result = send_with_library_fixture(
                        emulator,
                        native.active_account((0, 100), code, initial),
                        native.internal(
                            (0, 101), (0, 100), Cell().uint(fixture, 8).ref(candidate), value=10**11
                        ),
                    )
                    assert result["success"] and result["details"]["exit"] == expected, result
                    after = native.account_data(from_boc(result["shard_account"]))[0]
                    target = initial if expected else Cell().uint(output_bits, 16)
                    assert after.hash == target.hash
                    results[f"{label}/{name}"] = result["details"]
                    (out / f"{label}-{name}.json").write_text(json.dumps(result, indent=2) + "\n")
            finally:
                emulator.close()
    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("20 cell guard cases passed; 3 independent guard deletion controls")


if __name__ == "__main__":
    main()
