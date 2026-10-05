"""Exercise the fee vault's actual ordinary-cell guard and its deletion control."""

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
() recv_internal(slice body) impure {
  slice parsed = r2fee_ordinary(body~load_ref());
  body.end_parse();
  set_data(begin_cell().store_uint(slice_bits(parsed), 16).end_cell());
}
"""
        guard = "throw_if(2012, special | r2fee_level(c));"
        assert source.count(guard) == 1
        for mutant in (False, True):
            (work / "driver.fc").write_text(
                (source.replace(guard, "") if mutant else source) + driver
            )
            label = "deleted_guard" if mutant else "production_guard"
            code = native.compile_contract(str(work / "driver.fc"), out / f"{label}.boc")
            emulator = native.Emulator(17)
            try:
                for name, candidate, expected in (
                    ("ordinary", Cell().uint(123, 16), 0),
                    ("library", LibraryReference(123), 0 if mutant else 2012),
                ):
                    initial = Cell().uint(999, 16)
                    result = send_with_library_fixture(
                        emulator,
                        native.active_account((0, 100), code, initial),
                        native.internal((0, 101), (0, 100), Cell().ref(candidate), value=10**11),
                    )
                    assert result["success"] and result["details"]["exit"] == expected, result
                    after = native.account_data(from_boc(result["shard_account"]))[0]
                    target = initial if expected else Cell().uint(len(candidate.bits), 16)
                    assert after.hash == target.hash
                    results[f"{label}/{name}"] = result["details"]
                    (out / f"{label}-{name}.json").write_text(json.dumps(result, indent=2) + "\n")
            finally:
                emulator.close()
    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("4 cell guard cases passed, including unsafe acceptance after guard deletion")


if __name__ == "__main__":
    main()
