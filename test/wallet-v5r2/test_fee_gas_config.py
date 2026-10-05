"""Actual trusted-config gas-cap parsing and admission guard, without PQ key generation."""

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
from cells import Cell, from_boc, make_dict, read_dict  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    out = parser.parse_args().output
    out.mkdir(parents=True, exist_ok=True)
    source = (ROOT / "crypto/smartcont/wallet-v5r2-fee-vault.fc").read_text()
    guard = "throw_unless(2017, r2fee_gas_limit() >= r2fee::compute_bound);"
    assert source.count(guard) == 1
    source = source.replace("() recv_internal(", "() fee_deposit(").replace(
        "() recv_external(", "() fee_external("
    )
    driver = (
        "\n() recv_internal(slice body) impure { "
        + guard
        + " set_data(begin_cell().store_uint(r2fee_gas_limit(), 64).end_cell()); }\n"
    )
    results = {}
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        shutil.copyfile(ROOT / "crypto/smartcont/pq.fc", work / "pq.fc")
        for mutant in (False, True):
            (work / "driver.fc").write_text(
                source + (driver.replace(guard, "") if mutant else driver)
            )
            label = "deleted_guard" if mutant else "production"
            code = native.compile_contract(str(work / "driver.fc"), out / f"{label}.boc")
            for encoding in ("flat_ext", "ext", "legacy"):
                for cap in [65535] if mutant else [65535, 65536, 1000000]:
                    entries = read_dict(native.config(17), 32)
                    original = entries[21].refs[0]
                    assert int(original.bits[:8], 2) == 0xD1
                    extended = original.bits[136:]
                    assert int(extended[:8], 2) == 0xDE
                    extended = extended[:72] + format(cap, "064b") + extended[136:]
                    if encoding == "flat_ext":
                        bits = original.bits[:136] + extended
                    elif encoding == "ext":
                        bits = extended
                    else:
                        bits = format(0xDD, "08b") + extended[8:136] + extended[200:]
                    entries[21] = Cell().ref(Cell(bits=bits))
                    with patch.object(native, "config", return_value=make_dict(entries, 32)):
                        emulator = native.Emulator(17)
                    try:
                        initial = Cell().uint(0, 64)
                        result = emulator.send(
                            native.active_account((0, 100), code, initial),
                            native.internal((0, 101), (0, 100), Cell(), value=10**11),
                        )
                        expected = 2017 if cap < 65536 and not mutant else 0
                        assert result["success"] and result["details"]["exit"] == expected, result
                        after = native.account_data(from_boc(result["shard_account"]))[0]
                        assert after.hash == (initial if expected else Cell().uint(cap, 64)).hash
                        name = f"{label}-{encoding}-{cap}"
                        results[name] = result["details"]
                        (out / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n")
                    finally:
                        emulator.close()
    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("12 trusted gas configuration cases passed, including 3 guard deletion controls")


if __name__ == "__main__":
    main()
