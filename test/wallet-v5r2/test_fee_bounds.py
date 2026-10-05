"""Boundary equivalence and deletion controls for actual fee admission predicates."""

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
import native  # noqa: E402
from cells import Cell, from_boc  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    out = parser.parse_args().output
    out.mkdir(parents=True, exist_ok=True)
    source = (ROOT / "crypto/smartcont/wallet-v5r2-fee-vault.fc").read_text()
    cases = {
        "tag": (
            "throw_if(2017, (tag - 0xdd) >> 1);",
            8,
            range(256),
            lambda x: x in (0xDD, 0xDE),
            2017,
        ),
        "kind": ("throw_if(2012, (kind - 1) >> 1);", 8, range(256), lambda x: x in (1, 2), 2012),
        "role": ("throw_if(2012, (role - 1) >> 1);", 8, range(256), lambda x: x in (1, 2), 2012),
        "deadline": (
            "throw_if(2003, (deadline - now() - 1) / 3600);",
            32,
            [
                0,
                native.NOW - 3601,
                native.NOW - 1,
                native.NOW,
                native.NOW + 1,
                native.NOW + 3599,
                native.NOW + 3600,
                native.NOW + 3601,
                2**32 - 1,
            ],
            lambda x: native.NOW < x <= native.NOW + 3600,
            2003,
        ),
    }
    summaries = {}
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        shutil.copyfile(ROOT / "crypto/smartcont/pq.fc", work / "pq.fc")
        renamed = source.replace("() recv_internal(", "() fee_deposit(").replace(
            "() recv_external(", "() fee_external("
        )
        for name, (guard, width, values, permitted, error) in cases.items():
            assert source.count(guard) == 1, "the production predicate must be unambiguous"
            # The expression is copied verbatim from the production source. The
            # independent expected result above uses the specification's bounds.
            driver = (
                f"\n() recv_internal(slice body) impure {{ int {name} = body~load_uint({width}); "
                f"body.end_parse(); {guard} set_data(begin_cell().store_uint(1, 1).end_cell()); }}\n"
            )
            count = 0
            for mutant in (False, True):
                label = name + ("-deleted" if mutant else "-production")
                (work / "driver.fc").write_text(
                    renamed + (driver.replace(guard, "") if mutant else driver)
                )
                code = native.compile_contract(str(work / "driver.fc"), out / f"{label}.boc")
                emulator = native.Emulator(17)
                try:
                    tested = [0] if mutant else values
                    for value in tested:
                        initial = Cell().uint(0, 1)
                        result = emulator.send(
                            native.active_account((0, 100), code, initial),
                            native.internal(
                                (0, 101), (0, 100), Cell().uint(value, width), value=10**11
                            ),
                        )
                        expected = 0 if mutant or permitted(value) else error
                        assert result["success"] and result["details"]["exit"] == expected, (
                            name,
                            value,
                            result,
                        )
                        after = native.account_data(from_boc(result["shard_account"]))[0]
                        assert after.hash == Cell().uint(expected == 0, 1).hash
                        count += 1
                        if mutant:
                            assert not permitted(value), "mutation must accept a forbidden input"
                            (out / f"{label}.json").write_text(json.dumps(result, indent=2) + "\n")
                finally:
                    emulator.close()
            summaries[name] = {"cases": count, "deleted_guard_forbidden_input_exit": 0}
    (out / "results.json").write_text(json.dumps(summaries, indent=2) + "\n")
    print(
        f"{sum(s['cases'] for s in summaries.values())} cases passed; {len(cases)} guard deletion controls"
    )


if __name__ == "__main__":
    main()
