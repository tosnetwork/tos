"""Strict full-wallet storage admission; no message authorization or vault deployment."""

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))

from cells import Cell, from_boc  # noqa: E402
from native import (  # noqa: E402
    Emulator,
    account_data,
    active_account,
    compile_contract,
    internal,
    state_init,
)
from test_auth import KEY  # noqa: E402
from test_identity import chain, module_data  # noqa: E402


def fee(version=1, profile=1, slot=3600, per_slot=4, key=None, tree_id=456):
    if key is None:
        key = Cell().uint(1, 32).uint(8, 32).uint(3, 32).uint(7, 128).uint(9, 256)
    return (
        Cell()
        .uint(version, 8)
        .uint(profile, 8)
        .uint(tree_id, 256)
        .uint(123, 32)
        .uint(slot, 32)
        .uint(per_slot, 16)
        .ref(key)
    )


def state(
    module,
    metadata=None,
    version=4,
    mode=2,
    retired=0xFFFF,
    seqno=0xFFFFFFFF,
    epoch=2**64 - 1,
    primary=2**64 - 1,
    rescue=2**64 - 1,
    flag=0,
    extensions=None,
    key=0,
):
    a = (
        Cell()
        .uint(version, 8)
        .uint(mode, 2)
        .uint(retired, 16)
        .uint(epoch, 64)
        .uint(primary, 64)
        .uint(rescue, 64)
        .ref(module)
        .ref(metadata or fee())
    )
    s = (
        Cell()
        .uint(flag, 1)
        .uint(seqno, 32)
        .uint(42, 32)
        .uint(key, 256)
        .uint(extensions is not None, 1)
    )
    if extensions is not None:
        s.ref(extensions)
    return s.ref(a)


def run(code, pinned, candidate, expected):
    initial = Cell().uint(int.from_bytes(pinned.hash, "big"), 256)
    e = Emulator(17)
    try:
        result = e.send(
            active_account((0, 100), code, initial),
            internal((0, 101), (0, 100), Cell().ref(candidate), value=100_000_000_000),
        )
        assert result["success"], result
        actual = result["details"]["exit"]
        assert actual == expected, f"expected exit {expected}, got {actual}"
        data = account_data(from_boc(result["shard_account"]))[0]
        assert data.hash == (candidate if expected == 0 else initial).hash
        return result["details"]
    finally:
        e.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    out = p.parse_args().output
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for name in [
            "wallet-v5r2-state.fc",
            "wallet-v5r2-identity.fc",
            "pq-bytes.fc",
            "wallet-v5r2-common.fc",
        ]:
            shutil.copyfile(ROOT / "crypto/smartcont" / name, work / name)
        shutil.copyfile(ROOT / "test/wallet-v5r2/state-driver.fc", work / "driver.fc")
        code = compile_contract(str(work / "driver.fc"), out / "state.boc")
        module_code = compile_contract("rescue-dual-module.fc", out / "module.boc")
        module = state_init(module_code, module_data())
        cases = {"saturated_roundtrip": run(code, module_code, state(module), 0)}
        cases["classical_key_refused"] = run(code, module_code, state(module, key=KEY), 1819)
        cases["fresh_roundtrip"] = run(
            code, module_code, state(module, seqno=0, epoch=0, primary=0, rescue=0, retired=0), 0
        )
        missing = state(module)
        missing.refs = []
        cases["missing_auth"] = run(code, module_code, missing, 9)
        extra = state(module)
        extra.bits += "0"
        cases["trailing_base"] = run(code, module_code, extra, 9)
        extra = state(module)
        extra.refs[0].bits += "0"
        cases["trailing_auth"] = run(code, module_code, extra, 9)
        extra_fee = fee()
        extra_fee.bits += "0"
        cases["trailing_fee"] = run(code, module_code, state(module, metadata=extra_fee), 9)
        for name, kwargs, error in [
            ("legacy_flag", {"flag": 1}, 1819),
            ("extensions", {"extensions": Cell()}, 1819),
            ("old_version", {"version": 2}, 1819),
            ("hybrid_storage_version", {"version": 3}, 1819),
            ("mode0", {"mode": 0}, 1806),
            ("mode1", {"mode": 1}, 1806),
            ("mode3_refused", {"mode": 3}, 1806),
        ]:
            cases[name] = run(code, module_code, state(module, **kwargs), error)
        for name, kwargs in [
            ("version", {"version": 2}),
            ("profile", {"profile": 2}),
            ("counter_mode", {"per_slot": 0}),
            ("slot", {"slot": 1}),
            ("short_key", {"key": chain(bytes(59))}),
            ("bare_lms", {"key": chain(bytes(56))}),
            ("wrong_types", {"key": chain(bytes(60))}),
        ]:
            cases["fee_" + name] = run(
                code, module_code, state(module, metadata=fee(**kwargs)), 1819
            )
        cases["wrong_module_code"] = run(code, Cell(), state(module), 1815)
        cases["wrong_network"] = run(
            code, module_code, state(state_init(module_code, module_data(network=124))), 1815
        )
        mutants = {}
        for name, old, new, candidate, expected in [
            (
                "strict_mode",
                "  throw_unless(auth::bad_mode, mode == 2);",
                "",
                state(module, mode=1),
                1806,
            ),
            (
                "fee_profile",
                "  throw_unless(r2state::invalid, s~load_uint(8) == 1);",
                "  s~load_uint(8);",
                state(module, metadata=fee(profile=2)),
                1819,
            ),
        ]:
            src = ROOT / "crypto/smartcont/wallet-v5r2-state.fc"
            text = src.read_text()
            if name == "fee_profile":
                # Replace the second occurrence (profile), preserving version validation.
                pos = text.index(old, text.index(old) + len(old))
                text = text[:pos] + new + text[pos + len(old) :]
            else:
                assert text.count(old) == 1
                text = text.replace(old, new)
            (work / src.name).write_text(text)
            mutant = compile_contract(str(work / "driver.fc"), out / (name + ".boc"))
            try:
                run(mutant, module_code, candidate, expected)
            except AssertionError as error:
                assert "got 0" in str(error), str(error)
                mutants[name] = str(error)
            else:
                raise AssertionError("mutation survived: " + name)
            run(code, module_code, candidate, expected)
        report = {"scope": __doc__, "cases": cases, "mutations": mutants}
        (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"{len(cases)} cases; {len(mutants)} mutation controls passed")


if __name__ == "__main__":
    main()
