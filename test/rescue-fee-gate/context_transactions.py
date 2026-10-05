"""Compare complete native/Rust outcomes, preserving original input-cell encoding."""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-extensions"))
from native import account_data, from_boc, outgoing  # noqa: E402


def normalized(result):
    if not result["success"]:
        return [str(result.get("vm_exit_code", -(1 << 31))), "0", "-", "-"]
    d = result["details"]
    data, balance = account_data(from_boc(result["shard_account"]))
    messages = outgoing(from_boc(result["transaction"]))
    return [
        str(d["exit"]),
        str(d["action"]["code"] if d["action"] else 0),
        ",".join(m.hash.hex() for m in messages) or "-",
        str(balance),
        data.hash.hex(),
    ]


def compare(output, driver):
    result = subprocess.run(
        [str(driver), str(output / "config.boc"), str(output / "transactions.tsv"), "17"],
        capture_output=True,
        text=True,
        check=True,
    )
    (output / "rust-transactions.tsv").write_text(result.stdout)
    got = {}
    for line in result.stdout.splitlines():
        name, *values = line.split("\t")
        assert name not in got, name
        got[name] = values
    expected = {}
    for line in (output / "transactions.tsv").read_text().splitlines():
        name = line.split("\t")[0]
        expected[name] = normalized(json.loads((output / f"{name}.json").read_text()))
    assert set(got) == set(expected), "transaction set mismatch"
    for name in expected:
        assert got[name] == expected[name], (name, got[name], expected[name])
    return len(got)


def replay_native(output):
    """Re-run retained original inputs after mutation builds have restored the library."""
    from native import Cell, Emulator

    emulator = Emulator(17)
    count = 0
    try:
        for line in (output / "transactions.tsv").read_text().splitlines():
            name, _, lt, account, message, _ = line.split("\t")
            shard = Cell().uint(0, 256).uint(0, 64).ref(from_boc(bytes.fromhex(account)))
            emulator.lt = int(lt) - 1_000_000
            actual = emulator.send(shard, from_boc(bytes.fromhex(message)))
            expected = json.loads((output / f"{name}.json").read_text())
            assert normalized(actual) == normalized(expected), (
                name,
                normalized(actual),
                normalized(expected),
            )
            if actual["success"]:
                assert actual["details"]["gas"] == expected["details"]["gas"], name
            count += 1
        assert count > 0
        return count
    finally:
        emulator.close()


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--rust", type=Path, required=True)
    a = p.parse_args()
    print(json.dumps({"matched_transactions": compare(a.output, a.rust)}))


def check_getter_context(lib, code, config_cell, address):
    """A compute-only getter must never inherit authenticated import statistics."""
    import ctypes

    from native import Cell

    lib.tvm_emulator_create.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    lib.tvm_emulator_create.restype = ctypes.c_void_p
    lib.tvm_emulator_set_c7.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_uint32,
        ctypes.c_uint64,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]
    lib.tvm_emulator_set_c7.restype = ctypes.c_bool
    lib.tvm_emulator_run_get_method.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]
    lib.tvm_emulator_run_get_method.restype = ctypes.c_void_p
    lib.tvm_emulator_destroy.argtypes = [ctypes.c_void_p]
    ptr = lib.tvm_emulator_create(code.b64(), Cell().b64(), 1)
    assert ptr
    try:
        assert lib.tvm_emulator_set_c7(
            ptr,
            f"{address[0]}:{address[1]:064x}".encode(),
            1780000000,
            100000000000,
            b"00" * 32,
            config_cell.b64(),
        )
        raw = lib.tvm_emulator_run_get_method(ptr, 12345, Cell().uint(0, 24).b64())
        assert raw
        try:
            result = json.loads(ctypes.string_at(raw))
        finally:
            lib.string_destroy(raw)
        assert result["success"] and result["vm_exit_code"] == 0, result
        stack = from_boc(result["stack"]).slice()
        assert stack.uint(24) == 1
        stack.ref()  # empty previous stack list
        assert stack.uint(8) == 1 and stack.sint(64) == -1
        stack.end()
        return result
    finally:
        lib.tvm_emulator_destroy(ptr)
