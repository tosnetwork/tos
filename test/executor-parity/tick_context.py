"""Explicit tick/tock execution context, fees and rollback versus native v16."""

import argparse
import ctypes
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/auth-extensions"), str(ROOT / "test/rel02")]
import native  # noqa: E402
from cells import Cell, from_boc, make_dict, read_dict  # noqa: E402
from gas_purchase import expected_fee  # noqa: E402
from run_rust import binary_hash, execute  # noqa: E402


def cases():
    rows = [
        dict(
            name=f"{variant}-wc{wc}-cp31{int(fundamental)}-flags{flags}-tock{int(tock)}",
            variant=variant,
            wc=wc,
            fundamental=fundamental,
            flags=flags,
            tock=tock,
        )
        for variant in ("accept", "throw", "past", "due", "future", "zero", "stack")
        for wc in (-1, 0)
        for fundamental in (False, True)
        for flags in (None, 0, 1, 2, 3)
        for tock in (False, True)
    ]
    rows += [
        dict(
            name=f"state-{status}-{variant}-wc{wc}-cp31{int(fundamental)}-tock{int(tock)}",
            status=status,
            variant=variant,
            wc=wc,
            fundamental=fundamental,
            flags=None,
            tock=tock,
        )
        for status in ("uninit", "frozen")
        for variant in ("accept", "zero")
        for wc in (-1, 0)
        for fundamental in (False, True)
        for tock in (False, True)
    ]
    rows += [
        dict(
            name=f"state-none-tock{int(tock)}",
            status="none",
            variant="accept",
            wc=0,
            fundamental=False,
            flags=None,
            tock=tock,
        )
        for tock in (False, True)
    ]
    return rows


def fixture(case, *, balance=None, paid=None, lt=0, due=None, canonical=False, data=None):
    entries = read_dict(native.config(16), 32)
    entries.pop(45, None)
    members = {0x4545: Cell()} if case["fundamental"] else {}
    entries[31] = Cell().ref(Cell().maybe(make_dict(members, 256)))
    configuration = make_dict(entries, 32)
    status = case.get("status", "active")
    if status == "none":
        return configuration, Cell().uint(0, 320).ref(Cell().uint(0, 1))
    variant = case["variant"]
    code_bytes = (
        "303030c801fa02c9ed54f800"
        if variant == "stack"
        else "f22a"
        if variant == "throw"
        else "f800"
    )
    code = Cell().raw(bytes.fromhex(code_bytes))
    flags = None if canonical and case["flags"] == 0 else case["flags"]
    init = Cell().uint(0, 1).uint(flags is not None, 1)
    if flags is not None:
        init.uint(flags, 2)
    init.maybe(code).maybe(Cell() if data is None else data).uint(0, 1)
    if balance is None:
        balance = 0 if variant == "zero" else 100_000_000_000
    storage = Cell().uint(lt, 64).coins(balance).uint(0, 1)
    if status == "active":
        storage.uint(1, 1)
        storage.bits += init.bits
        storage.refs = list(init.refs)
    else:
        storage.uint(status == "frozen", 2)
        if status == "frozen":
            storage.uint(0x1234, 256)
    seen = {}

    def visit(cell):
        if cell.hash in seen:
            return
        seen[cell.hash] = len(cell.bits)
        for child in cell.refs:
            visit(child)

    visit(storage)
    if paid is None:
        paid = native.NOW + (1 if variant == "future" else -100000 if variant == "past" else 0)
    if due is None:
        due = variant in ("due", "stack")
    account = (
        Cell()
        .uint(1, 1)
        .addr((case["wc"], 0x4545))
        .varuint(len(seen), 7)
        .varuint(sum(seen.values()), 7)
        .uint(0, 3)
        .uint(paid, 32)
        .uint(due, 1)
    )
    if due:
        account.coins(123456)
    account.bits += storage.bits
    account.refs = list(storage.refs)
    if canonical and status == "uninit" and balance == 0:
        account = Cell().uint(0, 1)
    return configuration, Cell().uint(0, 320).ref(account)


def account_fields(account):
    cell = account.slice()
    if not cell.uint(1):
        cell.end()
        return dict(none=True)
    address = cell.addr()
    cells, bits = cell.varuint(7), cell.varuint(7)
    assert cell.uint(3) == 0
    paid = cell.uint(32)
    due = cell.coins() if cell.uint(1) else 0
    lt, balance = cell.uint(64), cell.coins()
    return dict(
        address=list(address), cells=cells, bits=bits, paid=paid, due=due, lt=lt, balance=balance
    )


def details(transaction, shard, tock):
    root = transaction.slice()
    root.uint(695)  # tag, address, LT, predecessor, now, count and statuses
    total = root.coins()
    assert root.uint(1) == 0
    cell = transaction.refs[2].slice()
    assert cell.uint(3) == 1 and bool(cell.uint(1)) == tock
    storage = cell.coins()
    due = cell.coins() if cell.uint(1) else 0
    assert cell.uint(1) == 0, "these funded/zero fixtures retain account status"
    if cell.uint(1):
        success = bool(cell.uint(1))
        cell.uint(2)
        fee = cell.coins()
        vm = cell.ref().slice()
        gas, limit = vm.varuint(7), vm.varuint(7)
        assert vm.uint(1) == 0, "tick/tock has no external credit"
        vm.sint(8)
        compute = dict(success=success, fee=fee, gas=gas, limit=limit, exit=vm.sint(32))
    else:
        compute = dict(skipped=cell.uint(2))
    action = cell.maybe()
    aborted, destroyed = bool(cell.uint(1)), bool(cell.uint(1))
    cell.end()
    return dict(
        total=total,
        storage=storage,
        storage_due=due,
        compute=compute,
        action=action is not None,
        aborted=aborted,
        destroyed=destroyed,
        account=account_fields(shard.refs[0]),
    )


def worker(library, output):
    os.environ["EMULATOR_PATH"] = str(library)
    rows = []
    for case in cases():
        cfg, shard = fixture(case)
        name = case["name"]
        for kind, value in (("config", cfg), ("shard", shard)):
            (output / f"{name}.{kind}.boc").write_bytes(value.boc())
        em = native.Emulator.from_config(cfg, vm_log_verbosity=0)
        try:
            em.lib.transaction_emulator_set_lt(em.ptr, 2_000_000)
            function = em.lib.transaction_emulator_emulate_tick_tock_transaction
            function.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_bool]
            function.restype = ctypes.c_void_p
            pointer = function(em.ptr, shard.b64(), case["tock"])
            assert pointer
            try:
                result = json.loads(ctypes.string_at(pointer))
            finally:
                em.lib.string_destroy(pointer)
        finally:
            em.close()
        (output / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n")
        row = dict(
            name=name,
            inputs=dict(config=cfg.hash.hex(), shard=shard.hash.hex()),
            success=result["success"],
        )
        if result["success"]:
            tx, after = from_boc(result["transaction"]), from_boc(result["shard_account"])
            row.update(
                transaction=tx.hash.hex(),
                account=after.refs[0].hash.hex(),
                shard_account=after.hash.hex(),
                details=details(tx, after, case["tock"]),
            )
        else:
            assert "transaction" not in result and "shard_account" not in result
            error = result["error"]
            row["stage"] = (
                "storage"
                if "storage phase" in error
                else "account"
                if "account_none" in error or "Standard address" in error
                else "other"
            )
        rows.append(row)
    (output / "outcomes.json").write_text(json.dumps(rows, indent=2) + "\n")


def check_native(rows):
    assert len(rows) == len(cases()), "tick context population"
    for row, case in zip(rows, cases(), strict=True):
        cfg, shard = fixture(case)
        assert row["name"] == case["name"]
        assert row["inputs"] == dict(config=cfg.hash.hex(), shard=shard.hash.hex())
        if case["variant"] == "future" or case.get("status") == "none":
            assert set(row) == {"name", "inputs", "success", "stage"}
            expected_stage = "storage" if case["variant"] == "future" else "account"
            assert not row["success"] and row["stage"] == expected_stage
            continue
        assert row["success"] and set(row) == {
            "name",
            "inputs",
            "success",
            "transaction",
            "account",
            "shard_account",
            "details",
        }
        before = account_fields(shard.refs[0])
        d = row["details"]
        special = case["wc"] == -1 and case["fundamental"]
        storage_fee = 123456 if case["variant"] in ("due", "stack") else 0
        entries = read_dict(cfg, 32)
        if case["variant"] == "past" and not special:
            # This fixture has a single storage price interval covering its age.
            prices = read_dict(entries[18].refs[0], 32)
            assert len(prices) == 1
            price = next(iter(prices.values())).slice()
            assert price.uint(8) == 0xCC and price.uint(32) <= before["paid"]
            values = [price.uint(64) for _ in range(4)]
            price.end()
            bit_price, cell_price = values[2:] if case["wc"] == -1 else values[:2]
            storage_fee += (
                (before["bits"] * bit_price + before["cells"] * cell_price) * 100000 + 65535
            ) // 65536
        assert d["storage"] == storage_fee and d["storage_due"] == 0
        prices = entries[20 if case["wc"] == -1 else 21].refs[0].slice()
        assert prices.uint(8) == 0xD1
        flat, flat_fee = prices.uint(64), prices.uint(64)
        assert prices.uint(8) == 0xDE
        price, limit, special_limit = prices.uint(64), prices.uint(64), prices.uint(64)
        if case["variant"] == "zero":
            fee = 0
            assert d["compute"] == dict(skipped=2)
        elif case.get("status", "active") != "active":
            fee = 0
            assert d["compute"] == dict(skipped=0), case["name"]
        else:
            throws = case["variant"] == "throw"
            gas = (
                76
                if throws
                else (3 * 18 + 18 + 18 + 26 + 518 + 26 + 26 + 5)
                if case["variant"] == "stack"
                else 31
            )  # THROW42:26+50; ACCEPT26+implicitRET5.
            fee = 0 if special else expected_fee(price, flat, flat_fee, gas)
            assert d["compute"] == dict(
                success=not throws,
                fee=fee,
                gas=gas,
                limit=special_limit if special else limit,
                exit=42 if throws else 0,
            )
        aborted = case["variant"] in ("throw", "zero") or case.get("status", "active") != "active"
        assert d["aborted"] == aborted and d["action"] == (not aborted) and not d["destroyed"]
        assert d["total"] == storage_fee + fee
        after = d["account"]
        if case.get("status") == "uninit" and case["variant"] == "zero":
            assert after == dict(none=True)
        else:
            assert after["balance"] == before["balance"] - storage_fee - fee
            assert after["paid"] == (0 if special else native.NOW) and after["due"] == 0
            assert after["address"] == before["address"] and after["lt"] == 2_000_001
        # Independently construct the selected Account and its authenticated wrapper.
        # Do not copy metadata or state-update fields from the native result.
        _, predicted = fixture(
            case,
            balance=before["balance"] - storage_fee - fee,
            paid=0 if special else native.NOW,
            lt=2_000_001,
            due=False,
            canonical=True,
            data=Cell().coins(before["balance"] - storage_fee)
            if case["variant"] == "stack"
            else None,
        )
        assert row["account"] == predicted.refs[0].hash.hex(), (
            case["name"],
            after,
            account_fields(predicted.refs[0]),
        )
        transaction_hash = row["transaction"]
        assert len(transaction_hash) == 64 and all(
            c in "0123456789abcdef" for c in transaction_hash
        )
        predicted = (
            Cell().uint(int(transaction_hash, 16), 256).uint(2_000_000, 64).ref(predicted.refs[0])
        )
        assert row["shard_account"] == predicted.hash.hex()


def compare_reports(native_rows, rust_rows):
    check_native(native_rows)
    assert native_rows == rust_rows, "tick/tock context outcomes, fees or complete roots differ"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--worker", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if args.worker:
        worker(args.worker.resolve(), output)
        return
    assert args.native and args.rust
    reports = []
    for name, binary in (("native", args.native), ("rust", args.rust)):
        directory = output / name
        directory.mkdir(exist_ok=True)
        execute(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--worker",
                str(binary.resolve()),
                "--output",
                str(directory),
            ],
            output,
            name,
        )
        result = directory / "outcomes.json"
        assert result.stat().st_size <= 1024 * 1024
        reports.append(json.loads(result.read_text()))
    compare_reports(*reports)
    receipt = dict(
        cases=len(cases()),
        passed=True,
        source=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        source_diff_sha256=hashlib.sha256(
            subprocess.check_output(["git", "diff", "HEAD"], cwd=ROOT)
        ).hexdigest(),
        harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        native_binary_sha256=binary_hash(args.native),
        rust_binary_sha256=binary_hash(args.rust),
        outputs={
            name: hashlib.sha256((output / name / "outcomes.json").read_bytes()).hexdigest()
            for name in ("native", "rust")
        },
    )
    (output / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"PASS: {len(cases())} explicit tick/tock contexts and complete roots")


if __name__ == "__main__":
    main()
