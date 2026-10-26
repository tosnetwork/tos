"""Fill v16 deployment vectors after checking independently authored assertions.

EMULATOR_PATH must point to a native emulator built from the reviewed reference.
Usage: deploy_state.py --output <deploy-state.json>
"""

# ruff: noqa: E402
import argparse
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / "test/auth-extensions"))
import native
from cells import Cell, from_boc, make_dict, read_dict


def account(address, init, status):
    if status == "nonexist":
        acc = Cell().uint(0, 1)
    else:
        storage = Cell().uint(0, 64).coins(100_000_000_000).uint(0, 1)
        if status == "active":
            storage.uint(1, 1)
            storage.bits += init.bits
            storage.refs.extend(init.refs)
        elif status == "frozen":
            storage.uint(1, 2).uint(int.from_bytes(init.hash, "big"), 256)
        else:
            storage.uint(0, 2)
        seen = {}

        def visit(cell):
            if cell.hash in seen:
                return
            seen[cell.hash] = len(cell.bits)
            for ref in cell.refs:
                visit(ref)

        visit(storage)
        acc = (
            Cell()
            .uint(1, 1)
            .addr(address)
            .varuint(len(seen), 7)
            .varuint(sum(seen.values()), 7)
            .uint(0, 3)
            .uint(native.NOW, 32)
            .uint(0, 1)
        )
        acc.bits += storage.bits
        acc.refs.extend(storage.refs)
    return Cell().uint(0, 320).ref(acc)


def flags(tx):
    s = tx.refs[2].slice()
    assert s.uint(4) == 0
    s.uint(1)
    if s.uint(1):
        s.coins()
        if s.uint(1):
            s.coins()
        if s.uint(1):
            s.uint(1)
    if s.uint(1):
        if s.uint(1):
            s.coins()
        s.coins()
        s.maybe()
    assert s.uint(1)
    return [bool(s.uint(1)), bool(s.uint(1)), bool(s.uint(1))]


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
rows = []
scenarios = [
    (status, mode)
    for status in ["nonexist", "uninit", "frozen", "active"]
    for mode in ["ordinary", "precompiled", "unaffordable"]
]
scenarios.append(("nonexist", "prefix"))
scenarios += [
    (status, mode)
    for status in ["uninit", "active"]
    for mode in ["external", "external-precompiled"]
]
for status, mode in scenarios:
    programs = [
        ("accept", bytes.fromhex("f800"), True, 0),
        ("throw", bytes.fromhex("f800f22a"), False, 42),
        ("commit-throw", bytes.fromhex("f800f80ff22a"), True, 42),
    ]
    if mode.startswith("external"):
        programs.append(("no-accept", b"", False, 0))
    for name, code, committed, exit_code in programs:
        init = native.state_init(Cell().raw(code), Cell())
        if mode == "prefix":
            init = Cell().uint(33, 6).uint(0, 1).maybe(Cell().raw(code)).maybe(Cell()).uint(0, 1)
        address = (0, 0x1234 if status == "frozen" else int.from_bytes(init.hash, "big"))
        if mode == "prefix":
            address = (0, address[1] ^ (1 << 255))
        shard = account(address, init, status)
        message = (
            Cell()
            .uint(4, 4)
            .addr((0, 0x9999))
            .addr(address)
            .coins(1_000_000_000)
            .uint(0, 1)
            .coins(0)
            .coins(0)
            .uint(0, 64)
            .uint(native.NOW, 32)
            .uint(1, 1)
            .uint(1, 1)
            .ref(init)
            .uint(1, 1)
            .ref(Cell())
        )
        if mode.startswith("external"):
            message = (
                Cell()
                .uint(8, 4)
                .addr(address)
                .coins(0)
                .uint(1, 1)
                .uint(1, 1)
                .ref(init)
                .uint(1, 1)
                .ref(Cell())
            )
        configuration = native.config(16)
        if mode in ("precompiled", "external-precompiled", "unaffordable"):
            entries = read_dict(configuration, 32)
            usage = 2_000_000 if mode == "unaffordable" else 1000
            listing = make_dict(
                {
                    int.from_bytes(Cell().raw(code).hash, "big"): Cell()
                    .uint(0xB0, 8)
                    .uint(usage, 64)
                },
                256,
            )
            entries[45] = Cell().ref(Cell().uint(0xC0, 8).maybe(listing))
            configuration = make_dict(entries, 32)
        em = native.Emulator.from_config(configuration)
        try:
            result = em.send(shard, message)
        finally:
            em.close()
        if name == "no-accept":
            assert not result["success"] and result["external_not_accepted"], result
            assert result["vm_exit_code"] == 0, result
            rows.append(
                {
                    "name": status + "-" + mode + "-" + name,
                    "account": shard.refs[0].boc().hex(),
                    "message": message.boc().hex(),
                    "now": native.NOW,
                    "lt": em.lt,
                    "config": configuration.boc().hex(),
                    "rejected_exit": 0,
                }
            )
            continue
        assert result["success"], (status, name, result)
        tx = from_boc(result["transaction"])
        if mode == "unaffordable":
            assert result["details"]["skipped"]
            assert result["details"]["reason"].startswith("10"), result["details"]
        else:
            used = status != "active"
            expected = [committed, used, used and committed]
            actual = flags(tx)
            assert actual == expected, (status, name, actual, expected)
            assert result["details"]["exit"] == exit_code, result["details"]
            # opctable.h: 10 + encoded bits per instruction; vm.h: implicit RET 5,
            # exception dispatch 50. ACCEPT/COMMIT/short THROW each occupy 16 bits.
            gas = 26 + 5 if name == "accept" else 26 + 26 + 50
            if name == "commit-throw":
                gas += 26
            if mode in ("precompiled", "external-precompiled"):
                gas = 1000
            assert result["details"]["gas"] == gas, result["details"]
            assert result["details"]["compute_success"] == committed
            assert result["details"]["aborted"] == (not committed)
            assert (result["details"]["action"] is not None) == committed
        row = {
            "name": status + "-" + mode + "-" + name,
            "account": shard.refs[0].boc().hex(),
            "message": message.boc().hex(),
            "expected_account": from_boc(result["shard_account"]).refs[0].boc().hex(),
            "now": native.NOW,
            "lt": em.lt,
            "config": configuration.boc().hex(),
            "tx_hash": tx.hash.hex(),
            "account_hash": from_boc(result["shard_account"]).refs[0].hash.hex(),
        }
        rows.append(row)
args.output.write_text(json.dumps(rows, indent=2) + "\n")
print(f"{len(rows)} native deployment cases passed independent assertions")
