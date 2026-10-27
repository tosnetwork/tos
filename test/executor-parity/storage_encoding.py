"""Fill native-accepted storage layouts before checking Rust round trips.

Every original storage hash/bit length is derived from the authored fields and
then checked through the production C++ Account decoder. Two nonminimal coin
controls must be rejected by that decoder; they remain the separate U3 finding.
"""

import argparse
import itertools
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(root / "test/rel02"), str(root / "test/auth-extensions")]
import run_rust as bounded  # noqa: E402
from cells import Cell, make_dict  # noqa: E402

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--native", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()

code = Cell().raw(bytes.fromhex("f800"))
data = Cell().uint(0x42, 8)
# SimpleLib: public Bool followed by the root reference.
library = make_dict({int.from_bytes(code.hash, "big"): Cell().uint(1, 1).ref(code)}, 256)
extra = make_dict({17: Cell().varuint(1234567, 32)}, 32)
rows = []


def add(
    name,
    state="active",
    balance=255,
    currencies=False,
    prefix=None,
    special=None,
    has_code=True,
    has_data=True,
    has_library=False,
    dict_hash=False,
    due=None,
    malformed=None,
):
    storage = Cell().uint(0, 64)
    if malformed is None:
        storage.coins(balance)
    else:
        # Value1 encoded with a leading zero in a two/three-byte coin integer.
        storage.uint(malformed, 4).uint(1, malformed * 8)
    storage.maybe(extra if currencies else None)
    refs = []
    if state == "active":
        storage.uint(1, 1).uint(prefix is not None, 1)
        if prefix is not None:
            storage.uint(prefix, 5)
        storage.uint(special is not None, 1)
        if special is not None:
            storage.uint(special, 2)
        for present, value in [(has_code, code), (has_data, data), (has_library, library)]:
            storage.maybe(value if present else None)
            if present:
                refs.append(value.hash.hex())
        state_bits = 6 + (5 if prefix is not None else 0) + (2 if special is not None else 0)
    elif state == "uninit":
        storage.uint(0, 2)
        state_bits = 2
    else:
        assert state == "frozen"
        storage.uint(1, 2).uint(0x4545, 256)
        state_bits = 258
    coin_bytes = (balance.bit_length() + 7) // 8 if malformed is None else malformed
    assert len(storage.bits) == 64 + 4 + coin_bytes * 8 + 1 + state_bits
    account = Cell().uint(1, 1).addr((0, 0)).varuint(0, 7).varuint(1000, 7).uint(int(dict_hash), 3)
    if dict_hash:
        account.uint(int.from_bytes(bytes([0x55]) * 32, "big"), 256)
    account.uint(1780000000, 32).uint(due is not None, 1)
    if due is not None:
        account.coins(due)
    account.bits += storage.bits
    account.refs = list(storage.refs)
    assert len(account.bits) <= 1023 and len(account.refs) <= 4
    shard = Cell().uint(0, 320).ref(account)
    rows.append(
        dict(
            name=name,
            shard=shard.boc().hex(),
            storage_bits=len(storage.bits),
            storage_hash=storage.hash.hex(),
            references=refs,
            native_accepted=malformed is None,
        )
    )


for state, balance in itertools.product(
    ["active", "uninit", "frozen"], [0, 255, 256, (1 << 24) - 1, 1 << 24, (1 << 120) - 1]
):
    add(f"coin-{state}-{balance}", state=state, balance=balance)
for state, dict_hash, due in itertools.product(
    ["active", "uninit", "frozen"], [False, True], [None, 0, 1, 256]
):
    add(f"metadata-{state}-{int(dict_hash)}-{due}", state=state, dict_hash=dict_hash, due=due)
for index, (prefix, special, has_code, has_data, has_library, currencies) in enumerate(
    itertools.product(
        [None, 0, 30],
        [None, 0, 1, 2, 3],
        [False, True],
        [False, True],
        [False, True],
        [False, True],
    )
):
    add(
        f"stateinit-{index}",
        prefix=prefix,
        special=special,
        has_code=has_code,
        has_data=has_data,
        has_library=has_library,
        currencies=currencies,
        dict_hash=True,
        due=256,
    )
for width in [2, 3]:
    add(f"nonminimal-coin-{width}", balance=1, malformed=width)
assert len(rows) == 284 and len({row["name"] for row in rows}) == 284
args.output.parent.mkdir(parents=True, exist_ok=True)
inputs = args.output.with_suffix(".inputs.tsv")
inputs.write_text("".join(row["name"] + "\t" + row["shard"] + "\n" for row in rows))
# Reuse the reviewed REL-02 supervisor's CPU/AS/output limits and cancellation
# cleanup. A native decoder failure must never leave a successful fixture.
stdout, stderr = bounded.execute(
    [str(args.native.resolve()), str(inputs)], args.output.parent, args.output.stem + "-native"
)
args.output.with_suffix(".native.tsv").write_bytes(stdout)
args.output.with_suffix(".native.stderr").write_bytes(stderr)
observed = [line.split("\t") for line in stdout.decode().splitlines()]
assert len(observed) == len(rows)
for row, fields in zip(rows, observed, strict=True):
    assert len(fields) == 4 and fields[0] == row["name"], fields
    assert fields[1] == str(int(row["native_accepted"])), (row["name"], fields)
    if row["native_accepted"]:
        assert int(fields[2]) == row["storage_bits"] and fields[3].lower() == row["storage_hash"], (
            row["name"]
        )
    else:
        assert fields[2:] == ["-", "-"]
fixture = dict(
    rows=[row for row in rows if row["native_accepted"]],
    rejected_controls=[row["name"] for row in rows if not row["native_accepted"]],
)
assert len(fixture["rows"]) == 282 and len(fixture["rejected_controls"]) == 2
args.output.write_text(json.dumps(fixture, indent=2) + "\n")
args.output.with_suffix(".fixture.tsv").write_text(
    "#native-account-storage-v1\n"
    + "".join(
        "\t".join(
            [
                row["name"],
                row["shard"],
                str(row["storage_bits"]),
                row["storage_hash"],
                ",".join(row["references"]) or "-",
            ]
        )
        + "\n"
        for row in fixture["rows"]
    )
)
print(f"PASS: 282 native-accepted storage layouts; two nonminimal controls rejected: {args.output}")
