"""Fill native zero-option normalization, freezing and successor transactions."""

import argparse
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / "test/auth-extensions"))
import native  # noqa: E402
from cells import Cell, from_boc  # noqa: E402

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
code, data = Cell().raw(bytes.fromhex("f800")), Cell()
canonical = native.state_init(code, data)
wrapped = from_boc((root / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())


def initial(prefix, special, freeze, address, existing=False):
    init = Cell().uint(prefix, 1)
    if prefix:
        init.uint(0, 5)
    init.uint(special, 1)
    if special:
        init.uint(0, 2)
    init.maybe(code).maybe(data).uint(0, 1)
    storage = Cell().uint(0, 64).coins(0 if freeze else 100_000_000_000).uint(0, 1).uint(1, 1)
    if existing:
        storage.bits = storage.bits[:-1]
        storage.uint(1, 2).uint(address, 256)
    else:
        storage.bits += init.bits
        storage.refs = list(init.refs)
    account = (
        Cell()
        .uint(1, 1)
        .addr((0, address))
        .varuint(0, 7)
        .varuint(1000, 7)
        .uint(0, 3)
        .uint(native.NOW - 10000 if freeze else native.NOW, 32)
        .uint(freeze, 1)
    )
    if freeze:
        account.coins(1 << 50)
    account.bits += storage.bits
    account.refs = list(storage.refs)
    return Cell().uint(0, 320).ref(account)


def init_message(bounce, address):
    message = native.internal((0, 0x9999), (0, address), Cell(), value=1 << 55)
    # Message init present/in-reference, body in-reference. Header bounce controls
    # whether storage freezing precedes or follows the incoming credit phase.
    return Cell(
        bits=("0110" if bounce else "0100") + message.bits[4:-2] + "111",
        refs=[canonical] + message.refs,
    )


def shape(shard):
    a = shard.refs[0].slice()
    assert a.uint(1) == 1
    a.addr()
    cells, bits = a.varuint(7), a.varuint(7)
    assert a.uint(3) == 0
    a.uint(32)
    if a.uint(1):
        a.coins()
    a.uint(64)
    a.coins()
    assert a.maybe() is None
    if a.uint(1):
        assert a.uint(1) == 0 and a.uint(1) == 0, "final active options must be absent"
        assert a.maybe().hash == code.hash and a.maybe().hash == data.hash
        assert a.maybe() is None
        return "active", cells, bits
    if a.uint(1):
        assert a.uint(256) == int.from_bytes(canonical.hash, "big")
        return "frozen", cells, bits
    return "uninit", cells, bits


def fill_case(prefix, special, mode, address, version):
    configuration = native.config(version)
    config = Cell(bits=wrapped.bits, refs=[configuration])
    freeze = mode not in ["active", "existing-frozen"]
    shard = initial(prefix, special, freeze, address, mode == "existing-frozen")
    em = native.Emulator.from_config(configuration)
    if mode == "active":
        messages = [native.external((0, address), Cell())] * 2
    elif mode == "freeze-successor":
        messages = [
            native.internal((0, 0x9999), (0, address), Cell(), value=0),
            init_message(False, address),
        ]
    elif mode == "same-transaction-init":
        messages = [init_message(True, address)]
    else:
        messages = [
            native.internal(
                (0, 0x9999),
                (0, address),
                Cell(),
                value=1_000_000 if mode == "existing-frozen" else 0,
            )
        ]
    rows = []
    try:
        for index, message in enumerate(messages):
            before = shard
            result = em.send(shard, message)
            assert result["success"], result
            shard = from_boc(result["shard_account"])
            details = result["details"]
            if mode == "active":
                assert shape(shard) == ("active", 0, 1000 - 5 * prefix - 2 * special)
                skipped = None
            elif mode == "freeze-successor" and index == 1:
                assert shape(shard) == ("active", 3, 147)
                skipped = None
            else:
                if mode == "existing-frozen":
                    assert shape(shard) == ("uninit", 0, 744)
                    skipped = "NoState"
                else:
                    # Zero balance: LT64 + coin length4 + extra-presence1 +
                    # Uninit2 =71; Frozen adds its256-bit hash, hence327.
                    expected = ("uninit", 1, 71) if address else ("frozen", 1, 327)
                    assert shape(shard) == expected, (
                        mode,
                        address,
                        version,
                        shape(shard),
                        expected,
                    )
                    skipped = "BadState" if mode == "same-transaction-init" else "NoGas"
                assert (
                    details["skipped"]
                    and details["reason"]
                    == {"NoState": "000", "BadState": "010", "NoGas": "100"}[skipped]
                ), details
            if skipped is None:
                # ACCEPT26 + implicit RET5. Frozen successor's incoming credit
                # clears debt before storage, then canonical StateInit binds hash.
                assert details["gas"] == 31 and details["exit"] == 0
                assert details["compute_success"] and not details["aborted"]
                assert details["action"]["success"] and details["action"]["code"] == 0
            status = shape(shard)[0]
            # Below13 the physical Uninit conversion still has logical Frozen
            # end status. Native changed the logical status from version13.
            end_status = "frozen" if status == "uninit" and version < 13 else status
            transaction = from_boc(result["transaction"])
            t = transaction.slice()
            assert t.uint(4) == 7
            for width in [256, 64, 256, 64, 32, 15, 2]:
                t.uint(width)
            assert t.uint(2) == {"uninit": 0, "frozen": 1, "active": 2}[end_status]
            row = dict(
                now=native.NOW,
                lt=em.lt,
                input_shard=before.boc().hex(),
                message=message.boc().hex(),
                status=status,
                end_status=end_status,
                transaction_hash=transaction.hash.hex(),
                account_hash=shard.refs[0].hash.hex(),
                shard_hash=shard.hash.hex(),
            )
            if skipped:
                row["skipped_reason"] = skipped
            else:
                row.update(gas=31, exit_code=0, aborted=False, action_code=0)
            rows.append(row)
    finally:
        em.close()
    suffix = "-selfhash" if address else ""
    if version != 16:
        suffix += f"-v{version}"
    return dict(
        name=f"{mode}-prefix{int(prefix)}-special{int(special)}{suffix}",
        config_boc=config.boc().hex(),
        rows=rows,
    )


cases = []
canonical_address = int.from_bytes(canonical.hash, "big")
for address in [0, canonical_address]:
    for prefix, special in [(False, False), (True, False), (False, True), (True, True)]:
        for mode in ["active", "freeze-successor", "same-transaction-init"]:
            cases.append(fill_case(prefix, special, mode, address, 16))
for version in [12, 13]:
    cases.append(fill_case(False, False, "freeze-only", canonical_address, version))
for version in [12, 13, 16]:
    for address in [0, canonical_address]:
        cases.append(fill_case(False, False, "existing-frozen", address, version))
# A graph-consistent self-hash account crosses the real storage-fee freeze
# threshold without an injected due_payment. This control is not dependent on
# deliberately inconsistent counters used by the original policy regressions.
large = None
for index in range(128):
    parent = Cell().uint(index, 32).uint(0, 991)
    if large is not None:
        parent.ref(large)
    large = parent
state = native.state_init(code, large)
address = int.from_bytes(state.hash, "big")
storage = Cell().uint(0, 64).coins(0).uint(0, 1).uint(1, 1)
storage.bits += state.bits
storage.refs = list(state.refs)
assert len(storage.bits) == 75
used_cells, used_bits = 128 + 1 + 1, 128 * 1023 + 16 + 75
assert (used_cells, used_bits) == (130, 131035)
account = (
    Cell()
    .uint(1, 1)
    .addr((0, address))
    .varuint(used_cells, 7)
    .varuint(used_bits, 7)
    .uint(0, 3)
    .uint(1, 32)
    .uint(0, 1)
)
account.bits += storage.bits
account.refs = list(storage.refs)
shard = Cell().uint(0, 320).ref(account)
message = native.internal((0, 0x9999), (0, address), Cell(), value=0)
configuration = native.config(16)
config = Cell(bits=wrapped.bits, refs=[configuration])
em = native.Emulator.from_config(configuration)
try:
    result = em.send(shard, message)
    lt = em.lt
finally:
    em.close()
assert result["success"] and result["details"]["skipped"] and result["details"]["reason"] == "100"
after = from_boc(result["shard_account"])
assert shape(after) == ("uninit", 1, 71)
transaction = from_boc(result["transaction"])
t = transaction.slice()
assert t.uint(4) == 7
for width in [256, 64, 256, 64, 32, 15]:
    t.uint(width)
assert t.uint(2) == 2 and t.uint(2) == 0
phase = transaction.refs[2].slice()
assert phase.uint(4) == 0 and phase.uint(1) == 1 and phase.uint(1) == 1
assert phase.coins() == 0 and phase.uint(1) == 1 and phase.coins() > 0
assert phase.uint(2) == 2, "storage phase must report Frozen"
cases.append(
    dict(
        name="consistent-storage-fee-freeze",
        config_boc=config.boc().hex(),
        rows=[
            dict(
                now=native.NOW,
                lt=lt,
                input_shard=shard.boc().hex(),
                message=message.boc().hex(),
                status="uninit",
                end_status="uninit",
                skipped_reason="NoGas",
                transaction_hash=transaction.hash.hex(),
                account_hash=after.refs[0].hash.hex(),
                shard_hash=after.hash.hex(),
            )
        ],
    )
)
assert len(cases) == 33 and sum(len(case["rows"]) for case in cases) == 49
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(dict(cases=cases), indent=2) + "\n")
print(f"PASS: 33 native option/freeze chains, 49 transactions: {args.output}")
