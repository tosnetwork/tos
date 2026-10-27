"""Fill native fundamental tick/OOG-tock/tick roots with live-state controls."""

import argparse
import ctypes
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / "test/auth-extensions"))
import native  # noqa: E402
from cells import Cell, from_boc, make_dict, read_dict  # noqa: E402

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()

# Tock writes X but exhausts gas before ACCEPT/COMMIT. Tick writes C.
# UNTIL:<{ GASCONSUMED; 2^12 PUSHPOW2; GREATER }> ACCEPT burns beyond2000.
c = Cell().uint(0x42, 8)
x = Cell().uint(0x43, 8)
burn = Cell().raw(bytes.fromhex("88ed5495f807830bbce6f800")).ref(x)
good = Cell().raw(bytes.fromhex("f80088ed54")).ref(c)
# DROP (entry selector -2), IFREFELSEREF (is_tock boolean).
code = Cell().raw(bytes.fromhex("30e30f")).ref(burn).ref(good)
init = Cell().uint(0, 1).uint(1, 1).uint(3, 2).maybe(code).maybe(code).uint(0, 1)
storage = Cell().uint(0, 64).coins(100_000_000_000).uint(0, 1).uint(1, 1)
storage.bits += init.bits
storage.refs = list(init.refs)
# Storage117 + code24 + burn96 + good40 + C8 + X8 =293, six unique cells.
assert len(storage.bits) == 117 and sum(len(v.bits) for v in [code, burn, good, c, x]) == 176
account = (
    Cell()
    .uint(1, 1)
    .addr((-1, 0x4545))
    .varuint(0, 7)
    .varuint(1000, 7)
    .uint(0, 3)
    .uint(native.NOW, 32)
    .uint(0, 1)
)
account.bits += storage.bits
account.refs = list(storage.refs)
shard = Cell().uint(0, 320).ref(account)
entries = read_dict(native.config(16), 32)
entries.pop(45, None)
prices = entries[20].refs[0]
offset = 136 if int(prices.bits[:8], 2) == 0xD1 else 0
assert int(prices.bits[offset : offset + 8], 2) == 0xDE
offset += 8 + 2 * 64
entries[20] = Cell().ref(
    Cell(
        bits=prices.bits[:offset] + format(2000, "064b") + prices.bits[offset + 64 :],
        refs=prices.refs,
    )
)
entries[31] = Cell().ref(Cell().maybe(make_dict({0x4545: Cell()}, 256)))
configuration = make_dict(entries, 32)
config_root = from_boc((root / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())
config = Cell(bits=config_root.bits, refs=[configuration])
em = native.Emulator.from_config(configuration)
function = em.lib.transaction_emulator_emulate_tick_tock_transaction
function.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_bool]
function.restype = ctypes.c_void_p
rows = []
try:
    for index, is_tock in enumerate([False, True, False]):
        before = shard
        lt = (index + 2) * 1_000_000
        em.lib.transaction_emulator_set_lt(em.ptr, lt)
        pointer = function(em.ptr, shard.b64(), is_tock)
        assert pointer
        try:
            result = json.loads(ctypes.string_at(pointer))
        finally:
            em.lib.string_destroy(pointer)
        assert result["success"], result
        transaction = from_boc(result["transaction"])
        d = transaction.refs[2].slice()
        assert d.uint(3) == 1 and bool(d.uint(1)) == is_tock
        d.coins()
        if d.uint(1):
            d.coins()
        if d.uint(1):
            d.uint(1)
        assert d.uint(1) == 1
        assert bool(d.uint(1)) == (not is_tock)
        d.uint(2)
        d.coins()
        vm = d.ref().slice()
        gas, limit = vm.varuint(7), vm.varuint(7)
        if vm.uint(1):
            vm.varuint(3)
        vm.sint(8)
        exit_code = vm.sint(32)
        d.maybe()
        assert bool(d.uint(1)) == is_tock
        # Success formula: DROP18 + IFREFELSEREF26 + branch load100 +
        # ACCEPT26 + PUSHREF18 + POPc4=26 + two implicit RET5 =224.
        # Prices: crypto/vm/opctable.h, contops.cpp and vm.h.
        assert gas == (2000 if is_tock else 224) and limit == 2000, (gas, limit)
        assert exit_code == (-14 if is_tock else 0), exit_code
        shard = from_boc(result["shard_account"])
        after = shard.refs[0]
        assert after.refs[0].hash == code.hash and after.refs[1].hash == c.hash
        a = after.slice()
        assert a.uint(1) == 1
        a.addr()
        assert a.varuint(7) == 6 and a.varuint(7) == 293 and a.uint(3) == 0
        rows.append(
            dict(
                now=native.NOW,
                lt=lt,
                is_tock=is_tock,
                input_shard=before.boc().hex(),
                gas=gas,
                exit_code=exit_code,
                aborted=is_tock,
                transaction_hash=transaction.hash.hex(),
                account_hash=after.hash.hex(),
                shard_hash=shard.hash.hex(),
            )
        )
finally:
    em.close()
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(dict(config_boc=config.boc().hex(), rows=rows), indent=2) + "\n")
print(f"PASS: tick/OOG-tock/tick native rows: {args.output}")
