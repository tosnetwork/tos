"""Fill two authored native transactions that exercise duplicate cache roots.

Code A uses SETCODE to install B while data still aliases A; B then changes
its data. The native opcode prices and graph sizes are asserted before any
roots are frozen. Rust tests retain the real Account/cache across both rows,
with cold and prewarmed input caches. Requires EMULATOR_PATH.
"""

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

# Opcode prices: ACCEPT26, PUSHREF18, SETCODE26+one new action cell500,
# POP c4=26, implicit RET5 (vm op table and cell-create gas price).
c = Cell().uint(0x42, 8)
b = Cell().raw(bytes([0xF8, 0x00, 0x88, 0xED, 0x54])).ref(c)
a = Cell().raw(bytes([0xF8, 0x00, 0x88, 0xFB, 0x04])).ref(b)
init = native.state_init(a, a)
storage = Cell().uint(0, 64).coins(100_000_000_000).uint(0, 1).uint(1, 1)
storage.bits += init.bits
storage.refs.extend(init.refs)
seen = {}


def visit(cell):
    if cell.hash in seen:
        return
    seen[cell.hash] = len(cell.bits)
    for r in cell.refs:
        visit(r)


visit(storage)
assert len(seen) == 4 and sum(seen.values()) == 203
account = (
    Cell()
    .uint(1, 1)
    .addr((0, 0x4545))
    .varuint(4, 7)
    .varuint(203, 7)
    .uint(0, 3)
    .uint(native.NOW, 32)
    .uint(0, 1)
)
account.bits += storage.bits
account.refs = list(storage.refs)
shard = Cell().uint(0, 320).ref(account)
message = native.external((0, 0x4545), Cell())
configuration = native.config(16)
fixture_root = from_boc((root / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())
config = Cell(bits=fixture_root.bits, refs=[configuration])
em = native.Emulator.from_config(configuration)
rows = []
try:
    for index, (gas, cells, bits, data) in enumerate([(575, 4, 203, a), (75, 3, 163, c)]):
        before = shard
        result = em.send(shard, message)
        assert result["success"], result
        details = result["details"]
        assert (
            details["exit"] == 0
            and details["gas"] == gas
            and details["compute_success"]
            and not details["aborted"]
        ), details
        assert details["action"]["success"] and details["action"]["code"] == 0, details
        shard = from_boc(result["shard_account"])
        tx = from_boc(result["transaction"])
        after = shard.refs[0]
        assert after.refs[0].hash == b.hash and after.refs[1].hash == data.hash
        s = after.slice()
        s.uint(1)
        s.addr()
        assert s.varuint(7) == cells and s.varuint(7) == bits
        rows.append(
            dict(
                now=native.NOW,
                lt=em.lt,
                input_shard=before.boc().hex(),
                message=message.boc().hex(),
                gas=gas,
                transaction_hash=tx.hash.hex(),
                account_hash=after.hash.hex(),
                shard_hash=shard.hash.hex(),
            )
        )
finally:
    em.close()
out = args.output
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(
    json.dumps(dict(schema=1, config_boc=config.boc().hex(), rows=rows), indent=2) + "\n"
)
print(out, out.stat().st_size)
