"""Fill native rollback/successor roots with asserted phases and graph accounting.

The original advertised counters deliberately remain zero/1000. A candidate
with too many real cells must roll back, after which small-state changes must
recount from the final graph. Requires EMULATOR_PATH.
"""

import argparse
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

# ACCEPT26 + DROP18 + PLDREF26 + POPc4=26 + implicit RET5 =101.
# crypto/vm/opctable.h and vm.h; the preload returns the reference without
# loading its contents. Code is56 bits. Storage root is115 bits at this balance.
code = Cell().raw(bytes.fromhex("f80030d74ced54"))
init = native.state_init(code, code)
storage = Cell().uint(0, 64).coins(100_000_000_000).uint(0, 1).uint(1, 1)
storage.bits += init.bits
storage.refs = list(init.refs)
assert len(storage.bits) == 115 and len(code.bits) == 56
account = (
    Cell()
    .uint(1, 1)
    .addr((0, 0x4545))
    .varuint(0, 7)
    .varuint(1000, 7)
    .uint(0, 3)
    .uint(native.NOW, 32)
    .uint(0, 1)
)
account.bits += storage.bits
account.refs = list(storage.refs)
shard = Cell().uint(0, 320).ref(account)
large = Cell()
for index in range(12):
    large = Cell().uint(index, 8).ref(large)
small = Cell().uint(0x42, 8)
entries = read_dict(native.config(16), 32)
# size_limits_config_v2#02 (block.tlb): four actual state cells allowed;
# storage-dictionary publication threshold3, distinct from oldcells>25.
limits = (
    Cell()
    .uint(2, 8)
    .uint(1 << 21, 32)
    .uint(1 << 13, 32)
    .uint(1000, 32)
    .uint(512, 16)
    .uint(65535, 32)
    .uint(512, 16)
    .uint(4, 32)
    .uint(65536, 32)
    .uint(256, 32)
    .uint(256, 32)
    .uint(255, 32)
    .uint(8, 8)
    .uint(3, 32)
)
entries[43] = Cell().ref(limits)
configuration = make_dict(entries, 32)
config_root = from_boc((root / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())
config = Cell(bits=config_root.bits, refs=[configuration])
em = native.Emulator.from_config(configuration)
rows = []
try:
    for supplied, selected, action, cells, bits, has_hash in [
        (large, code, 50, 0, 1000, False),
        (small, small, 0, 3, 179, True),
        (code, code, 0, 2, 171, False),
        (code, code, 0, 2, 171, False),
    ]:
        message = native.external((0, 0x4545), Cell().ref(supplied))
        before = shard
        result = em.send(shard, message)
        assert result["success"], result
        details = result["details"]
        assert (
            details["exit"] == 0
            and details["gas"] == 101
            and details["compute_success"]
            and details["aborted"] == (action != 0)
            and details["action"]["code"] == action
            and details["action"]["success"] == (action == 0)
        ), details
        shard = from_boc(result["shard_account"])
        after = shard.refs[0]
        assert after.refs[0].hash == code.hash and after.refs[1].hash == selected.hash
        s = after.slice()
        assert s.uint(1) == 1
        s.addr()
        assert s.varuint(7) == cells and s.varuint(7) == bits
        assert s.uint(3) == int(has_hash)
        rows.append(
            dict(
                now=native.NOW,
                lt=em.lt,
                input_shard=before.boc().hex(),
                message=message.boc().hex(),
                gas=101,
                aborted=action != 0,
                action_code=action,
                transaction_hash=from_boc(result["transaction"]).hash.hex(),
                account_hash=after.hash.hex(),
                shard_hash=shard.hash.hex(),
            )
        )
finally:
    em.close()
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(dict(config_boc=config.boc().hex(), rows=rows), indent=2) + "\n")
print(f"PASS: four native rollback/successor rows: {args.output}")
