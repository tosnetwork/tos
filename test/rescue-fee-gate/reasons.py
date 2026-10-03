"""Print why each rejected submission was refused, so a rejection test cannot pass for the
wrong reason. Same environment as test_fee_gate.py."""

# ruff: noqa: E402
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_fee_gate import NOW, Key, intent, body, VAULT, TARGET, GLOBAL_ID, chain
from cells import Cell
from native import Emulator, active_account, compile_contract, external

with tempfile.TemporaryDirectory() as tmp:
    code = compile_contract("rescue-fee-vault.fc", Path(tmp) / "vault.boc")
    emu = Emulator(global_version=19)

    def vault(key, next_leaf=0):
        data = Cell().sint(GLOBAL_ID, 32).uint(next_leaf, 32).ref(chain(key.public)).uint(0, 32)
        return active_account(VAULT, code, data)

    def show(name, shard, message_body):
        r = emu.send(shard, external(VAULT, message_body))
        keep = {
            k: r.get(k)
            for k in ("success", "error", "external_not_accepted", "vm_exit_code", "vm_log")
        }
        if keep.get("vm_log"):
            keep["vm_log"] = keep["vm_log"][-300:]
        print(f"{name}: {json.dumps(keep)}")

    key = Key(tmp, "r4", "10/4")
    shard = vault(key)
    good = intent(0)
    sig = key.sign(good.hash)
    flipped = bytearray(sig)
    flipped[200] ^= 1
    show("signature bit flip", shard, body(good, bytes(flipped)))
    show("intent changed", shard, body(intent(0, value=2_000_000_000), sig))
    show("foreign digest", shard, body(good, sig, digest=intent(0, value=5).hash))
    show("expired", shard, body(intent(0, valid_until=NOW - 1), sig))
    show("wrong vault", shard, body(intent(0, vault=TARGET), sig))
    show("replay against next_leaf=1", vault(key, next_leaf=1), body(good, sig))
    k8 = Key(tmp, "r8", "10/8")
    i8 = intent(0)
    show("valid W8 (over credit)", vault(k8), body(i8, k8.sign(i8.hash)))
    emu.close()
