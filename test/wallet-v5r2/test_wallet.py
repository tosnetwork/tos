"""Complete receiver entry points with compiled fixture dependencies, not signed PQ delivery."""

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
import native  # noqa: E402
from cells import Cell, from_boc, make_dict, read_dict  # noqa: E402
from test_auth import KEY  # noqa: E402
from test_auth_policy import policy as global_policy  # noqa: E402
from test_fee_identity import vault_data  # noqa: E402
from test_identity import module_data  # noqa: E402
from test_receiver_auth import ACCOUNT, TARGET, cosign, payload, relay, request  # noqa: E402
from test_state import fee, state  # noqa: E402


def run(code, data, module, req, expected=0, signature=None, shard=None, sender=None):
    entries = read_dict(native.config(17), 32)
    entries[48] = Cell().ref(global_policy())
    with patch.object(native, "config", return_value=make_dict(entries, 32)):
        e = native.Emulator(17)
    try:
        initial = shard or native.active_account(ACCOUNT, code, data, balance=10**15)
        result = e.send(
            initial,
            native.internal(
                sender or (0, int.from_bytes(module.hash, "big")),
                ACCOUNT,
                relay(req, signature),
                value=100_000_000_000,
            ),
        )
        assert result["success"], result
        d = result["details"]
        assert d["exit"] == expected, f"expected exit {expected}, got {d['exit']}"
        after = native.account_data(from_boc(result["shard_account"]))[0]
        if expected:
            assert after.hash == data.hash
        else:
            assert not d["aborted"] and (d["action"] is None or d["action"]["success"]), d
        messages = native.outgoing(from_boc(result["transaction"]))
        for m in messages:
            s = m.slice()
            flags = s.uint(4)
            s.addr()
            dest = s.addr()
            assert bool(flags & 1) if expected else dest == TARGET
        return after, from_boc(result["shard_account"]), len(messages)
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
            "wallet-v5r2-code.fc",
            "wallet-v5r2-auth.fc",
            "wallet-v5r2-fee-identity.fc",
            "wallet-v5r2-state.fc",
            "wallet-v5r2-identity.fc",
            "auth-extension.fc",
            "auth-policy.fc",
            "pq-bytes.fc",
            "wallet-v5-action-list.fc",
        ]:
            shutil.copyfile(ROOT / "crypto/smartcont" / name, work / name)
        (work / "vault.fc").write_text("() recv_internal(slice body) impure { }\n")
        vault_code = native.compile_contract(str(work / "vault.fc"), out / "vault-fixture.boc")
        module_code = native.compile_contract("rescue-dual-module.fc", out / "module-fixture.boc")
        driver = work / "driver.fc"
        driver.write_text(
            f'#include "wallet-v5r2-code.fc";\nint r2wallet_network() inline {{ return 123; }}\nint r2wallet_module_hash() inline {{ return 0x{module_code.hash.hex()}; }}\ncell fixture_vault_code() asm "B{{{vault_code.boc().hex()}}} B>boc PUSHREF";\ncell r2wallet_vault_code() inline {{ return fixture_vault_code(); }}\n'
        )
        try:
            code = native.compile_contract(str(driver), out / "wallet.boc")
        except Exception as e:
            if hasattr(e, "stderr"):
                print(e.stderr.decode())
            raise
        module = native.state_init(module_code, module_data())
        root = int.from_bytes(module.hash, "big")
        base = state(module, seqno=0, epoch=1, primary=0, rescue=0, retired=0, key=KEY)
        cases = 0
        for mode in range(256):
            req = request(root=root, body=payload(send_mode=mode))
            allowed = (mode & 2) and not (mode & 44) and (mode & 192) != 192
            run(code, base, module, req, 0 if allowed else (137 if not (mode & 2) else 1811))
            cases += 1
        successor = native.state_init(module_code, module_data(policy=2))
        new_fee = fee(tree_id=457)
        new_vault = native.state_init(
            vault_code, vault_data(metadata=new_fee, module=int.from_bytes(successor.hash, "big"))
        )
        mig = Cell().uint(0x4D494752, 32).ref(successor).ref(new_fee).ref(new_vault)
        locked = state(
            module,
            mode=3,
            seqno=2**32 - 1,
            epoch=1,
            primary=2**64 - 1,
            rescue=2**64 - 1,
            retired=0xFFFF,
            key=KEY,
        )
        req = request(root=root, role=2, kind=4, nonce=2**64 - 1, body=mig)
        after, shard, count = run(code, locked, module, req)
        expected = state(
            successor,
            metadata=new_fee,
            mode=2,
            seqno=0,
            epoch=2,
            primary=0,
            rescue=0,
            retired=0xFFFF,
            key=KEY,
        )
        assert after.hash == expected.hash and count == 0
        cases += 1
        run(code, after, successor, req, 1800, shard=shard, sender=(0, root))
        cases += 1
        req2 = request(root=int.from_bytes(successor.hash, "big"), role=2, epoch=2)
        after2, _, count = run(code, after, successor, req2, shard=shard)
        assert count == 1 and after2.hash != after.hash
        cases += 1
        ready_vault = native.state_init(vault_code, vault_data(metadata=new_fee, module=root))
        bad = Cell().uint(0x4D494752, 32).ref(module).ref(new_fee).ref(ready_vault)
        run(
            code,
            locked,
            module,
            request(root=root, role=2, kind=4, nonce=2**64 - 1, body=bad),
            1813,
        )
        cases += 1
        malformed = (
            Cell()
            .uint(0x4D494752, 32)
            .ref(successor)
            .ref(new_fee)
            .ref(native.state_init(vault_code, vault_data(metadata=new_fee, module=999)))
        )
        run(
            code,
            locked,
            module,
            request(root=root, role=2, kind=4, nonce=2**64 - 1, body=malformed),
            1815,
        )
        cases += 1
        hybrid = state(module, mode=3, seqno=0, epoch=1, primary=0, rescue=0, retired=0, key=KEY)
        conf = Cell().uint(0x434F4E46, 32).uint(2, 2).maybe(None)
        configure = request(root=root, role=2, kind=1, body=conf)
        configured, _, n = run(code, hybrid, module, configure, signature=cosign(configure))
        assert (
            configured.hash
            == state(module, mode=2, seqno=1, epoch=2, primary=0, rescue=0, retired=0, key=KEY).hash
            and n == 0
        )
        run(code, hybrid, module, configure, 1808)
        cases += 2
        lock = request(root=root, role=2, kind=3)
        locked_after, _, n = run(code, hybrid, module, lock)
        assert (
            locked_after.hash
            == state(module, mode=3, seqno=0, epoch=2, primary=0, rescue=0, retired=2, key=KEY).hash
            and n == 0
        )
        cases += 1
        for count in (0, 1, 254, 255, 256):
            _, _, sent = run(
                code,
                base,
                module,
                request(root=root, body=payload(count=count)),
                0 if count <= 255 else 147,
            )
            if count <= 255:
                assert sent == count
            cases += 1
        src = work / "wallet-v5r2-code.fc"
        original = src.read_text()
        mutations = {}
        guard = "    throw_if(auth_policy::retired, retired & 2);"
        assert original.count(guard) == 1
        src.write_text(original.replace(guard, ""))
        mutant = native.compile_contract(str(driver), out / "retirement-mutant.boc")
        try:
            run(
                mutant,
                locked,
                module,
                request(root=root, role=2, kind=4, nonce=2**64 - 1, body=bad),
                1813,
            )
        except AssertionError as error:
            assert "got 0" in str(error), str(error)
            mutations["successor_retirement"] = str(error)
        else:
            raise AssertionError("retirement mutation survived")
        guard = "  set_data(r2state_store(seqno, id, key, mode, retired, epoch, primary, rescue, module, fee));"
        assert original.count(guard) == 1
        src.write_text(original.replace(guard, guard.replace("mode, retired,", "mode, 0,")))
        mutant = native.compile_contract(str(driver), out / "retired-bits-mutant.boc")
        altered, _, _ = run(mutant, locked, module, req)
        assert altered.hash != expected.hash, "retirement preservation mutation survived"
        mutations["preserve_retired_bits"] = (
            "mutant successful migration lost retirement bits; canonical state assertion fails"
        )
        src.write_text(original)
        restored = native.compile_contract(str(driver), out / "restored.boc")
        assert restored.hash == code.hash
        after, _, _ = run(restored, locked, module, req)
        assert after.hash == expected.hash
        (out / "results.json").write_text(
            json.dumps(
                {
                    "scope": __doc__,
                    "cases": cases,
                    "mutations": mutations,
                    "wallet_code_hash": code.hash.hex(),
                },
                indent=2,
            )
            + "\n"
        )
        print(f"{cases} complete receiver cases passed")


if __name__ == "__main__":
    main()
