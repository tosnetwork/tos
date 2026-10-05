"""Real per-key POP transactions: domain/identity binding without wallet authority."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
sys.path.insert(0, str(ROOT / "test/rescue-fee-gate"))
import native  # noqa: E402
from cells import Cell, from_boc  # noqa: E402
from test_identity import chain  # noqa: E402
from test_rescue_e2e import Signers  # noqa: E402

CTX = b"TOS-RESCUE-POP-v1"


def challenge(
    root,
    primary,
    rescue,
    role=1,
    network=123,
    global_id=42,
    nonce=99,
    deadline=native.NOW + 600,
    account=(0, 100),
    policy=1,
    suite=1,
):
    parties = Cell().addr(account).uint(root, 256)
    keys = Cell().uint(suite, 8).uint(primary, 256).uint(rescue, 256).uint(policy, 8)
    return (
        Cell()
        .uint(0x504F5033, 32)
        .sint(global_id, 32)
        .uint(network, 256)
        .uint(role, 8)
        .uint(nonce, 256)
        .uint(deadline, 32)
        .ref(parties)
        .ref(keys)
    )


def signed(sign, c, role, context=CTX):
    message = sign.dir / "pop-message"
    signature = sign.dir / "pop-signature"
    message.write_bytes(Cell().uint(0x544F532D504F5031, 64).ref(c).hash)
    tool, sk = (
        (os.environ["MLDSA_TOOL"], sign.ml_sk)
        if role == 1
        else (os.environ["SLH_TOOL"], sign.slh_sk)
    )
    subprocess.run(
        [tool, "sign", str(sk), context.hex(), str(message), str(signature)],
        check=True,
        capture_output=True,
    )
    return chain(signature.read_bytes())


def run(e, code, data, address, c, sig, expected=0):
    initial = native.active_account(address, code, data, balance=10**12)
    result = e.send(
        initial,
        native.internal(
            (0, 102), address, Cell().uint(0x50505333, 32).ref(c).ref(sig), value=10**12
        ),
    )
    assert result["success"], result
    actual = result["details"]["exit"]
    assert actual == expected, f"expected exit {expected}, got {actual}"
    after, balance = native.account_data(from_boc(result["shard_account"]))
    assert after.hash == data.hash, "POP mutated module data"
    messages = native.outgoing(from_boc(result["transaction"]))
    if expected == 0:
        assert not result["details"]["aborted"] and not messages, "POP emitted an action or aborted"
        assert balance >= 10**12, "POP spent pre-message funds"
    else:
        assert all(m.slice().uint(4) & 1 for m in messages), "failed POP emitted authorization"
    return result["details"]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    out = p.parse_args().output
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for name in [
            "wallet-v5r2-module.fc",
            "wallet-v5r2-pop.fc",
            "wallet-v5r2-auth.fc",
            "wallet-v5r2-common.fc",
            "wallet-v5r2-fee-identity.fc",
            "wallet-v5r2-state.fc",
            "wallet-v5r2-identity.fc",
            "auth-policy.fc",
            "pq-bytes.fc",
            "pq.fc",
        ]:
            shutil.copyfile(ROOT / "crypto/smartcont" / name, work / name)
        driver = work / "module.fc"
        driver.write_text(
            '#include "wallet-v5r2-module.fc";\ncell r2module_vault_code() inline { return begin_cell().end_cell(); }\n'
        )
        code = native.compile_contract(str(driver), out / "module.boc")
        sign = Signers(work)
        primary = chain(sign.ml_pk.read_bytes())
        rescue = int.from_bytes(sign.slh_pk, "big")
        data = (
            Cell()
            .uint(1, 8)
            .sint(42, 32)
            .uint(123, 256)
            .uint(1, 8)
            .ref(primary)
            .uint(rescue, 256)
            .uint(1, 8)
        )
        root = int.from_bytes(native.state_init(code, data).hash, "big")
        address = (0, root)
        pk = int.from_bytes(primary.hash, "big")
        e = native.Emulator(17)
        cases = {}
        try:
            for role in (1, 2):
                c = challenge(root, pk, rescue, role=role)
                sig = signed(sign, c, role)
                cases[f"role_{role}"] = run(e, code, data, address, c, sig)
                cases[f"repeat_nonauthorizing_{role}"] = run(e, code, data, address, c, sig)
                cases[f"wrong_context_{role}"] = run(
                    e,
                    code,
                    data,
                    address,
                    c,
                    signed(sign, c, role, b"TOS-AUTH-SLH-DSA-SHA2-128S-v1"),
                    1808,
                )
                cases[f"changed_challenge_{role}"] = run(
                    e,
                    code,
                    data,
                    address,
                    challenge(root, pk, rescue, role=role, nonce=100),
                    sig,
                    1808,
                )
            for field, value, error in [
                ("network", 124, 1801),
                ("global_id", 43, 1801),
                ("nonce", 0, 1903),
                ("deadline", native.NOW, 1805),
                ("deadline", native.NOW + 3601, 1805),
                ("account", (-1, 100), 1815),
                ("policy", 2, 1903),
                ("suite", 2, 1903),
                ("role", 3, 1901),
            ]:
                c = challenge(root, pk, rescue, **{field: value})
                cases[field] = run(e, code, data, address, c, signed(sign, c, 1), error)
            for field, c in [
                ("root", challenge(root + 1, pk, rescue)),
                ("primary_key", challenge(root, pk + 1, rescue)),
                ("rescue_key", challenge(root, pk, rescue + 1)),
            ]:
                cases[field] = run(
                    e, code, data, address, c, signed(sign, c, 1), 1800 if field == "root" else 1903
                )
            mutations = {}
            src = work / "wallet-v5r2-pop.fc"
            original = src.read_text()
            for role, key, suite in [(1, "primary_key", 1), (2, "key", 3)]:
                guard = f"    throw_unless(auth::bad_signature, pq_check_suite(digest, context, signature, {key}, {suite}));"
                assert original.count(guard) == 1
                src.write_text(original.replace(guard, ""))
                mutant = native.compile_contract(str(driver), out / f"mutant-{role}.boc")
                mr = int.from_bytes(native.state_init(mutant, data).hash, "big")
                c = challenge(mr, pk, rescue, role=role)
                bad = signed(sign, c, role, b"wrong-pop-domain")
                try:
                    run(e, mutant, data, (0, mr), c, bad, 1808)
                except AssertionError as error:
                    assert "got 0" in str(error), str(error)
                    mutations[str(role)] = str(error)
                else:
                    raise AssertionError("POP signature mutation survived")
            src.write_text(original)
            restored = native.compile_contract(str(driver), out / "restored.boc")
            assert restored.hash == code.hash
            c = challenge(root, pk, rescue)
            run(e, restored, data, address, c, signed(sign, c, 1))
            (out / "results.json").write_text(
                json.dumps({"scope": __doc__, "cases": cases, "mutations": mutations}, indent=2)
                + "\n"
            )
            print(f"{len(cases)} POP cases and {len(mutations)} signature mutations passed")
        finally:
            e.close()


if __name__ == "__main__":
    main()
