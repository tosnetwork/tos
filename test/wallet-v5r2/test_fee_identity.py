"""Canonical paired-vault identity only; no fee admission, reserve or POP claim."""

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))

from cells import Cell, from_boc  # noqa: E402
from native import (  # noqa: E402
    Emulator,
    account_data,
    active_account,
    compile_contract,
    internal,
    state_init,
)
from test_state import fee  # noqa: E402


def address(value, wc=0):
    return Cell().uint(4, 3).sint(wc, 8).uint(value, 256)


def vault_data(metadata=None, wallet=100, module=200, network=123, global_id=42, leaf=0):
    config = Cell().uint(1, 8).sint(global_id, 32).uint(network, 256).ref(metadata or fee())
    config.bits += address(wallet).bits + address(module).bits
    metadata = metadata or fee()
    ms = metadata.slice()
    ms.uint(16 + 256)
    epoch0 = ms.uint(32)
    prefix = Cell().uint(0x41553252, 32).sint(global_id, 32).uint(network, 256)
    prefix.bits += address(wallet).bits
    prefix.uint(module, 256).uint(2, 8)
    parties = Cell(bits=address(wallet).bits).uint(module, 256)
    result = Cell().uint(3, 8).uint(leaf, 32).raw(config.hash).uint(epoch0, 32)
    result.bits += address(module).bits
    return result.raw(parties.hash).ref(metadata.refs[0]).ref(prefix)


def run(code, pinned, witness, expected, wallet=None, module=None, claimed=None):
    wallet = address(100) if wallet is None else wallet
    module = address(200) if module is None else module
    initial = Cell(bits=wallet.bits + module.bits, refs=[pinned, fee()])
    e = Emulator(17)
    try:
        result = e.send(
            active_account((0, 1000), code, initial),
            internal(
                (0, 1001),
                (0, 1000),
                Cell()
                .uint(int.from_bytes(witness.hash, "big") if claimed is None else claimed, 256)
                .ref(witness),
                value=100_000_000_000,
            ),
        )
        assert result["success"], result
        actual = result["details"]["exit"]
        assert actual == expected, f"expected exit {expected}, got {actual}"
        after = account_data(from_boc(result["shard_account"]))[0]
        target = Cell().uint(int.from_bytes(witness.hash, "big"), 256) if expected == 0 else initial
        assert after.hash == target.hash, "identity derivation or rejected state changed"
        return result["details"]
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
            "wallet-v5r2-fee-identity.fc",
            "wallet-v5r2-state.fc",
            "wallet-v5r2-identity.fc",
            "wallet-v5r2-common.fc",
            "pq-bytes.fc",
        ]:
            shutil.copyfile(ROOT / "crypto/smartcont" / name, work / name)
        shutil.copyfile(ROOT / "test/wallet-v5r2/fee-identity-driver.fc", work / "driver.fc")
        code = compile_contract(str(work / "driver.fc"), out / "pairing.boc")
        # Actual compiled code is a fixture only; no vault behavior is inferred.
        (work / "vault.fc").write_text("() recv_internal(slice body) impure { }\n")
        vault = compile_contract(str(work / "vault.fc"), out / "vault-fixture.boc")
        witness = state_init(vault, vault_data())
        cases = {"canonical": run(code, vault, witness, 0)}
        for field, value in [
            ("wallet", 101),
            ("module", 201),
            ("network", 124),
            ("global_id", 43),
            ("leaf", 1),
        ]:
            cases[field] = run(code, vault, state_init(vault, vault_data(**{field: value})), 1815)
        other_key = Cell().uint(1, 32).uint(8, 32).uint(3, 32).uint(8, 128).uint(9, 256)
        cases["fee_key"] = run(
            code, vault, state_init(vault, vault_data(metadata=fee(key=other_key))), 1815
        )
        cases["fee_tree_id"] = run(
            code, vault, state_init(vault, vault_data(metadata=fee(tree_id=457))), 1815
        )
        cases["wrong_code"] = run(code, Cell(), witness, 1815)
        cases["wrong_address"] = run(code, vault, witness, 1815, claimed=1)
        cases["wallet_workchain"] = run(code, vault, witness, 1815, wallet=address(100, -1))
        cases["module_workchain"] = run(code, vault, witness, 1815, module=address(200, -1))
        extra = vault_data()
        extra.bits += "0"
        cases["trailing_data"] = run(code, vault, state_init(vault, extra), 1815)
        cases["libraries"] = run(code, vault, Cell(bits="00111", refs=witness.refs), 1815)
        other = state_init(vault, vault_data(wallet=101))
        cases["independent_wallet_derivation"] = run(code, vault, other, 0, wallet=address(101))
        assert other.hash != witness.hash
        src = work / "wallet-v5r2-fee-identity.fc"
        original = src.read_text()
        guard = "  throw_unless(r2id::invalid, cell_hash(actual) == cell_hash(expected));"
        assert original.count(guard) == 1
        src.write_text(original.replace(guard, ""))
        mutant = compile_contract(str(work / "driver.fc"), out / "pairing-mutant.boc")
        try:
            run(mutant, vault, state_init(vault, vault_data(module=201)), 1815)
        except AssertionError as error:
            assert "got 0" in str(error), str(error)
            killed = str(error)
        else:
            raise AssertionError("pairing mutation survived")
        run(code, vault, state_init(vault, vault_data(module=201)), 1815)
        report = {
            "scope": __doc__,
            "cases": cases,
            "mutations": {"pairing": killed},
            "golden": {"wallet_100": witness.hash.hex(), "wallet_101": other.hash.hex()},
        }
        (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"{len(cases)} cases; pairing mutation rejected")


if __name__ == "__main__":
    main()
