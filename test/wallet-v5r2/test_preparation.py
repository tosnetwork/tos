"""SLH-only bounded successor preparation: actual sends/deployments, no wallet transition."""

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
from fee_tx_parity import transcript  # noqa: E402
from test_fee_identity import vault_data  # noqa: E402
from test_identity import chain  # noqa: E402
from test_rescue_e2e import Signers  # noqa: E402
from test_state import fee  # noqa: E402

CTX = b"TOS-RESCUE-FEE-PREP-v1"


def signed(sign, request, context=CTX, sk=None):
    message, signature = sign._files(request.hash)
    subprocess.run(
        [
            os.environ["SLH_TOOL"],
            "sign",
            sk or sign.slh_sk,
            context.hex(),
            str(message),
            str(signature),
        ],
        check=True,
        capture_output=True,
    )
    return chain(signature.read_bytes())


def request(root, plan, wallet=(0, 100), network=123, global_id=42, deadline=native.NOW + 600):
    return (
        Cell()
        .uint(0x50525033, 32)
        .sint(global_id, 32)
        .uint(network, 256)
        .addr(wallet)
        .uint(root, 256)
        .uint(deadline, 32)
        .ref(plan)
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rust-driver", type=Path)
    options = parser.parse_args()
    out = options.output
    scenarios, expected_rows = [], []

    class RecordingEmulator(native.Emulator):
        def __init__(self, *args, **kwargs):
            self.record = kwargs.get("max_msg_cells") is None
            super().__init__(*args, **kwargs)

        def send(self, shard, message):
            result = super().send(shard, message)
            if self.record:
                name = f"preparation-{len(scenarios):03d}"
                scenarios.append(
                    "\t".join(
                        [
                            name,
                            str(native.NOW),
                            str(self.lt),
                            shard.refs[0].boc().hex(),
                            message.boc().hex(),
                            "-",
                        ]
                    )
                )
                expected_rows.append(transcript(name, result))
            return result

    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for src in (ROOT / "crypto/smartcont").glob("wallet-v5r2-*.fc"):
            shutil.copyfile(src, work / src.name)
        for name in ["auth-policy.fc", "pq.fc", "pq-bytes.fc"]:
            shutil.copyfile(ROOT / "crypto/smartcont" / name, work / name)
        vault = native.compile_contract(str(work / "wallet-v5r2-fee-vault.fc"), out / "vault.boc")
        driver = work / "module.fc"
        driver.write_text(
            '#include "wallet-v5r2-module.fc";\n'
            + f'cell compiled_vault() asm "B{{{vault.boc().hex()}}} B>boc PUSHREF";\n'
            + "cell r2module_vault_code() inline { return compiled_vault(); }\n"
        )
        code = native.compile_contract(str(driver), out / "module.boc")
        sign = Signers(work)
        primary = chain(sign.ml_pk.read_bytes())

        def data(policy):
            return (
                Cell()
                .uint(1, 8)
                .sint(42, 32)
                .uint(123, 256)
                .uint(1, 8)
                .ref(primary)
                .raw(sign.slh_pk)
                .uint(policy, 8)
            )

        current = data(1)
        metadata = fee()

        def identities(module_code, wallet=100, module_amount=10**10, vault_amount=2 * 10**10):
            successor = native.state_init(module_code, data(2))
            root = int.from_bytes(successor.hash, "big")
            vd = vault_data(metadata=metadata, wallet=wallet, module=root)
            vi = native.state_init(vault, vd)
            plan = (
                Cell().coins(module_amount).coins(vault_amount).ref(successor).ref(metadata).ref(vi)
            )
            return plan, successor, vi, vd

        plan, successor, vi, vd = identities(code)
        root = int.from_bytes(native.state_init(code, current).hash, "big")
        emulator = RecordingEmulator(17)
        cases = {}

        def run(
            name,
            req,
            sig=None,
            expected=0,
            value=10**12,
            module_code=code,
            initial=None,
            expected_messages=2,
        ):
            address = (0, int.from_bytes(native.state_init(module_code, current).hash, "big"))
            initial = initial or native.active_account(
                address, module_code, current, balance=10**12
            )
            result = emulator.send(
                initial,
                native.internal(
                    (0, 102),
                    address,
                    Cell().uint(0x46505233, 32).ref(req).ref(sig or signed(sign, req)),
                    value=value,
                ),
            )
            assert result["success"] and result["details"]["exit"] == expected, (name, result)
            after, balance = native.account_data(from_boc(result["shard_account"]))
            assert after.hash == current.hash, "preparation changed source module state"
            messages = native.outgoing(from_boc(result["transaction"]))
            assert balance >= native.account_data(initial)[1], "spent pre-message funds"
            if expected == 0:
                assert not result["details"]["aborted"] and len(messages) == expected_messages
            else:
                assert all(m.slice().uint(4) & 1 for m in messages), "failure emitted a deployment"
            (out / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n")
            cases[name] = result["details"]
            return result, messages

        try:
            req = request(root, plan)
            successful, messages = run("prepare", req)
            run("repeat_fresh_funding", req, initial=from_boc(successful["shard_account"]))
            for label, message, target, target_data, amount in zip(
                ["module", "vault"], messages, [successor, vi], [data(2), vd], [10**10, 2 * 10**10]
            ):
                ms = message.slice()
                ms.uint(4)
                ms.addr()
                assert ms.addr() == (0, int.from_bytes(target.hash, "big"))
                assert ms.coins() == amount
                assert message.refs[0].hash == target.hash, "different StateInit"
                empty = Cell().uint(0, 320).ref(Cell().uint(0, 1))
                deployed = emulator.send(empty, message)
                assert deployed["success"] and deployed["details"]["exit"] == 0, deployed
                assert not deployed["details"]["aborted"]
                actual, balance = native.account_data(from_boc(deployed["shard_account"]))
                assert actual.hash == target_data.hash and balance > 0
                assert not native.outgoing(from_boc(deployed["transaction"]))
                (out / f"deployed-{label}.json").write_text(json.dumps(deployed, indent=2) + "\n")
                cases[f"deployed-{label}"] = deployed["details"]
            run("wrong_key", req, signed(sign, req, sk=sign.other_slh_sk), 1808)

            def cell_count(cell):
                seen = set()

                def visit(c):
                    if c.hash in seen:
                        return
                    seen.add(c.hash)
                    for child in c.refs:
                        visit(child)

                visit(cell)
                return len(seen) - 1

            module_cells, vault_cells = map(cell_count, messages)
            assert module_cells > vault_cells
            original_emulator = emulator
            emulator = RecordingEmulator(17, max_msg_cells=vault_cells)
            try:
                partial, surviving = run("partial_send_size_limit", req, expected_messages=1)
                assert surviving[0].refs[0].hash == vi.hash, "unexpected surviving deployment"
            finally:
                emulator.close()
                emulator = original_emulator
            run("wrong_domain", req, signed(sign, req, b"TOS-RESCUE-POP-v1"), 1808)
            changed = request(root, identities(code, module_amount=10**10 + 1)[0])
            run("changed_amount", changed, signed(sign, req), 1808)
            for name, kwargs, expected in [
                ("wrong_source", {"root": root + 1}, 1800),
                ("wrong_network", {"network": 124}, 1801),
                ("wrong_global", {"global_id": 43}, 1801),
                ("expired", {"deadline": native.NOW}, 1805),
                ("overlong", {"deadline": native.NOW + 3601}, 1805),
                ("wrong_wallet_chain", {"wallet": (-1, 100)}, 1815),
            ]:
                run(name, request(**{"root": root, "plan": plan, **kwargs}), expected=expected)
            run("wrong_pair", request(root, identities(code, wallet=101)[0]), expected=1815)
            for name, amounts in [
                ("module_floor", (0, 2 * 10**10)),
                ("vault_floor", (10**10, 0)),
                ("setup_cap", (10**14, 10**14)),
            ]:
                run(
                    name,
                    request(
                        root, identities(code, module_amount=amounts[0], vault_amount=amounts[1])[0]
                    ),
                    expected=1905,
                )
            run("incoming_only", req, value=3 * 10**10, expected=1905)
            source = work / "wallet-v5r2-module.fc"
            original = source.read_text()
            prefix, rest = original.split("() recv_external", 1)
            guard = "  throw_unless(auth::bad_signature, pq_check_suite(digest, context, signature, key, 3));"
            assert prefix.count(guard) == 1
            source.write_text(prefix.replace(guard, "") + "() recv_external" + rest)
            mutant = native.compile_contract(str(driver), out / "mutant.boc")
            mr = int.from_bytes(native.state_init(mutant, current).hash, "big")
            bad = request(mr, identities(mutant)[0])
            run(
                "deleted_verifier_accepts_wrong_domain",
                bad,
                signed(sign, bad, b"wrong-domain"),
                module_code=mutant,
            )
            for name, guard, amounts, incoming, count in [
                (
                    "deleted_floor",
                    "  throw_unless(1905, (module_amount >= module_floor) & (vault_amount >= vault_floor));",
                    (0, 2 * 10**10),
                    10**12,
                    2,
                ),
                (
                    "deleted_cap",
                    "  throw_unless(1905, module_amount + vault_amount <= 4 * (module_floor + vault_floor));",
                    (10**14, 10**14),
                    10**15,
                    2,
                ),
                (
                    "deleted_incoming_budget",
                    "  throw_unless(1905, module_amount + vault_amount + get_compute_fee(0, 1000000)\n      + 2 * forwarding <= value);",
                    (10**10, 2 * 10**10),
                    3 * 10**10,
                    1,
                ),
            ]:
                assert prefix.count(guard) == 1
                source.write_text(prefix.replace(guard, "") + "() recv_external" + rest)
                mutant = native.compile_contract(str(driver), out / f"{name}.boc")
                mr = int.from_bytes(native.state_init(mutant, current).hash, "big")
                bad = request(
                    mr, identities(mutant, module_amount=amounts[0], vault_amount=amounts[1])[0]
                )
                run(name, bad, value=incoming, module_code=mutant, expected_messages=count)
            source.write_text(original)
            restored = native.compile_contract(str(driver), out / "restored.boc")
            assert restored.hash == code.hash
            run("restored", req)
        finally:
            emulator.close()
    if options.rust_driver:
        assert len(scenarios) >= 18
        fixture = from_boc((ROOT / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())
        (out / "config.boc").write_bytes(
            Cell().uint(int(fixture.bits, 2), 256).ref(native.config(17)).boc()
        )
        (out / "scenarios.tsv").write_text("\n".join(scenarios) + "\n")
        (out / "native.tsv").write_text("\n".join(expected_rows) + "\n")
        rust = subprocess.run(
            [
                str(options.rust_driver.resolve()),
                str(out / "config.boc"),
                str(out / "scenarios.tsv"),
                "17",
                "--details",
            ],
            capture_output=True,
            text=True,
        )
        (out / "rust.tsv").write_text(rust.stdout)
        (out / "rust.log").write_text(rust.stderr)
        assert rust.returncode == 0, rust.stderr[-2000:]
        observed = rust.stdout.splitlines()
        report = {
            "transactions": len(scenarios),
            "success": observed == expected_rows,
            "scope": "Funded internal preparations and deployments; partial-send custom config native-only; no paired external fee admission",
            "differences": [
                {"native": a, "rust": b} for a, b in zip(expected_rows, observed) if a != b
            ],
        }
        (out / "parity.json").write_text(json.dumps(report, indent=2) + "\n")
        assert report["success"], report
    (out / "results.json").write_text(json.dumps(cases, indent=2) + "\n")
    print(f"{len(cases)} preparation cases passed; actual deployments and four deletion controls")


if __name__ == "__main__":
    main()
