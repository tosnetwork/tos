"""Real PQ module -> complete wallet -> recipient, with the production vault dependency.

The initial funded internal message is supplied by the harness; this does not
prove a payer's own transaction or default-credit external admission.
"""

import argparse
import json
import shutil
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
sys.path.insert(0, str(ROOT / "test/rescue-fee-gate"))
import native  # noqa: E402
from cells import Cell, from_boc, make_dict, read_dict  # noqa: E402
from test_auth_policy import policy as global_policy  # noqa: E402
from test_fee_identity import vault_data  # noqa: E402
from test_identity import chain  # noqa: E402
from test_receiver_auth import ACCOUNT, TARGET, request  # noqa: E402
from test_rescue_e2e import Signers, digest  # noqa: E402
from test_state import fee, state  # noqa: E402


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--native-signer", type=Path)
    p.add_argument(
        "--delete-recipient-update", action="store_true", help="Test-only delivery control"
    )
    args = p.parse_args()
    with ExitStack() as stack:
        if args.native_signer:
            from native_signer_fixture import NativeSignerFixture

            signer = NativeSignerFixture(args.native_signer)
            signer.install(stack)
        run(args.output, args.delete_recipient_update)
        if args.native_signer:
            assert {(call["key"], call["purpose"]) for call in signer.calls} >= {
                ("primary", "auth"),
                ("rescue", "auth"),
            }
            (args.output / "native-wallet-signatures.json").write_text(
                json.dumps(signer.calls, indent=2) + "\n"
            )


def run(out, delete_recipient_update=False):
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for name in [
            "wallet-v5r2-module.fc",
            "wallet-v5r2-pop.fc",
            "wallet-v5r2-code.fc",
            "wallet-v5r2-auth.fc",
            "wallet-v5r2-fee-identity.fc",
            "wallet-v5r2-fee-vault.fc",
            "wallet-v5r2-state.fc",
            "wallet-v5r2-identity.fc",
            "wallet-v5r2-common.fc",
            "auth-policy.fc",
            "pq-bytes.fc",
            "pq.fc",
            "wallet-v5-action-list.fc",
        ]:
            shutil.copyfile(ROOT / "crypto/smartcont" / name, work / name)
        vault = native.compile_contract(str(work / "wallet-v5r2-fee-vault.fc"), out / "vault.boc")
        recipient_source = work / "recipient.fc"
        recipient_source.write_text(
            "() recv_internal(slice body) impure { "
            "int count = get_data().begin_parse().preload_uint(32); "
            "set_data(begin_cell().store_uint(count + 1, 32).end_cell()); }\n"
        )
        if delete_recipient_update:
            original = recipient_source.read_text()
            update = "set_data(begin_cell().store_uint(count + 1, 32).end_cell());"
            assert original.count(update) == 1
            recipient_source.write_text(original.replace(update, ""))
        recipient_code = native.compile_contract(str(recipient_source), out / "recipient.boc")
        const = f'cell fixture_vault() asm "B{{{vault.boc().hex()}}} B>boc PUSHREF";\n'
        module_driver = work / "module.fc"
        module_driver.write_text(
            '#include "wallet-v5r2-module.fc";\n'
            + const
            + "cell r2module_vault_code() inline { return fixture_vault(); }\n"
        )
        try:
            module_code = native.compile_contract(str(module_driver), out / "module.boc")
        except Exception as error:
            if hasattr(error, "stderr"):
                print(error.stderr.decode())
            raise
        wallet_driver = work / "wallet.fc"
        wallet_driver.write_text(
            '#include "wallet-v5r2-code.fc";\n'
            + const
            + f"int r2wallet_network() inline {{ return 123; }}\nint r2wallet_module_hash() inline {{ return 0x{module_code.hash.hex()}; }}\ncell r2wallet_vault_code() inline {{ return fixture_vault(); }}\n"
        )
        wallet_code = native.compile_contract(str(wallet_driver), out / "wallet.boc")
        for compiled in ["wallet.fif", "module.fif"]:
            assembly = (out / compiled).read_text()
            assert "CHKSIGN" not in assembly and "auth_require_strong_classical_key" not in assembly
        sign = Signers(work)
        data = (
            Cell()
            .uint(1, 8)
            .sint(42, 32)
            .uint(123, 256)
            .uint(1, 8)
            .ref(chain(sign.ml_pk.read_bytes()))
            .raw(sign.slh_pk)
            .uint(1, 8)
        )
        witness = native.state_init(module_code, data)
        root = int.from_bytes(witness.hash, "big")
        address = (0, root)
        entries = read_dict(native.config(17), 32)
        entries[48] = Cell().ref(global_policy())
        with patch.object(native, "config", return_value=make_dict(entries, 32)):
            e = native.Emulator(17)
        cases = {}
        try:
            for name, role, mode, kind in [
                ("primary", 1, 2, 0),
                ("rescue", 2, 2, 0),
                ("lock", 2, 2, 3),
            ]:
                wallet_data = state(
                    witness, mode=mode, seqno=0, epoch=1, primary=0, rescue=0, retired=0, key=0
                )
                req = request(root=root, role=role, kind=kind)
                sig = sign.ml(digest(req)) if role == 1 else sign.slh(digest(req))
                body = Cell().uint(0x53554233, 32).ref(req).ref(chain(sig))
                module_initial = native.active_account(address, module_code, data, balance=10**12)
                result = e.send(
                    module_initial, native.internal((0, 102), address, body, value=10**12)
                )
                assert result["success"] and result["details"]["exit"] == 0, result
                messages = native.outgoing(from_boc(result["transaction"]))
                assert len(messages) == 1, result
                module_after, balance = native.account_data(from_boc(result["shard_account"]))
                assert module_after.hash == data.hash and balance >= 10**12, (
                    "module spent its pre-message balance"
                )
                received = e.send(
                    native.active_account(ACCOUNT, wallet_code, wallet_data, balance=10**15),
                    messages[0],
                )
                assert received["success"] and received["details"]["exit"] == 0, received
                assert not received["details"]["aborted"], received
                after = native.account_data(from_boc(received["shard_account"]))[0]
                expected = state(
                    witness,
                    mode=mode,
                    seqno=1 if kind == 0 else 0,
                    epoch=1 if kind == 0 else 2,
                    primary=1 if role == 1 else 0,
                    rescue=1 if role == 2 and kind == 0 else 0,
                    retired=2 if kind == 3 else 0,
                    key=0,
                )
                assert after.hash == expected.hash
                outputs = native.outgoing(from_boc(received["transaction"]))
                assert len(outputs) == (1 if kind == 0 else 0)
                cases[name] = {"module": result["details"], "wallet": received["details"]}
                if kind == 0:
                    delivered = e.send(
                        native.active_account(
                            TARGET, recipient_code, Cell().uint(0, 32), balance=10**9
                        ),
                        outputs[0],
                    )
                    (out / f"{name}-recipient.json").write_text(
                        json.dumps(delivered, indent=2) + "\n"
                    )
                    assert delivered["success"] and delivered["details"]["exit"] == 0, delivered
                    assert not delivered["details"]["aborted"], delivered
                    recipient_data, recipient_balance = native.account_data(
                        from_boc(delivered["shard_account"])
                    )
                    assert recipient_data.hash == Cell().uint(1, 32).hash, (
                        "recipient state update missing"
                    )
                    assert recipient_balance > 10**9
                    cases[name]["recipient"] = delivered["details"]
                    for hop, receipt in (
                        ("module", result),
                        ("wallet", received),
                        ("recipient", delivered),
                    ):
                        (out / f"{name}-{hop}.json").write_text(
                            json.dumps(receipt, indent=2) + "\n"
                        )
                if name == "primary":
                    # Actual changed signature must be rejected without any authorization relay.
                    broken = bytes([sig[0] ^ 1]) + sig[1:]
                    bad = Cell().uint(0x53554233, 32).ref(req).ref(chain(broken))
                    rejected = e.send(
                        module_initial, native.internal((0, 102), address, bad, value=10**12)
                    )
                    assert rejected["details"]["exit"] == 1808, rejected
                    cases["invalid_primary_signature"] = rejected["details"]
                    for tag in (0x53554231, 0x53554232):
                        legacy = Cell().uint(tag, 32).ref(req).ref(chain(sig)).maybe(None)
                        refused = e.send(
                            module_initial, native.internal((0, 102), address, legacy, value=10**12)
                        )
                        assert refused["details"]["exit"] == 1902, refused
                        cases[f"legacy_submit_{tag:x}"] = refused["details"]
                    extra = (
                        Cell()
                        .uint(0x53554233, 32)
                        .ref(req)
                        .ref(chain(sig))
                        .ref(Cell().uint(0, 512))
                    )
                    refused = e.send(
                        module_initial, native.internal((0, 102), address, extra, value=10**12)
                    )
                    assert refused["details"]["exit"] == 9, refused
                    cases["classical_field_refused"] = refused["details"]

            # Authenticated migration uses actual module MYCODE and full paired witnesses.
            next_data = Cell(bits=data.bits[:-8]).uint(2, 8).ref(data.refs[0])
            successor = native.state_init(module_code, next_data)
            metadata = fee(tree_id=457)
            paired = native.state_init(
                vault, vault_data(metadata=metadata, module=int.from_bytes(successor.hash, "big"))
            )
            migration = Cell().uint(0x4D494752, 32).ref(successor).ref(metadata).ref(paired)
            req = request(root=root, role=2, kind=4, body=migration)
            body = Cell().uint(0x53554233, 32).ref(req).ref(chain(sign.slh(digest(req))))
            forwarded = e.send(
                module_initial, native.internal((0, 102), address, body, value=10**12)
            )
            assert forwarded["details"]["exit"] == 0, forwarded
            messages = native.outgoing(from_boc(forwarded["transaction"]))
            assert len(messages) == 1
            migrated = e.send(
                native.active_account(ACCOUNT, wallet_code, wallet_data, balance=10**15),
                messages[0],
            )
            assert migrated["details"]["exit"] == 0 and not migrated["details"]["aborted"], migrated
            after = native.account_data(from_boc(migrated["shard_account"]))[0]
            assert (
                after.hash
                == state(
                    successor,
                    metadata=metadata,
                    mode=2,
                    seqno=0,
                    epoch=2,
                    primary=0,
                    rescue=0,
                    retired=0,
                    key=0,
                ).hash
            )
            cases["signed_migration"] = {
                "module": forwarded["details"],
                "wallet": migrated["details"],
            }
            # The same authentic primary submission is refused after global retirement.
            primary_request = request(root=root)
            primary_signature = sign.ml(digest(primary_request))
            primary_body = (
                Cell().uint(0x53554233, 32).ref(primary_request).ref(chain(primary_signature))
            )
            entries[48] = Cell().ref(global_policy(retired=2))
            with patch.object(native, "config", return_value=make_dict(entries, 32)):
                retired_emulator = native.Emulator(17)
            try:
                rejected = retired_emulator.send(
                    module_initial, native.internal((0, 102), address, primary_body, value=10**12)
                )
                assert rejected["details"]["exit"] == 1813, rejected
                cases["global_retirement"] = rejected["details"]
                # Retirement must leave a real SLH payment available, including
                # the receiving wallet's independent policy check and recipient.
                rescue_request = request(root=root, role=2)
                rescue_body = (
                    Cell()
                    .uint(0x53554233, 32)
                    .ref(rescue_request)
                    .ref(chain(sign.slh(digest(rescue_request))))
                )
                rescue_module = retired_emulator.send(
                    module_initial, native.internal((0, 102), address, rescue_body, value=10**12)
                )
                assert rescue_module["details"]["exit"] == 0
                relay = native.outgoing(from_boc(rescue_module["transaction"]))
                assert len(relay) == 1
                rescue_wallet = retired_emulator.send(
                    native.active_account(
                        ACCOUNT,
                        wallet_code,
                        state(
                            witness, mode=2, seqno=0, epoch=1, primary=0, rescue=0, retired=0, key=0
                        ),
                        balance=10**15,
                    ),
                    relay[0],
                )
                assert rescue_wallet["details"]["exit"] == 0
                payment = native.outgoing(from_boc(rescue_wallet["transaction"]))
                assert len(payment) == 1
                rescue_recipient = retired_emulator.send(
                    native.active_account(
                        TARGET, recipient_code, Cell().uint(0, 32), balance=10**9
                    ),
                    payment[0],
                )
                assert rescue_recipient["details"]["exit"] == 0
                after, balance = native.account_data(from_boc(rescue_recipient["shard_account"]))
                assert after.hash == Cell().uint(1, 32).hash and balance > 10**9
                for receipt in (rescue_module, rescue_wallet, rescue_recipient):
                    assert receipt["success"] and not receipt["details"]["aborted"]
                cases["global_retirement_rescue"] = {
                    "module": rescue_module["details"],
                    "wallet": rescue_wallet["details"],
                    "recipient": rescue_recipient["details"],
                }
            finally:
                retired_emulator.close()
            # Guard deletion must accept the same kind of corrupted signature.
            src = work / "wallet-v5r2-module.fc"
            original = src.read_text()
            guard = "    throw_unless(auth::bad_signature, pq_check_suite(digest, context, signature, primary_key, 1));"
            assert original.count(guard) == 1
            src.write_text(original.replace(guard, ""))
            mutant = native.compile_contract(str(module_driver), out / "signature-mutant.boc")
            mutant_witness = native.state_init(mutant, data)
            mutant_address = (0, int.from_bytes(mutant_witness.hash, "big"))
            mutant_req = request(root=mutant_address[1])
            signature = sign.ml(digest(mutant_req))
            broken = bytes([signature[0] ^ 1]) + signature[1:]
            mutant_body = Cell().uint(0x53554233, 32).ref(mutant_req).ref(chain(broken))
            accepted = e.send(
                native.active_account(mutant_address, mutant, data, balance=10**12),
                native.internal((0, 102), mutant_address, mutant_body, value=10**12),
            )
            assert accepted["details"]["exit"] == 0 and not accepted["details"]["aborted"], accepted
            assert len(native.outgoing(from_boc(accepted["transaction"]))) == 1
            src.write_text(original)
            restored = native.compile_contract(str(module_driver), out / "restored-module.boc")
            assert restored.hash == module_code.hash
            mutations = {
                "primary_signature": "guard deletion changed corrupted signature rejection 1808 to successful relay"
            }
            report = {
                "scope": __doc__,
                "cases": cases,
                "mutations": mutations,
                "module_code_hash": module_code.hash.hex(),
                "wallet_code_hash": wallet_code.hash.hex(),
            }
            (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
            print(f"{len(cases)} real PQ delivery cases passed")
        finally:
            e.close()


if __name__ == "__main__":
    main()
