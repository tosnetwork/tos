"""Real LMS fee delivery for wallet AUTH or non-authorizing per-key POP; candidate limits."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
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
from test_pop import challenge as pop_challenge  # noqa: E402
from test_pop import signed as pop_signed  # noqa: E402
from test_receiver_auth import request  # noqa: E402
from test_rescue_e2e import Signers, digest  # noqa: E402
from test_state import fee, state  # noqa: E402


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument(
        "--credit-probe",
        action="store_true",
        help="Measure required credit without changing protocol defaults",
    )
    p.add_argument("--gas-trace", action="store_true", help="Retain instruction gas accounting")
    p.add_argument("--pop-role", type=int, choices=(1, 2), help="Exercise fee-funded per-key POP")
    p.add_argument(
        "--delete-payload-guard",
        action="store_true",
        help="Sensitivity control: delete the selected class constructor guard",
    )
    options = p.parse_args()
    out = options.output
    out.mkdir(parents=True, exist_ok=True)
    # Public deterministic test key only. Never use this tree or seed for funds.
    tree = out / "PUBLIC-TEST-ONLY-lms-tree"
    args = ["44" * 32, "55" * 16, "20", str(tree)]
    pub = bytes.fromhex(
        subprocess.run(
            [os.environ["LMS_TOOL"], "keygen", *args], check=True, capture_output=True, text=True
        ).stdout.strip()
    )
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for src in (ROOT / "crypto/smartcont").glob("wallet-v5r2-*.fc"):
            shutil.copyfile(src, work / src.name)
        for name in ["auth-policy.fc", "pq.fc", "pq-bytes.fc", "wallet-v5-action-list.fc"]:
            shutil.copyfile(ROOT / "crypto/smartcont" / name, work / name)
        if options.delete_payload_guard:
            src = work / "wallet-v5r2-fee-vault.fc"
            source = src.read_text()
            tag = "0x50505333" if options.pop_role else "0x53554233"
            guard = f"throw_unless(2012, payload_tag == {tag});"
            assert source.count(guard) == 1
            src.write_text(source.replace(guard, ""))
        vault = native.compile_contract(str(work / "wallet-v5r2-fee-vault.fc"), out / "vault.boc")
        const = f'cell compiled_vault() asm "B{{{vault.boc().hex()}}} B>boc PUSHREF";\n'
        (work / "module.fc").write_text(
            '#include "wallet-v5r2-module.fc";\n'
            + const
            + "cell r2module_vault_code() inline { return compiled_vault(); }\n"
        )
        module = native.compile_contract(str(work / "module.fc"), out / "module.boc")
        (work / "wallet.fc").write_text(
            '#include "wallet-v5r2-code.fc";\n'
            + const
            + f"int r2wallet_network() inline {{ return 123; }}\nint r2wallet_module_hash() inline {{ return 0x{module.hash.hex()}; }}\ncell r2wallet_vault_code() inline {{ return compiled_vault(); }}\n"
        )
        wallet = native.compile_contract(str(work / "wallet.fc"), out / "wallet.boc")
        signer = Signers(work)
        md = (
            Cell()
            .uint(1, 8)
            .sint(42, 32)
            .uint(123, 256)
            .uint(1, 8)
            .ref(chain(signer.ml_pk.read_bytes()))
            .raw(signer.slh_pk)
            .uint(1, 8)
        )
        mi = native.state_init(module, md)
        root = int.from_bytes(mi.hash, "big")
        metadata = fee(key=chain(pub), epoch0=native.NOW - 2 * 3600 - 10)
        wd = state(mi, metadata=metadata, mode=2, seqno=0, epoch=1, primary=0, rescue=0, retired=0)
        wa = (0, int.from_bytes(native.state_init(wallet, wd).hash, "big"))
        vd = vault_data(metadata=metadata, wallet=wa[1], module=root)
        vi = native.state_init(vault, vd)
        va = (0, int.from_bytes(vi.hash, "big"))
        (work / "recipient.fc").write_text(
            "() recv_internal(slice body) impure { set_data(begin_cell().store_uint(get_data().begin_parse().preload_uint(32) + 1, 32).end_cell()); }\n"
        )
        recipient_code = native.compile_contract(str(work / "recipient.fc"), out / "recipient.boc")
        recipient_data = Cell().uint(0, 32)
        recipient = (
            0,
            int.from_bytes(native.state_init(recipient_code, recipient_data).hash, "big"),
        )
        payment = native.internal(wa, recipient, Cell(), value=1_000_000_000)
        actions = Cell().uint(0x0EC3C86D, 32).uint(3, 8).ref(Cell()).ref(payment)
        req = request(root=root, role=2, account=wa, body=Cell().uint(0x45584543, 32).ref(actions))
        if options.pop_role:
            req = pop_challenge(
                root,
                int.from_bytes(chain(signer.ml_pk.read_bytes()).hash, "big"),
                int.from_bytes(signer.slh_pk, "big"),
                role=options.pop_role,
                account=wa,
            )
            submit = (
                Cell().uint(0x50505333, 32).ref(req).ref(pop_signed(signer, req, options.pop_role))
            )
        else:
            submit = Cell().uint(0x53554233, 32).ref(req).ref(chain(signer.slh(digest(req))))
        amount = 5_000_000_000
        header = vd.slice().uint(8 + 32 + 256) & ((1 << 256) - 1)

        def make_intent(
            *,
            kind=2 if options.pop_role else 1,
            target=va,
            config_hash=header,
            leaf=8,
            deadline=native.NOW + 600,
            value=amount,
            payload=submit,
        ):
            return (
                Cell()
                .uint(0x46454534, 32)
                .raw(b"TOS-RESCUE-FEE-v1")
                .uint(kind, 8)
                .addr(target)
                .uint(config_hash, 256)
                .uint(leaf, 32)
                .uint(deadline, 32)
                .coins(value)
                .ref(payload)
            )

        msg = work / "message"
        sig = work / "signature"

        def sign_fee(fee_intent, leaf=8):
            # All messages use public, deterministic test-only OTS material.
            # Reusing a leaf this way is forbidden for a production signer.
            msg.write_bytes(fee_intent.hash)
            subprocess.run(
                [os.environ["LMS_TOOL"], "sign", *args, str(leaf), str(msg), "66" * 32, str(sig)],
                check=True,
                capture_output=True,
            )
            return native.external(va, Cell().ref(fee_intent).ref(chain(sig.read_bytes())))

        intent = make_intent()
        ext = sign_fee(intent)
        entries = read_dict(native.config(17), 32)
        entries[48] = Cell().ref(global_policy())
        # Independently decode the fixture's current tariffs. This mirrors the
        # protocol fee formulas, not the optimized contract arithmetic/branches.
        gas_prices = entries[21].refs[0].slice()
        assert gas_prices.uint(8) == 0xD1
        flat_limit, flat_price = gas_prices.uint(64), gas_prices.uint(64)
        assert gas_prices.uint(8) == 0xDE
        gas_price = gas_prices.uint(64)
        forward_prices = entries[25].refs[0].slice()
        assert forward_prices.uint(8) == 0xEA
        lump, bit_price, cell_price = (forward_prices.uint(64) for _ in range(3))
        forwarding = lump + (1024 * 1023 * bit_price + 1024 * cell_price + 65535) // 65536
        downstream_gas = 1_000_000 if options.pop_role else 2_000_000
        fee_floor = (
            flat_price
            + (max(downstream_gas - flat_limit, 0) * gas_price + 65535) // 65536
            + 2 * forwarding
        )
        initial = native.active_account(va, vault, vd, balance=10**15)
        credit_probe = None
        if options.credit_probe:
            original = entries[21].refs[0]
            assert int(original.bits[:8], 2) == 0xD1 and int(original.bits[136:144], 2) == 0xDE
            offset = 336
            assert int(original.bits[offset : offset + 64], 2) == 10000
            with patch.object(native, "config", return_value=make_dict(entries, 32)):
                baseline = native.Emulator(17, vm_log_verbosity=3 if options.gas_trace else 1)
            try:
                default_result = baseline.send(initial, ext)
            finally:
                baseline.close()
            (out / "default-credit-result.json").write_text(
                json.dumps(default_result, indent=2) + "\n"
            )
            low, high = 0, 30000
            while low + 1 < high:
                credit = (low + high) // 2
                changed = Cell(
                    bits=original.bits[:offset]
                    + format(credit, "064b")
                    + original.bits[offset + 64 :],
                    refs=original.refs,
                )
                entries[21] = Cell().ref(changed)
                with patch.object(native, "config", return_value=make_dict(entries, 32)):
                    probe = native.Emulator(17, vm_log_verbosity=3 if options.gas_trace else 1)
                try:
                    result = probe.send(initial, ext)
                finally:
                    probe.close()
                if result["success"]:
                    assert result["details"]["exit"] == 0, result["details"]
                    high = credit
                else:
                    assert result.get("vm_exit_code") == -14, {
                        k: v for k, v in result.items() if k != "vm_log"
                    }
                    low = credit
            credit_probe = {
                "default_credit": 10000,
                "minimum_accept_credit": high,
                "production_admission_passed": high <= 10000,
                "downstream_diagnostic_credit": max(high, 20000),
            }
            entries[21] = Cell().ref(
                Cell(
                    bits=original.bits[:offset]
                    + format(max(high, 20000), "064b")
                    + original.bits[offset + 64 :],
                    refs=original.refs,
                )
            )
            (out / "credit-probe.json").write_text(json.dumps(credit_probe, indent=2) + "\n")
            print(json.dumps(credit_probe), flush=True)
        with patch.object(native, "config", return_value=make_dict(entries, 32)):
            e = native.Emulator(17, vm_log_verbosity=3 if options.gas_trace else 1)
        try:
            paid = e.send(native.active_account(va, vault, vd, balance=10**15), ext)
            (out / "vault-result.json").write_text(json.dumps(paid, indent=2) + "\n")
            if options.gas_trace and paid["success"]:
                initial_credit = (
                    credit_probe["downstream_diagnostic_credit"] if credit_probe else 10000
                )
                remaining = initial_credit
                costs = {}
                instruction = None
                for line in paid["vm_log"].splitlines():
                    if line.startswith("execute "):
                        instruction = line.removeprefix("execute ").split()[0]
                        if instruction == "ACCEPT":
                            break
                    if line.startswith("gas remaining:"):
                        current = int(line.split(":", 1)[1])
                        assert instruction is not None and current <= remaining
                        costs[instruction] = costs.get(instruction, 0) + remaining - current
                        remaining = current
                assert instruction == "ACCEPT", "trace omitted admission or was truncated"
                profile = {
                    "before_accept": initial_credit - remaining,
                    "lms_opcode": costs["LMSCHECKFEEHASH"],
                    "other_admission": initial_credit - remaining - costs["LMSCHECKFEEHASH"],
                    "instruction_totals": dict(sorted(costs.items(), key=lambda item: -item[1])),
                }
                (out / "gas-profile.json").write_text(json.dumps(profile, indent=2) + "\n")
            assert paid["success"], paid
            assert paid["details"]["exit"] == 0 and not paid["details"]["aborted"], paid
            failures = {}
            corrupt = sig.read_bytes()
            corrupt = corrupt[:-1] + bytes([corrupt[-1] ^ 1])
            invalid = native.external(va, Cell().ref(intent).ref(chain(corrupt)))
            bad = e.send(initial, invalid)
            assert not bad["success"] and bad.get("vm_exit_code") == 2007, bad
            failures["invalid_fee_signature"] = bad["vm_exit_code"]
            poor = e.send(native.active_account(va, vault, vd, balance=amount), ext)
            assert not poor["success"] and poor.get("vm_exit_code") == 2008, poor
            failures["insufficient_reserve"] = poor["vm_exit_code"]
            (out / "failure-results.json").write_text(
                json.dumps({"invalid_signature": bad, "insufficient_reserve": poor}, indent=2)
                + "\n"
            )

            wrong_tag = 0x53554233 if options.pop_role else 0x50505333
            wrong_payload = Cell().uint(wrong_tag, 32).ref(req).ref(submit.refs[1])
            # These envelopes have genuine LMS signatures, so signature failure
            # cannot hide an omitted structural/class/value guard.
            for name, changes, error in [
                ("payload_constructor", {"payload": wrong_payload}, 2012),
                ("class_zero", {"kind": 0}, 2012),
                ("class_three", {"kind": 3}, 2012),
                ("wrong_vault", {"target": (0, va[1] ^ 1)}, 2002),
                ("wrong_config", {"config_hash": header ^ 1}, 2013),
                ("expired", {"deadline": native.NOW}, 2003),
                ("ttl_overflow", {"deadline": native.NOW + 3601}, 2003),
                ("future_slot", {"leaf": 12}, 2009),
                ("old_slot", {"leaf": 3}, 2009),
                ("below_floor", {"value": fee_floor - 1}, 2010),
                ("above_ceiling", {"value": 4 * fee_floor + 1}, 2010),
            ]:
                rejected = e.send(initial, sign_fee(make_intent(**changes), changes.get("leaf", 8)))
                (out / f"negative-{name}.json").write_text(json.dumps(rejected, indent=2) + "\n")
                assert not rejected["success"] and rejected.get("vm_exit_code") == error, (
                    name,
                    "fee admission guard failed",
                    rejected,
                )
                failures[name] = rejected["vm_exit_code"]

            boundaries = {}
            for name, changes in [
                ("minimum_amount", {"value": fee_floor}),
                ("maximum_amount", {"value": 4 * fee_floor}),
                ("minimum_ttl", {"deadline": native.NOW + 1}),
                ("maximum_ttl", {"deadline": native.NOW + 3600}),
            ]:
                accepted = e.send(initial, sign_fee(make_intent(**changes)))
                (out / f"boundary-{name}.json").write_text(json.dumps(accepted, indent=2) + "\n")
                assert (
                    accepted["success"]
                    and accepted["details"]["exit"] == 0
                    and not accepted["details"]["aborted"]
                ), (name, accepted)
                assert len(native.outgoing(from_boc(accepted["transaction"]))) == 1
                after = native.account_data(from_boc(accepted["shard_account"]))[0].slice()
                assert after.uint(8) == 3 and after.uint(32) == 9
                boundaries[name] = accepted["details"]

            messages = native.outgoing(from_boc(paid["transaction"]))
            assert len(messages) == 1
            relayed = e.send(
                native.active_account((0, root), module, md, balance=10**12), messages[0]
            )
            (out / "module-result.json").write_text(json.dumps(relayed, indent=2) + "\n")
            assert relayed["success"] and relayed["details"]["exit"] == 0, relayed
            messages = native.outgoing(from_boc(relayed["transaction"]))
            executed = delivered = None
            if options.pop_role:
                assert not relayed["details"]["aborted"] and not messages, (
                    "POP emitted authorization"
                )
                module_after, module_balance = native.account_data(
                    from_boc(relayed["shard_account"])
                )
                assert module_after.hash == md.hash and module_balance >= 10**12
            else:
                assert len(messages) == 1
                executed = e.send(
                    native.active_account(wa, wallet, wd, balance=10**15), messages[0]
                )
                (out / "wallet-result.json").write_text(json.dumps(executed, indent=2) + "\n")
                assert executed["success"] and executed["details"]["exit"] == 0, executed
                assert len(native.outgoing(from_boc(executed["transaction"]))) == 1
                outgoing = native.outgoing(from_boc(executed["transaction"]))[0]
                delivered = e.send(
                    native.active_account(
                        recipient, recipient_code, recipient_data, balance=1_000_000_000
                    ),
                    outgoing,
                )
                assert (
                    delivered["success"]
                    and delivered["details"]["exit"] == 0
                    and not delivered["details"]["aborted"]
                ), delivered
                recipient_after, recipient_balance = native.account_data(
                    from_boc(delivered["shard_account"])
                )
                assert (
                    recipient_after.hash == Cell().uint(1, 32).hash
                    and recipient_balance > 1_000_000_000
                )
                (out / "recipient-result.json").write_text(json.dumps(delivered, indent=2) + "\n")
            vault_after = native.account_data(from_boc(paid["shard_account"]))[0]
            vs = vault_after.slice()
            assert vs.uint(8) == 3 and vs.uint(32) == 9
            replay = e.send(from_boc(paid["shard_account"]), ext)
            assert not replay["success"] and replay.get("vm_exit_code") == 2004, replay
            (out / "replay-result.json").write_text(json.dumps(replay, indent=2) + "\n")

            report = {
                "scope": __doc__,
                "pop_role": options.pop_role,
                "credit_probe": credit_probe,
                "vault": paid["details"],
                "module": relayed["details"],
                "wallet": executed["details"] if executed else None,
                "recipient": delivered["details"] if delivered else None,
                "replay_exit": replay["vm_exit_code"],
                "failure_exits": failures,
                "fee_floor": fee_floor,
                "admission_boundaries": boundaries,
                "addresses": {
                    "wallet": hex(wa[1]),
                    "module": hex(root),
                    "vault": hex(va[1]),
                    "recipient": hex(recipient[1]),
                },
            }
            (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report, indent=2))
        finally:
            e.close()


if __name__ == "__main__":
    main()
