"""Real LMS fee delivery for wallet AUTH, per-key POP or bounded successor preparation; candidate limits."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
sys.path.insert(0, str(ROOT / "test/rescue-fee-gate"))
import fee_failure_controls  # noqa: E402
import native  # noqa: E402
from cells import Cell, from_boc, make_dict, read_dict  # noqa: E402
from test_auth_policy import policy as global_policy  # noqa: E402
from test_fee_identity import vault_data  # noqa: E402
from test_identity import chain  # noqa: E402
from test_pop import challenge as pop_challenge  # noqa: E402
from test_pop import signed as pop_signed  # noqa: E402
from test_preparation import request as preparation_request  # noqa: E402
from test_preparation import signed as preparation_signed  # noqa: E402
from test_receiver_auth import request  # noqa: E402
from test_rescue_e2e import Signers, digest  # noqa: E402
from test_state import fee, state  # noqa: E402


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--genesis-driver", type=Path)
    p.add_argument("--fee-driver", type=Path)
    p.add_argument("--preparation-driver", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument(
        "--cache-driver",
        type=Path,
        help="Use real SDK cached signature for the positive fee request",
    )
    p.add_argument(
        "--credit-probe",
        action="store_true",
        help="Measure required credit without changing protocol defaults",
    )
    p.add_argument("--gas-trace", action="store_true", help="Retain instruction gas accounting")
    p.add_argument(
        "--recovery", action="store_true", help="Run continuous funded recovery after preparation"
    )
    p.add_argument("--prepare", action="store_true", help="Exercise bounded successor deployment")
    p.add_argument("--pop-role", type=int, choices=(1, 2), help="Exercise fee-funded per-key POP")
    p.add_argument(
        "--delete-payload-guard",
        action="store_true",
        help="Sensitivity control: delete the selected class constructor guard",
    )
    p.add_argument(
        "--fault",
        choices=fee_failure_controls.FAULTS,
        help="Inject a post-ACCEPT failure into a private copy of the vault",
    )
    p.add_argument(
        "--delete-preparation-guard",
        choices=("floors", "ceiling"),
        help="Preparation fee budget sensitivity control",
    )
    p.add_argument("--recovery-delete-transition", choices=("lock", "migrate"))
    p.add_argument(
        "--migration-gate",
        action="store_true",
        help="Test-only Rust gate over recorded native receipts",
    )
    options = p.parse_args()
    assert not options.gas_trace or options.credit_probe, "--gas-trace requires --credit-probe"
    assert not options.recovery_delete_transition or options.recovery
    assert not options.recovery or options.prepare
    assert not options.migration_gate or (options.recovery and options.genesis_driver)
    assert not options.delete_preparation_guard or options.prepare
    assert (
        sum(
            bool(x)
            for x in (options.delete_preparation_guard, options.delete_payload_guard, options.fault)
        )
        <= 1
    )
    assert not (options.prepare and options.pop_role), "select one submission class"
    assert not (options.fault and options.delete_payload_guard), (
        "run independent controls separately"
    )
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
        if options.recovery_delete_transition:
            src = work / "wallet-v5r2-code.fc"
            source = src.read_text()
            deleted = {"lock": "retired |= 2;", "migrate": "module = next_module;"}[
                options.recovery_delete_transition
            ]
            assert source.count(deleted) == 1
            src.write_text(source.replace(deleted, ""))
        if options.delete_payload_guard:
            src = work / "wallet-v5r2-fee-vault.fc"
            source = src.read_text()
            tag = (
                "0x46505233"
                if options.prepare
                else ("0x50505333" if options.pop_role else "0x53554233")
            )
            guard = f"throw_unless(2012, payload_tag == {tag});"
            assert source.count(guard) == 1
            src.write_text(source.replace(guard, ""))
        if options.delete_preparation_guard:
            src = work / "wallet-v5r2-fee-vault.fc"
            text = src.read_text()
            old, new = (
                (
                    "    throw_unless(2010, (setup_module >= reserve) & (setup_vault >= vault_floor));",
                    "",
                )
                if options.delete_preparation_guard == "floors"
                else (
                    "  throw_unless(2010, (amount >= floor) & (amount <= ceiling));",
                    "  throw_unless(2010, amount >= floor);",
                )
            )
            assert text.count(old) == 1
            src.write_text(text.replace(old, new))
        if options.fault:
            src = work / "wallet-v5r2-fee-vault.fc"
            src.write_text(fee_failure_controls.inject(src.read_text(), options.fault))
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
        genesis_cells = None
        if options.genesis_driver:
            assert (
                options.prepare
                and options.recovery
                and options.cache_driver
                and options.credit_probe
                and options.fault is None
            )
            from sdk_genesis_fixture import encode as encode_genesis

            genesis_cells = encode_genesis(
                options.genesis_driver,
                out / "sdk-genesis.json",
                wallet=wallet,
                module=module,
                vault=vault,
                primary=signer.ml_pk.read_bytes(),
                rescue=signer.slh_pk,
                fee_key=pub,
                expected=dict(
                    module_data=md,
                    module_init=mi,
                    metadata=metadata,
                    wallet_data=wd,
                    wallet_init=native.state_init(wallet, wd),
                    vault_data=vd,
                    vault_init=vi,
                ),
            )
            md, mi, metadata = (
                genesis_cells[name] for name in ("module_data", "module_init", "metadata")
            )
            wd, vd, vi = (
                genesis_cells[name] for name in ("wallet_data", "vault_data", "vault_init")
            )

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
        if options.prepare:
            successor_tree = out / "PUBLIC-TEST-ONLY-successor-tree"
            successor_key = bytes.fromhex(
                subprocess.run(
                    [
                        os.environ["LMS_TOOL"],
                        "keygen",
                        "77" * 32,
                        "88" * 16,
                        "20",
                        str(successor_tree),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()
            )
            assert successor_key != pub, "successor must use a distinct LMS key"
            successor_metadata = fee(
                key=chain(successor_key), tree_id=457, epoch0=native.NOW - 2 * 3600 - 10
            )
            successor_pk = work / "successor-ml.pk"
            successor_sk = work / "successor-ml.sk"
            subprocess.run(
                [
                    os.environ["MLDSA_TOOL"],
                    "keygen",
                    "99" * 32,
                    str(successor_pk),
                    str(successor_sk),
                ],
                check=True,
                capture_output=True,
            )
            new_slh_pk = bytes.fromhex(
                subprocess.run(
                    [os.environ["SLH_TOOL"], "keygen", "33" * 48],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.split()[0]
            )
            assert new_slh_pk != signer.slh_pk
            assert successor_pk.read_bytes() != signer.ml_pk.read_bytes()
            successor_data = (
                Cell()
                .uint(1, 8)
                .sint(42, 32)
                .uint(123, 256)
                .uint(1, 8)
                .ref(chain(successor_pk.read_bytes()))
                .raw(new_slh_pk)
                .uint(2, 8)
            )
            successor_module = native.state_init(module, successor_data)
            successor_root = int.from_bytes(successor_module.hash, "big")
            successor_vd = vault_data(
                metadata=successor_metadata, wallet=wa[1], module=successor_root
            )
            successor_vault = native.state_init(vault, successor_vd)
            if options.genesis_driver:
                successor_cells = encode_genesis(
                    options.genesis_driver,
                    out / "sdk-successor.json",
                    wallet=wallet,
                    module=module,
                    vault=vault,
                    primary=successor_pk.read_bytes(),
                    rescue=new_slh_pk,
                    fee_key=successor_key,
                    policy=2,
                    tree_id=457,
                    existing_wallet=wa[1],
                    expected=dict(
                        module_data=successor_data,
                        module_init=successor_module,
                        metadata=successor_metadata,
                        vault_data=successor_vd,
                        vault_init=successor_vault,
                    ),
                )
                (
                    successor_data,
                    successor_module,
                    successor_metadata,
                    successor_vd,
                    successor_vault,
                ) = (
                    successor_cells[name]
                    for name in (
                        "module_data",
                        "module_init",
                        "metadata",
                        "vault_data",
                        "vault_init",
                    )
                )
            module_amount, vault_amount = 10**10, 2 * 10**10
            plan = (
                Cell()
                .coins(module_amount)
                .coins(vault_amount)
                .ref(successor_module)
                .ref(successor_metadata)
                .ref(successor_vault)
            )
            req = preparation_request(root, plan, wallet=wa)
            submit = Cell().uint(0x46505233, 32).ref(req).ref(preparation_signed(signer, req))
            if options.preparation_driver:
                from sdk_prepare_fixture import encode as encode_preparation

                submit = encode_preparation(
                    options.preparation_driver, out / "sdk-prepare-initial.json", submit, native.NOW
                )

        elif options.pop_role:
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
        amount = 50_000_000_000 if options.prepare else 5_000_000_000
        header = vd.slice().uint(8 + 32 + 256) & ((1 << 256) - 1)

        def make_intent(
            *,
            kind=3 if options.prepare else (2 if options.pop_role else 1),
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
        fee_encoder = None
        if options.fee_driver:
            assert options.cache_driver, "SDK fee integration requires journal-backed signing"
            from sdk_fee_fixture import FeeEncoder

            fee_encoder = FeeEncoder(
                options.fee_driver, out / "sdk-fee", native.NOW - 2 * 3600 - 10
            )
            intent = fee_encoder.encode(intent, native.NOW)
        if options.cache_driver:
            from cached_fee_fixture import signature as cached_fee_signature

            cached_signature = cached_fee_signature(
                options.cache_driver,
                out / "sdk-cache",
                tree=tree,
                key=pub,
                vault=va[1],
                digest=intent.hash,
                now=native.NOW,
                epoch0=native.NOW - 2 * 3600 - 10,
            )
            sig.write_bytes(cached_signature)
            body = (
                fee_encoder.encode(intent, native.NOW, cached_signature)
                if fee_encoder
                else Cell().ref(intent).ref(chain(cached_signature))
            )
            ext = native.external(va, body)
        else:
            ext = sign_fee(intent)
        entries = read_dict(native.config(17), 32)
        entries[48] = Cell().ref(global_policy())
        cap = {
            "low-gas-cap": 12000,
            "low-gas-cap-unguarded": 12000,
            "gas-cap-below-minimum": 65535,
            "gas-cap-minimum": 65536,
        }.get(options.fault)
        if cap is not None:
            original_prices = entries[21].refs[0]
            entries[21] = Cell().ref(
                Cell(
                    bits=original_prices.bits[:208]
                    + format(cap, "064b")
                    + original_prices.bits[272:],
                    refs=original_prices.refs,
                )
            )
        if options.fault == "oversized-ignore":
            entries[43] = Cell().ref(native.size_limits(256))
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
        fee_ceiling = 4 * fee_floor
        if options.prepare:

            def compute_fee(gas):
                return flat_price + (max(gas - flat_limit, 0) * gas_price + 65535) // 65536

            prices = read_dict(entries[18].refs[0], 32)
            active = prices[max(t for t in prices if t <= native.NOW)].slice()
            assert active.uint(8) == 0xCC
            active.uint(32)
            storage_bit, storage_cell = active.uint(64), active.uint(64)
            storage = (33554432 * (128 * 1023 * storage_bit + 128 * storage_cell) + 65535) // 65536
            reserve = compute_fee(65536) + 2 * forwarding + storage
            successor_floor = 2 * (compute_fee(2000000) + 2 * forwarding + reserve)
            fee_floor = module_amount + vault_amount + compute_fee(1000000) + 2 * forwarding
            fee_ceiling = 4 * (reserve + successor_floor) + compute_fee(1000000) + 2 * forwarding
        initial_balance = (
            amount if options.fault and options.fault.startswith("unfunded-") else 10**15
        )
        initial = native.active_account(va, vault, vd, balance=initial_balance)
        credit_probe = None
        if options.credit_probe and options.fault not in ("low-gas-cap", "gas-cap-below-minimum"):
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
                    expected_exit = (
                        fee_failure_controls.expected_exit(options.fault) if options.fault else 0
                    )
                    assert result["details"]["exit"] == expected_exit, result["details"]
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
            genesis_accounts = None
            if genesis_cells:
                from sdk_genesis_fixture import deploy as deploy_genesis

                genesis_accounts = deploy_genesis(e, out / "genesis-deployment", genesis_cells)
                initial = genesis_accounts["vault"]
            paid = e.send(initial, ext)
            (out / "vault-result.json").write_text(json.dumps(paid, indent=2) + "\n")
            if options.gas_trace and paid["success"]:
                initial_credit = (
                    credit_probe["downstream_diagnostic_credit"] if credit_probe else 10000
                )
                from admission_profile import profile as trace_profile

                assert credit_probe is not None, "--gas-trace requires --credit-probe"
                profile = trace_profile(
                    paid["vm_log"], initial_credit, credit_probe["minimum_accept_credit"]
                )
                (out / "gas-profile.json").write_text(json.dumps(profile, indent=2) + "\n")
            if options.fault:
                fee_failure_controls.verify(options.fault, e, initial, ext, paid, out)
                return
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

            wrong_tag = 0x53554233 if options.pop_role or options.prepare else 0x50505333
            wrong_payload = Cell().uint(wrong_tag, 32).ref(req).ref(submit.refs[1])
            # These envelopes have genuine LMS signatures, so signature failure
            # cannot hide an omitted structural/class/value guard.
            for name, changes, error in [
                ("payload_constructor", {"payload": wrong_payload}, 2012),
                ("class_zero", {"kind": 0}, 2012),
                ("class_four", {"kind": 4}, 2012),
                ("wrong_vault", {"target": (0, va[1] ^ 1)}, 2002),
                ("wrong_config", {"config_hash": header ^ 1}, 2013),
                ("expired", {"deadline": native.NOW}, 2003),
                ("ttl_overflow", {"deadline": native.NOW + 3601}, 2003),
                ("future_slot", {"leaf": 12}, 2009),
                ("old_slot", {"leaf": 3}, 2009),
                ("below_floor", {"value": fee_floor - 1}, 2010),
                ("above_ceiling", {"value": fee_ceiling + 1}, 2010),
            ]:
                rejected = e.send(initial, sign_fee(make_intent(**changes), changes.get("leaf", 8)))
                (out / f"negative-{name}.json").write_text(json.dumps(rejected, indent=2) + "\n")
                assert not rejected["success"] and rejected.get("vm_exit_code") == error, (
                    name,
                    "fee admission guard failed",
                    rejected,
                )
                failures[name] = rejected["vm_exit_code"]

            if options.prepare:

                def changed_preparation(changed_plan=plan, **kwargs):
                    changed = preparation_request(
                        **{"root": root, "plan": changed_plan, "wallet": wa, **kwargs}
                    )
                    return (
                        Cell()
                        .uint(0x46505233, 32)
                        .ref(changed)
                        .ref(preparation_signed(signer, changed))
                    )

                def changed_plan(module_value=module_amount, vault_value=vault_amount):
                    return (
                        Cell()
                        .coins(module_value)
                        .coins(vault_value)
                        .ref(successor_module)
                        .ref(successor_metadata)
                        .ref(successor_vault)
                    )

                wrong_request = Cell(bits=format(0x50525034, "032b") + req.bits[32:], refs=req.refs)
                for name, payload, value, error in [
                    ("prepare_wallet", changed_preparation(wallet=(0, wa[1] ^ 1)), amount, 9),
                    ("prepare_source", changed_preparation(root=root ^ 1), amount, 9),
                    ("prepare_network", changed_preparation(network=124), amount, 9),
                    (
                        "prepare_constructor",
                        Cell()
                        .uint(0x46505233, 32)
                        .ref(wrong_request)
                        .ref(preparation_signed(signer, wrong_request)),
                        amount,
                        2012,
                    ),
                    (
                        "prepare_missing_witness",
                        changed_preparation(Cell(bits=plan.bits, refs=plan.refs[:-1])),
                        amount,
                        9,
                    ),
                    (
                        "prepare_trailing_plan",
                        changed_preparation(Cell(bits=plan.bits + "0", refs=plan.refs)),
                        amount,
                        9,
                    ),
                    (
                        "prepare_module_floor",
                        changed_preparation(changed_plan(module_value=0)),
                        amount,
                        2010,
                    ),
                    (
                        "prepare_vault_floor",
                        changed_preparation(changed_plan(vault_value=0)),
                        amount,
                        2010,
                    ),
                    (
                        "prepare_setup_cap",
                        changed_preparation(changed_plan(10**14, 10**14)),
                        2 * 10**14 + compute_fee(1000000) + 2 * forwarding,
                        2010,
                    ),
                ]:
                    rejected = e.send(initial, sign_fee(make_intent(payload=payload, value=value)))
                    (out / f"negative-{name}.json").write_text(
                        json.dumps(rejected, indent=2) + "\n"
                    )
                    assert not rejected["success"] and rejected.get("vm_exit_code") == error, (
                        name,
                        rejected,
                    )
                    failures[name] = rejected["vm_exit_code"]

            boundaries = {}
            for name, changes in [
                ("minimum_amount", {"value": fee_floor}),
                ("maximum_amount", {"value": fee_ceiling}),
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
                if options.prepare:
                    boundary_module = e.send(
                        native.active_account((0, root), module, md, balance=10**12),
                        native.outgoing(from_boc(accepted["transaction"]))[0],
                    )
                    assert (
                        boundary_module["success"]
                        and boundary_module["details"]["exit"] == 0
                        and not boundary_module["details"]["aborted"]
                    ), boundary_module
                    assert len(native.outgoing(from_boc(boundary_module["transaction"]))) == 2
                    boundary_data, boundary_balance = native.account_data(
                        from_boc(boundary_module["shard_account"])
                    )
                    assert boundary_data.hash == md.hash and boundary_balance >= 10**12
                    (out / f"boundary-module-{name}.json").write_text(
                        json.dumps(boundary_module, indent=2) + "\n"
                    )

            messages = native.outgoing(from_boc(paid["transaction"]))
            assert len(messages) == 1
            relayed = e.send(
                native.active_account((0, root), module, md, balance=10**12), messages[0]
            )
            (out / "module-result.json").write_text(json.dumps(relayed, indent=2) + "\n")
            assert relayed["success"] and relayed["details"]["exit"] == 0, relayed
            messages = native.outgoing(from_boc(relayed["transaction"]))
            executed = delivered = None
            preparation_deployments = None
            successor_pop = None
            if options.prepare:
                assert not relayed["details"]["aborted"] and len(messages) == 2
                module_after, module_balance = native.account_data(
                    from_boc(relayed["shard_account"])
                )
                assert module_after.hash == md.hash and module_balance >= 10**12
                preparation_deployments = {}
                prepared_states = {}
                for name, message, target, data, value in zip(
                    ["module", "vault"],
                    messages,
                    [successor_module, successor_vault],
                    [successor_data, successor_vd],
                    [module_amount, vault_amount],
                ):
                    ms = message.slice()
                    ms.uint(4)
                    assert ms.addr() == (0, root)
                    assert ms.addr() == (0, int.from_bytes(target.hash, "big"))
                    assert ms.coins() == value and message.refs[0].hash == target.hash
                    empty = Cell().uint(0, 320).ref(Cell().uint(0, 1))
                    deployed = e.send(empty, message)
                    assert (
                        deployed["success"]
                        and deployed["details"]["exit"] == 0
                        and not deployed["details"]["aborted"]
                    ), deployed
                    after, balance = native.account_data(from_boc(deployed["shard_account"]))
                    assert after.hash == data.hash and balance > 0
                    assert not native.outgoing(from_boc(deployed["transaction"]))
                    (out / f"prepared-{name}.json").write_text(
                        json.dumps(deployed, indent=2) + "\n"
                    )
                    preparation_deployments[name] = deployed["details"]
                    prepared_states[name] = from_boc(deployed["shard_account"])
                # Prove the actual fresh fee route using its deployed balances and
                # the rescue key. The continuous recovery below proves both keys
                # before any wallet migration is attempted.
                next_signer = SimpleNamespace(
                    dir=work, slh_sk=signer.other_slh_sk, ml_sk=successor_sk
                )
                pop = pop_challenge(
                    successor_root,
                    int.from_bytes(chain(successor_pk.read_bytes()).hash, "big"),
                    int.from_bytes(new_slh_pk, "big"),
                    role=2,
                    account=wa,
                    policy=2,
                )
                next_body = (
                    Cell().uint(0x50505333, 32).ref(pop).ref(pop_signed(next_signer, pop, 2))
                )
                next_address = (0, int.from_bytes(successor_vault.hash, "big"))
                next_header = successor_vd.slice().uint(8 + 32 + 256) & ((1 << 256) - 1)
                next_intent = (
                    Cell()
                    .uint(0x46454534, 32)
                    .raw(b"TOS-RESCUE-FEE-v1")
                    .uint(2, 8)
                    .addr(next_address)
                    .uint(next_header, 256)
                    .uint(8, 32)
                    .uint(native.NOW + 600, 32)
                    .coins(5_000_000_000)
                    .ref(next_body)
                )
                next_msg, next_sig = work / "next-fee-message", work / "next-fee-signature"
                next_msg.write_bytes(next_intent.hash)
                subprocess.run(
                    [
                        os.environ["LMS_TOOL"],
                        "sign",
                        "77" * 32,
                        "88" * 16,
                        "20",
                        str(successor_tree),
                        "8",
                        str(next_msg),
                        "66" * 32,
                        str(next_sig),
                    ],
                    check=True,
                    capture_output=True,
                )
                next_external = native.external(
                    next_address, Cell().ref(next_intent).ref(chain(next_sig.read_bytes()))
                )
                next_paid = e.send(prepared_states["vault"], next_external)
                assert (
                    next_paid["success"]
                    and next_paid["details"]["exit"] == 0
                    and not next_paid["details"]["aborted"]
                ), next_paid
                next_messages = native.outgoing(from_boc(next_paid["transaction"]))
                assert len(next_messages) == 1
                pop_result = e.send(prepared_states["module"], next_messages[0])
                assert (
                    pop_result["success"]
                    and pop_result["details"]["exit"] == 0
                    and not pop_result["details"]["aborted"]
                ), pop_result
                pop_data, pop_balance = native.account_data(from_boc(pop_result["shard_account"]))
                assert pop_data.hash == successor_data.hash
                assert pop_balance >= native.account_data(prepared_states["module"])[1]
                assert not native.outgoing(from_boc(pop_result["transaction"]))
                next_data = native.account_data(from_boc(next_paid["shard_account"]))[0].slice()
                assert next_data.uint(8) == 3 and next_data.uint(32) == 9
                next_replay = e.send(from_boc(next_paid["shard_account"]), next_external)
                assert not next_replay["success"] and next_replay.get("vm_exit_code") == 2004
                for name, receipt in [
                    ("successor-fee-pop", next_paid),
                    ("successor-module-pop", pop_result),
                    ("successor-fee-replay", next_replay),
                ]:
                    (out / f"{name}.json").write_text(json.dumps(receipt, indent=2) + "\n")
                if options.recovery:
                    from funded_recovery import run as run_recovery

                    def retime(envelope, now, sign):
                        original = envelope.refs[0]
                        fresh = Cell(bits=original.bits[:-32], refs=original.refs).uint(
                            now + 600, 32
                        )
                        return Cell(bits=envelope.bits).ref(fresh).ref(sign(fresh))

                    def primary_pop(now):
                        challenge = pop_challenge(
                            successor_root,
                            int.from_bytes(chain(successor_pk.read_bytes()).hash, "big"),
                            int.from_bytes(new_slh_pk, "big"),
                            role=1,
                            account=wa,
                            policy=2,
                            nonce=100,
                            deadline=now + 600,
                        )
                        return (
                            Cell()
                            .uint(0x50505333, 32)
                            .ref(challenge)
                            .ref(pop_signed(next_signer, challenge, 1))
                        )

                    def migration_signer():
                        target = out / "recovery/sdk-migration.boc"
                        subprocess.run(
                            [
                                sys.executable,
                                str(ROOT / "test/wallet-v5r2/recorded_migration_gate.py"),
                                "--fixtures",
                                str(out),
                                "--output",
                                str(target),
                            ],
                            check=True,
                        )
                        return from_boc(target.read_bytes())

                    recovery = run_recovery(
                        e,
                        out / "recovery",
                        old=SimpleNamespace(
                            key=pub,
                            tree=tree,
                            vault_address=va,
                            vault=initial,
                            module=genesis_accounts["module"]
                            if genesis_accounts
                            else native.active_account((0, root), module, md, balance=10**12),
                            root=root,
                            witness=mi,
                            metadata=metadata,
                        ),
                        new=SimpleNamespace(
                            data=successor_data,
                            vault_data=successor_vd,
                            witness=successor_module,
                            metadata=successor_metadata,
                            vault_witness=successor_vault,
                            root=successor_root,
                            vault_address=next_address,
                            header=next_header,
                            tree=successor_tree,
                            key=successor_key,
                        ),
                        wallet=SimpleNamespace(
                            address=wa,
                            initial=genesis_accounts["wallet"]
                            if genesis_accounts
                            else native.active_account(wa, wallet, wd, balance=10**15),
                        ),
                        recipient=SimpleNamespace(
                            address=recipient,
                            initial=native.active_account(
                                recipient, recipient_code, recipient_data, balance=1_000_000_000
                            ),
                        ),
                        prepare=submit,
                        pop_external=next_external,
                        primary_pop=primary_pop,
                        migration_signer=migration_signer if options.migration_gate else None,
                        sign_old=signer.slh,
                        sign_new=lambda d: signer.slh(d, sk=signer.other_slh_sk),
                        fee_intent=make_intent,
                        sign_fee=sign_fee,
                        work=work,
                        cache_driver=options.cache_driver,
                        fee_encoder=fee_encoder,
                        retime_prepare=lambda now: (
                            encode_preparation(
                                options.preparation_driver,
                                out / "sdk-prepare-retimed.json",
                                retime(submit, now, lambda req: preparation_signed(signer, req)),
                                now,
                            )
                            if options.preparation_driver
                            else retime(submit, now, lambda req: preparation_signed(signer, req))
                        ),
                        retime_pop=lambda now: retime(
                            next_body, now, lambda req: pop_signed(next_signer, req, 2)
                        ),
                    )
                    (out / "recovery-summary.json").write_text(
                        json.dumps(recovery, indent=2) + "\n"
                    )
                successor_pop = {
                    "role": 2,
                    "vault": next_paid["details"],
                    "module": pop_result["details"],
                    "replay_exit": 2004,
                }

            elif options.pop_role:
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

            # A fresh fee leaf pays for a deliberately invalid inner signature.
            # Exercise the actual module-generated bounce, not a fabricated deposit.
            inner_signature = submit.refs[1]
            flipped = ("1" if inner_signature.bits[0] == "0" else "0") + inner_signature.bits[1:]
            broken_submit = Cell(
                bits=submit.bits, refs=[req, Cell(bits=flipped, refs=inner_signature.refs)]
            )
            failed_external = sign_fee(make_intent(leaf=9, payload=broken_submit), 9)
            funded_failure = e.send(from_boc(paid["shard_account"]), failed_external)
            assert (
                funded_failure["success"]
                and funded_failure["details"]["exit"] == 0
                and not funded_failure["details"]["aborted"]
            )
            funded_messages = native.outgoing(from_boc(funded_failure["transaction"]))
            assert len(funded_messages) == 1
            rejected_module = e.send(from_boc(relayed["shard_account"]), funded_messages[0])
            assert (
                rejected_module["success"]
                and rejected_module["details"]["exit"] == 1808
                and rejected_module["details"]["aborted"]
            ), rejected_module
            bounces = native.outgoing(from_boc(rejected_module["transaction"]))
            assert len(bounces) == 1 and bounces[0].slice().uint(4) & 1, (
                "module must emit a real bounce"
            )
            before_return, before_return_balance = native.account_data(
                from_boc(funded_failure["shard_account"])
            )
            returned = e.send(from_boc(funded_failure["shard_account"]), bounces[0])
            assert (
                returned["success"]
                and returned["details"]["exit"] == 0
                and not returned["details"]["aborted"]
            )
            after_return, after_return_balance = native.account_data(
                from_boc(returned["shard_account"])
            )
            assert (
                after_return.hash == before_return.hash
                and after_return_balance > before_return_balance
            )
            assert not native.outgoing(from_boc(returned["transaction"]))
            returned_state = after_return.slice()
            assert returned_state.uint(8) == 3 and returned_state.uint(32) == 10
            bounced_replay = e.send(from_boc(returned["shard_account"]), failed_external)
            assert not bounced_replay["success"] and bounced_replay.get("vm_exit_code") == 2004
            for name, receipt in [
                ("funded-failure", funded_failure),
                ("module-rejection", rejected_module),
                ("bounce-return", returned),
                ("bounce-replay", bounced_replay),
            ]:
                (out / f"{name}.json").write_text(json.dumps(receipt, indent=2) + "\n")
            bounce_recovery = {
                "module_exit": 1808,
                "fee_leaf_after_return": 10,
                "returned_balance_gain": after_return_balance - before_return_balance,
                "replay_exit": 2004,
            }

            report = {
                "scope": __doc__,
                "pop_role": options.pop_role,
                "prepare": options.prepare,
                "preparation_deployments": preparation_deployments,
                "successor_pop": successor_pop,
                "credit_probe": credit_probe,
                "bounce_recovery": bounce_recovery,
                "vault": paid["details"],
                "module": relayed["details"],
                "wallet": executed["details"] if executed else None,
                "recipient": delivered["details"] if delivered else None,
                "replay_exit": replay["vm_exit_code"],
                "failure_exits": failures,
                "fee_floor": fee_floor,
                "fee_ceiling": fee_ceiling,
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
