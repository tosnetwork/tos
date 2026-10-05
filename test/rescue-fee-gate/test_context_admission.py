"""Version-17 contextual admission: real normal-credit transactions and VM parity."""

import argparse
import json
import tempfile
from pathlib import Path

import test_rescue_e2e as loop
from context_transactions import check_getter_context, compare
from native import Emulator, config, internal, state_init
from probe_bounded_admission import auth_prefix, cell_count, header
from probe_native_cost import run_driver


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpp", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--rust-tx", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    loop.RescueLoopTests.setUpClass()
    test = None
    em = Emulator(17)
    try:
        test = loop.RescueLoopTests("test_rescue_lock_through_the_fee_vault")
        test.setUp()
        test.em = em
        code = loop.compile_contract("rescue-fee-vault-context.fc", args.output / "context.boc")
        expected_header = header(test.fee.public)
        prefix = auth_prefix().uint(loop.RESCUE, 8)
        req = loop.request(loop.RESCUE, loop.K_LOCK, loop.Cell().uint(loop.LOCK, 32).uint(1, 8))
        slh = test.sign.slh(loop.digest(req))
        sub = loop.submission(req, slh)
        leaf = test.leaf
        rows = []
        receipts = {}

        def signed(payload=sub, fee_header=expected_header, **kw):
            nonlocal leaf
            q = leaf
            leaf += 1
            intent = (
                loop.Cell()
                .uint(kw.get("constructor", 0x46454533), 32)
                .uint(kw.get("fee_class", 1), 8)
                .addr(kw.get("vault", loop.slot.VAULT))
                .uint(q, 32)
                .uint(kw.get("deadline", loop.NOW + 600), 32)
                .coins(kw.get("value", loop.slot.MAX_VALUE))
                .ref(payload)
                .ref(fee_header)
            )
            sig = test.fee.sign_at(q, intent.hash)
            return loop.Cell().ref(intent).ref(loop.slot.chain(sig)), q, sig

        def send(
            name,
            vector,
            next_leaf=0,
            balance=100_000_000_000,
            code_cell=None,
            slot_delta=0,
            wrapper=None,
        ):
            body, q, _ = vector
            data = (
                loop.Cell()
                .uint(next_leaf, 32)
                .uint(0, 32)
                .uint(loop.NOW - (q // 4 + slot_delta) * 3600 - 10, 32)
                .coins(loop.slot.MAX_VALUE)
                .raw(expected_header.hash)
                .addr(loop.MODULE)
                .ref(loop.slot.chain(test.fee.public))
                .ref(prefix)
            )
            account = loop.slot.active_account(
                loop.slot.VAULT, code_cell or code, data, balance=balance
            )
            msg = wrapper(body) if wrapper else loop.slot.external(loop.slot.VAULT, body)
            result = em.send(account, msg)
            rows.append(
                "\t".join(
                    [
                        name,
                        str(loop.NOW),
                        str(em.lt),
                        account.refs[0].boc().hex(),
                        msg.boc().hex(),
                        "-",
                    ]
                )
            )
            (args.output / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n")
            return result

        valid = signed()
        result = send("valid", valid)
        test.assertTrue(test.h.admitted(result), result)
        data, _ = loop.slot.account_data(loop.from_boc(result["shard_account"]))
        st = data.slice()
        test.assertEqual(st.uint(32), valid[1] + 1)
        gas = st.uint(32)
        test.assertLessEqual(gas, loop.slot.CREDIT)
        (forwarded,) = loop.outgoing(loop.from_boc(result["transaction"]))
        module_before, account_before = test.module(), test.account()
        mr, ar, _, account = test.hop(module_before, account_before, forwarded, "context lock")
        (relay,) = loop.outgoing(loop.from_boc(mr["transaction"]))
        for name, before, msg, outcome, lt in [
            ("slh_module", module_before, forwarded, mr, em.lt - 1_000_000),
            ("locked_account", account_before, relay, ar, em.lt),
        ]:
            rows.append(
                "\t".join(
                    [name, str(loop.NOW), str(lt), before.refs[0].boc().hex(), msg.boc().hex(), "-"]
                )
            )
            (args.output / f"{name}.json").write_text(json.dumps(outcome, indent=2) + "\n")
        test.assertEqual(test.state(account)["retired"], 1 << 1)
        receipts["valid"] = {
            "gas_at_accept": gas,
            "total_gas": result["details"]["gas"],
            "cells": cell_count(loop.slot.external(loop.slot.VAULT, valid[0])),
            "receiver_locked": True,
        }

        def reject(name, vector, exit_code, **kw):
            result = send(name, vector, **kw)
            test.assertFalse(result["success"], result)
            test.assertTrue(result.get("external_not_accepted"), result)
            test.assertEqual(result.get("vm_exit_code"), exit_code, result)
            receipts[name] = exit_code

        reject("replay", valid, 2004, next_leaf=valid[1] + 1)
        reject("poor", valid, 2008, balance=loop.slot.MAX_VALUE)
        reject("future_slot", valid, 2009, slot_delta=-1)
        reject("old_slot", valid, 2009, slot_delta=2)
        previous = send("previous_slot", valid, slot_delta=1)
        test.assertTrue(test.h.admitted(previous), previous)
        reject("zero_value", signed(value=0), 2010)
        reject("expired", signed(deadline=loop.NOW), 2003)
        reject("far_deadline", signed(deadline=loop.NOW + 3601), 2003)
        reject("wrong_vault", signed(vault=loop.PAYEE), 2002)
        reject("wrong_class", signed(fee_class=2), 9)
        reject("wrong_constructor", signed(constructor=0), 9)
        reject("value_cap", signed(value=loop.slot.MAX_VALUE + 1), 2010)
        for name, kw in {
            "domain": {"domain": b"XOS-RESCUE-FEE-v1"},
            "network": {"network_tag": bytes(32)},
            "wallet": {"wallet": loop.PAYEE},
            "module": {"module": loop.PAYEE},
            "profile": {"profile": 3},
            "tree": {"tree": bytes(32)},
        }.items():
            reject("header_" + name, signed(fee_header=header(test.fee.public, **kw)), 2013)
        for name, kw in {
            "network": {"network_tag": bytes(32)},
            "wallet": {"account": loop.PAYEE},
            "module": {"root": loop.PAYEE},
        }.items():
            wrong = loop.request(loop.RESCUE, loop.K_LOCK, req.refs[0], **kw)
            reject("auth_" + name, signed(loop.submission(wrong, slh)), 9)
        primary = loop.request(loop.PRIMARY, loop.K_LOCK, req.refs[0])
        reject("primary", signed(loop.submission(primary, slh)), 9)
        wrong = loop.request(loop.RESCUE, 2, req.refs[0])
        reject("wrong_kind", signed(loop.submission(wrong, slh)), 2012)
        reject("trailing_sub", signed(loop.Cell(bits=sub.bits + "0", refs=sub.refs)), 9)
        reject(
            "trailing_req",
            signed(loop.submission(loop.Cell(bits=req.bits + "0", refs=req.refs), slh)),
            9,
        )
        tail = loop.Cell()
        for i in range(50):
            tail = loop.Cell().uint(i, 32).ref(tail)
        big = loop.request(
            loop.RESCUE, loop.K_LOCK, loop.Cell().uint(loop.LOCK, 32).uint(1, 8).ref(tail)
        )
        oversized = signed(loop.submission(big, slh))
        reject("oversize", oversized, 2015)
        for count in [128, 129]:
            tail = loop.Cell()
            for i in range(count - 94):
                tail = loop.Cell().uint(i, 32).ref(tail)
            request = loop.request(
                loop.RESCUE, loop.K_LOCK, loop.Cell().uint(loop.LOCK, 32).uint(1, 8).ref(tail)
            )
            vector = signed(loop.submission(request, slh))
            test.assertEqual(cell_count(loop.slot.external(loop.slot.VAULT, vector[0])), count)
            if count == 129:
                reject("one_cell_over", vector, 2015)
            else:
                exact = send("exact_cell_limit", vector)
                test.assertTrue(test.h.admitted(exact), exact)
                receipts["exact_limit_gas"] = exact["details"]["gas"]
        source_path = loop.slot.ROOT / "crypto/smartcont/rescue-fee-vault-context.fc"
        source = source_path.read_text()
        guard = "  throw_unless(2015, incoming_cells() <= fee::max_in_cells);"
        test.assertEqual(source.count(guard), 1)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".fc", prefix="context-mutant-", dir=source_path.parent
        ) as f:
            f.write(source.replace(guard, ""))
            f.flush()
            mutant_code = loop.compile_contract(f.name, args.output / "no-bound.boc")
            mutant = send("bound_mutation", oversized, code_cell=mutant_code)
            test.assertTrue(test.h.admitted(mutant), mutant)
            receipts["bound_mutation_admitted"] = True

        # The outer StateInit is included in the input bound but is not forwarded.
        def with_init(body):
            init = state_init(loop.Cell(), loop.Cell())
            return (
                loop.Cell()
                .uint(8, 4)
                .addr(loop.slot.VAULT)
                .coins(0)
                .uint(1, 1)
                .uint(1, 1)
                .ref(init)
                .uint(1, 1)
                .ref(body)
            )

        initialized = send("wrong_state_init", valid, wrapper=with_init)
        test.assertFalse(initialized["success"], initialized)
        test.assertTrue(initialized.get("external_not_accepted"), initialized)
        test.assertEqual(initialized.get("vm_log"), "")  # executor rejects before the VM
        rows.pop()  # executor API error taxonomies differ; this is a native import control
        receipts["wrong_state_init_pre_vm"] = True
        altered = loop.Cell(
            bits=valid[0].refs[0].bits[:-1] + ("1" if valid[0].refs[0].bits[-1] == "0" else "0"),
            refs=valid[0].refs[0].refs,
        )
        reject(
            "tampered", (loop.Cell().ref(altered).ref(valid[0].refs[1]), valid[1], valid[2]), 2007
        )
        for kind in [0, 1, 3, 4]:
            request = loop.request(loop.RESCUE, kind, req.refs[0])
            admitted = send(f"eligible_kind_{kind}", signed(loop.submission(request, slh)))
            test.assertTrue(test.h.admitted(admitted), admitted)
            state, _ = loop.slot.account_data(loop.from_boc(admitted["shard_account"]))
            test.assertLessEqual(state.slice().uint(64) & 0xFFFFFFFF, loop.slot.CREDIT)
        bad_slh = slh[:-1] + bytes([slh[-1] ^ 1])
        invalid_inner = signed(loop.submission(req, bad_slh))
        paid = send("bad_slh_fee_paid", invalid_inner)
        test.assertTrue(test.h.admitted(paid), paid)
        state, _ = loop.slot.account_data(loop.from_boc(paid["shard_account"]))
        test.assertEqual(state.slice().uint(32), invalid_inner[1] + 1)
        (bad_forwarded,) = loop.outgoing(loop.from_boc(paid["transaction"]))
        module_before = test.module()
        refused = em.send(module_before, bad_forwarded)
        test.assertTrue(refused["success"], refused)
        test.assertEqual(refused["details"]["exit"], 1808, refused)
        (bounce,) = loop.outgoing(loop.from_boc(refused["transaction"]))
        info = bounce.slice()
        test.assertEqual(info.uint(4), 5)  # internal, IHR disabled, bounced
        test.assertEqual(info.addr(), loop.MODULE)
        test.assertEqual(info.addr(), loop.slot.VAULT)
        after_paid = loop.from_boc(paid["shard_account"])
        # Record the module before any following delivery advances logical time.
        refused_lt = em.lt
        refunded = em.send(after_paid, bounce)
        test.assertTrue(test.h.admitted(refunded), refunded)
        state, _ = loop.slot.account_data(loop.from_boc(refunded["shard_account"]))
        test.assertEqual(state.slice().uint(32), invalid_inner[1] + 1)
        rows.append(
            "\t".join(
                [
                    "bad_slh_bounce",
                    str(loop.NOW),
                    str(em.lt),
                    after_paid.refs[0].boc().hex(),
                    bounce.boc().hex(),
                    "-",
                ]
            )
        )
        (args.output / "bad_slh_bounce.json").write_text(json.dumps(refunded, indent=2) + "\n")
        rows.append(
            "\t".join(
                [
                    "bad_slh_module",
                    str(loop.NOW),
                    str(refused_lt),
                    module_before.refs[0].boc().hex(),
                    bad_forwarded.boc().hex(),
                    "-",
                ]
            )
        )
        (args.output / "bad_slh_module.json").write_text(json.dumps(refused, indent=2) + "\n")
        receipts["fee_does_not_bypass_slh"] = True
        leaf = (1 << 20) - 1
        exhausted = send("last_leaf", signed())
        test.assertTrue(test.h.admitted(exhausted), exhausted)
        data, _ = loop.slot.account_data(loop.from_boc(exhausted["shard_account"]))
        test.assertEqual(data.slice().uint(32), 1 << 20)
        old = Emulator(16)
        try:
            original = rows[0].split("\t")
            shard = (
                loop.Cell().uint(0, 256).uint(0, 64).ref(loop.from_boc(bytes.fromhex(original[3])))
            )
            rejected = old.send(shard, loop.from_boc(bytes.fromhex(original[4])))
            test.assertFalse(rejected["success"], rejected)
            test.assertEqual(rejected["vm_exit_code"], 5)
            receipts["version_16_missing_context"] = 5
        finally:
            old.close()

        # Independently persist all context fields, including shared descendants and inline bodies.
        metadata_code = loop.compile_contract(
            str(Path(__file__).with_name("context-stats.fc").resolve()), args.output / "stats.boc"
        )
        getter = check_getter_context(em.lib, metadata_code, config(17), loop.slot.VAULT)
        (args.output / "getter.json").write_text(json.dumps(getter, indent=2) + "\n")
        receipts["native_getter_context_absent"] = True
        shared = loop.Cell().uint(123, 32)
        stats_body = loop.Cell().uint(99, 8).ref(shared).ref(shared)
        ordinary = loop.slot.external(loop.slot.VAULT, stats_body)
        inline = loop.Cell(bits=ordinary.bits[:-1] + "0" + stats_body.bits, refs=stats_body.refs)
        stats_init = state_init(metadata_code, loop.Cell())
        init_addr = (0, int.from_bytes(stats_init.hash, "big"))
        initialized_stats = (
            loop.Cell()
            .uint(8, 4)
            .addr(init_addr)
            .coins(0)
            .uint(1, 1)
            .uint(1, 1)
            .ref(stats_init)
            .uint(1, 1)
            .ref(stats_body)
        )
        for name, msg in [
            ("stats_ref", ordinary),
            ("stats_inline", inline),
            ("stats_init", initialized_stats),
            ("stats_internal", internal(loop.PAYEE, loop.slot.VAULT, stats_body)),
        ]:
            account = loop.slot.active_account(
                init_addr if name == "stats_init" else loop.slot.VAULT, metadata_code, loop.Cell()
            )
            result = em.send(account, msg)
            test.assertTrue(test.h.admitted(result), result)
            data, _ = loop.slot.account_data(loop.from_boc(result["shard_account"]))
            if name == "stats_internal":
                test.assertEqual(data.bits, "0" * 8)
            else:
                found = {}

                def visit(cell):
                    if cell.hash not in found:
                        found[cell.hash] = cell
                        for ref in cell.refs:
                            visit(ref)

                visit(msg)
                expected = (
                    loop.Cell()
                    .uint(1, 8)
                    .raw(msg.hash)
                    .uint(len(found), 64)
                    .uint(sum(len(c.bits) for c in found.values()), 64)
                )
                test.assertEqual(data.hash, expected.hash, name)
            rows.append(
                "\t".join(
                    [
                        name,
                        str(loop.NOW),
                        str(em.lt),
                        account.refs[0].boc().hex(),
                        msg.boc().hex(),
                        "-",
                    ]
                )
            )
            (args.output / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n")
        (args.output / "transactions.tsv").write_text("\n".join(rows) + "\n")
        # ConfigParams wrapper used by the Rust whole-transaction driver.
        (args.output / "config.boc").write_bytes(loop.Cell().uint(0, 256).ref(config(17)).boc())

        cases = []
        expected = {}
        key = loop.slot.chain(test.fee.public).boc().hex()
        sig = valid[0].refs[1].boc().hex()
        digest = "hash:" + valid[0].refs[0].hash.hex()

        def case(name, stack, exit_code=0, value=-1, version=17, budget=10000):
            cases.append("\t".join([name, str(version), str(budget), "f93103", *stack]))
            expected[name] = (exit_code, value)

        stack = [digest, f"int:{valid[1]}", sig, key]
        for version in range(20):
            case(
                f"version_{version}",
                stack,
                6 if version < 17 else 0,
                99 if version < 17 else -1,
                version,
            )
        case("wrong_leaf", [digest, f"int:{valid[1] + 1}", sig, key], value=0)
        case("negative_hash", ["int:-1", *stack[1:]], 5, 99)
        case("negative_leaf", [digest, "int:-1", sig, key], 5, 99)
        case("oversize_leaf", [digest, "int:1048576", sig, key], 5, 99)
        case("wrong_hash_type", [sig, *stack[1:]], 7, 99)
        case("underflow", stack[1:], 2, 99)
        case("wrong_digest", ["hash:" + bytes(32).hex(), *stack[1:]], value=0)
        case(
            "short_signature",
            [digest, stack[1], loop.slot.chain(valid[2][:-1]).boc().hex(), key],
            9,
            99,
        )
        case("empty_key", [*stack[:3], loop.Cell().boc().hex()], 9, 99)
        case("budget", stack, -14, 99, budget=3700)
        for name, public in {
            "bare_lms_key": test.fee.public[4:],
            "wrong_hss_levels": bytes(4) + test.fee.public[4:],
            "trailing_key": test.fee.public + b"x",
        }.items():
            case(name, [*stack[:3], loop.slot.chain(public).boc().hex()], 9, 99)
        case(
            "trailing_signature",
            [digest, stack[1], loop.slot.chain(valid[2] + b"x").boc().hex(), key],
            9,
            99,
        )
        case("wrong_signature_type", [digest, stack[1], "int:0", key], 7, 99)
        case("wrong_key_type", [*stack[:3], "int:0"], 7, 99)
        case("wrong_leaf_type", [digest, sig, sig, key], 7, 99)

        path = args.output / "opcodes.tsv"
        path.write_text("\n".join(cases) + "\n")
        cpp_text, cpp = run_driver(args.cpp, path)
        rust_text, rust = run_driver(args.rust, path)
        (args.output / "cpp.tsv").write_text(cpp_text)
        (args.output / "rust.tsv").write_text(rust_text)
        test.assertEqual(cpp, rust)
        test.assertEqual(set(cpp), set(expected))
        for name, (exit_code, value) in expected.items():
            test.assertEqual((cpp[name][0], cpp[name][2]), (exit_code, value), name)
        receipts["transaction_parity"] = compare(args.output, args.rust_tx)
        receipts["opcode_parity"] = len(cases)
        receipts["opcode_valid_gas"] = cpp["version_17"][1]
        (args.output / "summary.json").write_text(json.dumps(receipts, indent=2) + "\n")
        print(json.dumps(receipts, indent=2))
    finally:
        em.close()
        if test is not None:
            test.doCleanups()
        loop.RescueLoopTests.tearDownClass()


if __name__ == "__main__":
    main()
