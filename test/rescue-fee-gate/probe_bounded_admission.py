"""Bounded SUB1 experiment: normal-credit rejection and diagnostic-credit controls.

The 30,000-gas configuration exists only in this local emulator. It is not a
protocol change, proposed tariff, or evidence of fit within the real 10,000 credit.
"""

import ctypes
import hashlib
import json
import tempfile
from pathlib import Path

import test_rescue_e2e as loop
from cells import make_dict, read_dict
from native import config as native_config
from probe_compact_admission import replace_once

SOURCE = loop.slot.ROOT / "crypto/smartcont/rescue-fee-vault-bounded.fc"
DIAGNOSTIC_CREDIT = 30_000
DOMAIN = b"TOS-RESCUE-FEE-v1"


def auth_prefix(network_tag=loop.NETWORK_TAG, account=loop.ACCOUNT, module=loop.MODULE):
    return (
        loop.Cell()
        .uint(loop.AU2R, 32)
        .sint(loop.GLOBAL_ID, 32)
        .raw(network_tag)
        .addr(account)
        .uint(module[1], 256)
    )


def header(
    public_key,
    domain=DOMAIN,
    network_tag=loop.NETWORK_TAG,
    wallet=loop.ACCOUNT,
    module=loop.MODULE,
    profile=4,
    tree=None,
):
    parties = loop.Cell().addr(wallet).addr(module)
    return (
        loop.Cell()
        .raw(domain)
        .sint(loop.GLOBAL_ID, 32)
        .raw(network_tag)
        .uint(profile, 8)
        .raw(tree or hashlib.sha256(public_key).digest())
        .ref(parties)
    )


def cell_count(cell):
    seen = set()

    def visit(node):
        h = node.hash
        if h in seen:
            return
        seen.add(h)
        for ref in node.refs:
            visit(ref)

    visit(cell)
    return len(seen)


def main():
    source = SOURCE.read_text()
    loop.RescueLoopTests.setUpClass()
    test = None
    receipts = {}
    try:
        test = loop.RescueLoopTests("test_rescue_lock_through_the_fee_vault")
        test.setUp()
        original_config = native_config(loop.slot.GLOBAL_VERSION)
        setter = test.em.lib.transaction_emulator_set_config
        setter.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        setter.restype = ctypes.c_bool
        expected_header = header(test.fee.public)
        prefix = auth_prefix()
        test.assertEqual(len(prefix.bits), 843)
        req = loop.request(loop.RESCUE, loop.K_LOCK, loop.Cell().uint(loop.LOCK, 32).uint(1, 8))
        signature = test.sign.slh(loop.digest(req))
        sub = loop.submission(req, signature)
        next_leaf = test.leaf

        def signed(payload=sub, fee_header=expected_header, fee_class=1, constructor=0x46454532):
            nonlocal next_leaf
            leaf = next_leaf
            next_leaf += 1
            intent = (
                loop.Cell()
                .uint(constructor, 32)
                .sint(loop.GLOBAL_ID, 32)
                .addr(loop.slot.VAULT)
                .uint(leaf, 32)
                .uint(loop.NOW + 600, 32)
                .coins(loop.slot.MAX_VALUE)
                .uint(fee_class, 8)
                .ref(payload)
                .ref(fee_header)
            )
            msg = loop.slot.body(intent, test.fee.sign_at(leaf, intent.hash))
            return msg, leaf

        valid = signed()
        bad_headers = {
            name: signed(fee_header=header(test.fee.public, **kwargs))
            for name, kwargs in {
                "domain": {"domain": b"XOS-RESCUE-FEE-v1"},
                "network": {"network_tag": bytes(32)},
                "wallet": {"wallet": loop.PAYEE},
                "module": {"module": loop.PAYEE},
                "profile": {"profile": 3},
                "tree": {"tree": bytes(32)},
            }.items()
        }
        bad_requests = {}
        for name, kwargs in {
            "network": {"network_tag": bytes(32)},
            "wallet": {"account": loop.PAYEE},
            "module": {"root": loop.PAYEE},
        }.items():
            wrong = loop.request(loop.RESCUE, loop.K_LOCK, req.refs[0], **kwargs)
            bad_requests[name] = signed(loop.submission(wrong, signature))
        bad_class = signed(fee_class=2)
        bad_constructor = signed(constructor=0)
        wrong_kind = loop.request(loop.RESCUE, 2, req.refs[0])
        bad_kind = signed(loop.submission(wrong_kind, signature))
        primary_req = loop.request(loop.PRIMARY, loop.K_LOCK, req.refs[0])
        primary = signed(loop.submission(primary_req, signature))
        trailing_sub = signed(loop.Cell(bits=sub.bits + "0", refs=sub.refs))
        trailing_req = loop.Cell(bits=req.bits + "0", refs=req.refs)
        trailing_request = signed(loop.submission(trailing_req, signature))
        # Extra descendants are inside the signed operation body; SUB1 itself
        # retains its exact two-reference shape.
        tail = loop.Cell()
        for i in range(12):
            tail = loop.Cell().uint(i, 32).ref(tail)
        large_req = loop.request(
            loop.RESCUE, loop.K_LOCK, loop.Cell().uint(loop.LOCK, 32).uint(1, 8).ref(tail)
        )
        large_payload = loop.submission(large_req, signature)
        oversized = signed(large_payload)
        test.assertGreater(cell_count(large_payload), 72)
        test.assertLessEqual(cell_count(loop.slot.external(loop.slot.VAULT, oversized[0])), 128)

        def compile_variant(name, code):
            path = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", prefix="bounded-probe-", suffix=".fc", dir=SOURCE.parent, delete=False
                ) as f:
                    f.write(code)
                    path = Path(f.name)
                test.h.code = loop.compile_contract(path.name, Path(test.tmp.name) / f"{name}.boc")
            finally:
                if path is not None:
                    path.unlink()

        def send(vector):
            msg, leaf = vector
            epoch = loop.NOW - (leaf // 4) * 3600 - 10
            data = (
                loop.Cell()
                .uint(0, 32)
                .uint(0, 32)
                .sint(loop.GLOBAL_ID, 32)
                .uint(epoch, 32)
                .coins(loop.slot.MAX_VALUE)
                .addr(loop.MODULE)
                .ref(loop.slot.chain(test.fee.public))
                .ref(expected_header)
                .ref(prefix)
            )
            vault = loop.slot.active_account(
                loop.slot.VAULT, test.h.code, data, balance=100_000_000_000
            )
            external = loop.slot.external(loop.slot.VAULT, msg)
            return test.em.send(vault, external)

        def refuse(vector, code, **kwargs):
            result = send(vector, **kwargs)
            test.assertFalse(test.h.admitted(result), result)
            test.assertTrue(result.get("external_not_accepted"), result)
            test.assertEqual(result.get("vm_exit_code"), code, result)
            return code

        def admit(result):
            test.assertTrue(test.h.admitted(result), result)
            data, _ = loop.slot.account_data(loop.from_boc(result["shard_account"]))
            state = data.slice()
            leaf, gas = state.uint(32), state.uint(32)
            test.assertLessEqual(gas, DIAGNOSTIC_CREDIT)
            test.assertLessEqual(result["details"]["gas"], 40_000)
            return {
                "next_leaf": leaf,
                "gas_at_accept": gas,
                "total_compute_gas": result["details"]["gas"],
            }

        compile_variant("bounded", source)
        receipts["normal_credit"] = loop.slot.CREDIT
        receipts["normal_credit_valid_exit"] = refuse(valid, -14)
        entries = read_dict(original_config, 32)
        prices = entries[21].refs[0].slice()
        test.assertEqual(prices.uint(8), 0xD1)
        fixed = loop.Cell().uint(0xD1, 8).uint(prices.uint(64), 64).uint(prices.uint(64), 64)
        test.assertEqual(prices.uint(8), 0xDE)
        fixed.uint(0xDE, 8)
        for _ in range(3):  # gas price, limit and special limit remain unchanged
            fixed.uint(prices.uint(64), 64)
        test.assertEqual(prices.uint(64), loop.slot.CREDIT)
        fixed.uint(DIAGNOSTIC_CREDIT, 64)
        fixed.bits += prices.bits
        fixed.refs.extend(prices.refs)
        entries[21] = loop.Cell().ref(fixed)
        test.assertTrue(setter(test.em.ptr, make_dict(entries, 32).b64()))
        receipts["diagnostic_credit_only"] = DIAGNOSTIC_CREDIT
        result = send(valid)
        receipts["diagnostic_valid"] = admit(result)
        (forwarded,) = loop.outgoing(loop.from_boc(result["transaction"]))
        _, ar, _, account = test.hop(test.module(), test.account(), forwarded, "bounded lock")
        test.assertTrue(ar["details"]["compute_success"])
        test.assertEqual(test.state(account)["retired"], 1 << 1)
        receipts["diagnostic_receiver_locked"] = True
        receipts["header_rejections"] = {
            name: refuse(vector, 2013) for name, vector in bad_headers.items()
        }
        receipts["auth_identity_rejections"] = {
            name: refuse(vector, 2014) for name, vector in bad_requests.items()
        }
        receipts["unsupported_class"] = refuse(bad_class, 2012)
        receipts["wrong_constructor"] = refuse(bad_constructor, 2012)
        receipts["unsupported_kind"] = refuse(bad_kind, 2012)
        receipts["primary_rejected"] = refuse(primary, 2011)
        receipts["trailing_submission"] = refuse(trailing_sub, 9)
        receipts["trailing_request"] = refuse(trailing_request, 9)
        receipts["oversized_payload"] = refuse(oversized, 8)
        receipts["valid_payload_cells"] = cell_count(sub)
        receipts["oversized_payload_cells"] = cell_count(large_payload)
        receipts["valid_external_cells"] = cell_count(loop.slot.external(loop.slot.VAULT, valid[0]))
        receipts["compiled_code_cells"] = cell_count(test.h.code)
        # Prove that the full-message counter sees the external wrapper as well
        # as the signed body. Move only this limit around the exact fixture size.
        input_guard = "  compute_data_size(in_msg_full, fee::max_in_cells);"
        exact_size = receipts["valid_external_cells"]
        exact_source = replace_once(
            source, input_guard, f"  compute_data_size(in_msg_full, {exact_size});"
        )
        compile_variant("exact-input-bound", exact_source)
        receipts["exact_input_cell_bound"] = admit(send(valid))
        tight_guard = f"  compute_data_size(in_msg_full, {exact_size - 1});"
        tight_source = replace_once(source, input_guard, tight_guard)
        compile_variant("one-cell-short", tight_source)
        receipts["one_cell_below_input_bound"] = refuse(valid, 8)
        compile_variant("input-bound-mutation", replace_once(tight_source, tight_guard, ""))
        receipts["input_bound_mutation_admitted"] = admit(send(valid))
        guards = {
            "header": (
                "  throw_unless(2013, cell_hash(is~load_ref()) == cell_hash(expected_header));",
                "  is~load_ref();",
                bad_headers["domain"],
            ),
            "auth_identity": (
                "  throw_unless(2014, equal_slice_bits(request~load_bits(843), expected_auth_prefix));",
                "  request~skip_bits(843);",
                bad_requests["wallet"],
            ),
            "payload_size": ("  compute_data_size(payload, 72);", "", oversized),
            "class": (
                "  throw_unless(2012, is~load_uint(8) == 1);",
                "  is~load_uint(8);",
                bad_class,
            ),
            "constructor": (
                "  throw_unless(2012, is~load_uint(32) == 0x46454532);",
                "  is~load_uint(32);",
                bad_constructor,
            ),
            "kind": (
                "  throw_unless(2012, (kind == 0) | (kind == 1) | (kind == 3) | (kind == 4));",
                "",
                bad_kind,
            ),
            "role": (
                "  throw_unless(fee::not_rescue, request~load_uint(8) == 2);",
                "  request~load_uint(8);",
                primary,
            ),
            "submission_shape": ("  ps.end_parse();", "", trailing_sub),
            "request_shape": ("  request.end_parse();", "", trailing_request),
        }
        receipts["mutation_admitted"] = {}
        for name, (old, new, vector) in guards.items():
            compile_variant(name, replace_once(source, old, new))
            receipts["mutation_admitted"][name] = admit(send(vector))
        # Cost attribution only: this deliberately unsafe variant is never a
        # candidate. Neither size check may be omitted from the stated policy.
        no_sizes = replace_once(source, input_guard, "")
        no_sizes = replace_once(no_sizes, "  compute_data_size(payload, 72);", "")
        compile_variant("unsafe-no-size-cost-control", no_sizes)
        receipts["unsafe_no_sizes_cost_control"] = admit(send(valid))
        compile_variant("restored", source)
        refuse(oversized, 8)
        refuse(bad_requests["wallet"], 2014)
        receipts["diagnostic_restored"] = admit(send(valid))
        test.assertTrue(setter(test.em.ptr, original_config.b64()))
        receipts["restored_normal_credit_valid_exit"] = refuse(valid, -14)
        receipts.update(
            source_sha256=hashlib.sha256(source.encode()).hexdigest(),
            scope="bounded SUB1 experiment, diagnostic credit only; not production admission",
        )
        print(json.dumps(receipts, indent=2))
    finally:
        if test is not None:
            test.doCleanups()
        loop.RescueLoopTests.tearDownClass()


if __name__ == "__main__":
    main()
