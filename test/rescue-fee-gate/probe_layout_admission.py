"""Exercise the fixed-layout admission experiment with real native transactions.

Environment: as test_rescue_e2e.py. This is NOT complete v5 admission: identity,
class, proven size/fee bounds and successor witnesses remain open. The
prototype data layout is incompatible with the earlier slot-vault experiment.
"""

import ctypes
import hashlib
import json
import tempfile
from pathlib import Path

import test_rescue_e2e as loop
from cells import make_dict, read_dict
from native import config as native_config
from probe_compact_admission import NEW_DIGEST, replace_once
from probe_role_budget import GUARD

SOURCE = loop.slot.ROOT / "crypto/smartcont/rescue-fee-vault-layout.fc"


def main():
    original = SOURCE.read_text()
    candidate = original
    loop.RescueLoopTests.setUpClass()
    test = None
    receipts = {}
    try:
        test = loop.RescueLoopTests("test_rescue_lock_through_the_fee_vault")
        test.setUp()
        req = loop.request(loop.RESCUE, loop.K_LOCK, loop.Cell().uint(loop.LOCK, 32).uint(1, 8))
        sub = loop.submission(req, test.sign.slh(loop.digest(req)))
        intent = loop.slot.rescue_intent(test.leaf, sub, value=loop.slot.MAX_VALUE)
        message = loop.slot.body(intent, test.fee.sign_at(test.leaf, intent.hash))
        primary = loop.request(loop.PRIMARY, loop.K_EXECUTE, loop.pay(loop.PAYEE, 1))
        primary_sub = loop.submission(primary, test.sign.ml(loop.digest(primary)))
        primary_intent = loop.slot.rescue_intent(test.leaf + 1, primary_sub)
        primary_sig = test.fee.sign_at(test.leaf + 1, primary_intent.hash)
        primary_message = loop.slot.body(primary_intent, primary_sig)
        long_intent = loop.slot.rescue_intent(test.leaf + 2, sub, now=loop.NOW + 3001)
        long_message = loop.slot.body(
            long_intent, test.fee.sign_at(test.leaf + 2, long_intent.hash)
        )
        mismatch_intent = loop.slot.rescue_intent(test.leaf, sub)
        mismatch = loop.slot.body(
            mismatch_intent, test.fee.sign_at(test.leaf + 3, mismatch_intent.hash)
        )
        swapped_intent = loop.slot.rescue_intent(test.leaf + 1, sub)
        swapped = loop.slot.body(swapped_intent, primary_sig, primary_intent.hash)

        def compile_variant(name, source):
            path = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    prefix="admission-probe-",
                    suffix=".fc",
                    dir=SOURCE.parent,
                    delete=False,
                ) as f:
                    f.write(source)
                    path = Path(f.name)
                test.h.code = loop.compile_contract(path.name, Path(test.tmp.name) / f"{name}.boc")
            finally:
                if path is not None:
                    path.unlink()

        def send(
            msg,
            balance=100_000_000_000,
            next_leaf=0,
            epoch0=loop.slot.EPOCH0,
            max_value=loop.slot.MAX_VALUE,
        ):
            data = (
                loop.Cell()
                .uint(next_leaf, 32)
                .uint(0, 32)
                .sint(loop.slot.GLOBAL_ID, 32)
                .uint(epoch0, 32)
                .coins(max_value)
                .addr(loop.slot.TARGET)
                .ref(loop.slot.chain(test.fee.public))
            )
            vault = loop.slot.active_account(loop.slot.VAULT, test.h.code, data, balance=balance)
            return test.h.submit(vault, msg)

        def admitted(result):
            test.assertTrue(test.h.admitted(result), result)
            data, _ = loop.slot.account_data(loop.from_boc(result["shard_account"]))
            state = data.slice()
            leaf, gas = state.uint(32), state.uint(32)
            test.assertLessEqual(gas, loop.slot.CREDIT)
            return {"next_leaf": leaf, "gas_at_accept": gas}

        def rejected(msg, code=None, **kwargs):
            result = send(msg, **kwargs)
            test.assertFalse(test.h.admitted(result), result)
            if code is not None:
                test.assertEqual(result.get("vm_exit_code"), code, result)
            return result.get("vm_exit_code")

        compile_variant("role-gated", candidate)
        result = send(message)
        receipts["candidate"] = admitted(result)
        test.assertEqual(receipts["candidate"]["next_leaf"], test.leaf + 1)
        (forwarded,) = loop.outgoing(loop.from_boc(result["transaction"]))
        _, ar, _, account = test.hop(test.module(), test.account(), forwarded, "candidate lock")
        test.assertTrue(ar["details"]["compute_success"])
        test.assertEqual(test.state(account)["retired"], 1 << 1)
        receipts["receiver_locked"] = True
        replay = test.h.submit(loop.from_boc(result["shard_account"]), message)
        test.assertFalse(test.h.admitted(replay), replay)
        test.assertEqual(replay.get("vm_exit_code"), 2004, replay)
        receipts["actual_updated_state_replay_rejected"] = 2004
        updated, _ = loop.slot.account_data(loop.from_boc(result["shard_account"]))
        state = updated.slice()
        state.uint(32), state.uint(32)
        expected = (
            loop.Cell()
            .sint(loop.slot.GLOBAL_ID, 32)
            .uint(loop.slot.EPOCH0, 32)
            .coins(loop.slot.MAX_VALUE)
            .addr(loop.slot.TARGET)
            .ref(loop.slot.chain(test.fee.public))
        )
        test.assertEqual(loop.Cell(bits=state.bits, refs=state.refs).hash, expected.hash)
        receipts["immutable_suffix_preserved"] = True
        receipts["primary_rejected"] = rejected(primary_message, 2011)
        receipts["digest_binding_rejected"] = rejected(swapped, 2006)
        malformed = {
            "short": loop.Cell().raw(intent.hash[:-1]),
            "trailing_bit": loop.Cell().raw(intent.hash).uint(0, 1),
            "trailing_ref": loop.Cell().raw(intent.hash).ref(loop.Cell()),
        }
        receipts["malformed_digest_rejected"] = {}
        for name, digest in malformed.items():
            msg = loop.Cell().ref(intent).ref(digest).ref(message.refs[2]).ref(message.refs[3])
            receipts["malformed_digest_rejected"][name] = rejected(msg, 9)

        # Sensitivity controls use valid fee signatures and execute successfully;
        # compiler failures or unrelated rejection cannot count as detection.
        no_role = replace_once(candidate, GUARD, "")
        compile_variant("no-role", no_role)
        receipts["role_mutation_admitted_primary"] = admitted(send(primary_message))
        no_binding = replace_once(candidate, NEW_DIGEST, "")
        compile_variant("no-binding", no_binding)
        receipts["binding_mutation_admitted_swapped_body"] = admitted(send(swapped))
        compile_variant("restored", candidate)
        rejected(primary_message, 2011)
        rejected(swapped, 2006)
        receipts["restored"] = admitted(send(message))
        # Reuse one signed intent against independent states, never re-sign an OTS leaf.
        receipts["replay_rejected"] = rejected(message, 2004, next_leaf=test.leaf + 1)
        receipts["future_slot_rejected"] = rejected(message, 2009, epoch0=loop.slot.EPOCH0 + 3600)
        receipts["old_slot_rejected"] = rejected(message, 2009, epoch0=loop.slot.EPOCH0 - 7200)
        receipts["previous_slot"] = admitted(send(message, epoch0=loop.slot.EPOCH0 - 3600))
        receipts["value_cap_rejected"] = rejected(message, 2010, max_value=1)
        test.h.clock(loop.NOW + 600)
        receipts["expired_rejected"] = rejected(message, 2003)
        test.h.clock(loop.NOW)
        receipts["long_deadline_rejected"] = rejected(long_message, 2003)
        receipts["leaf_binding_rejected"] = rejected(mismatch, 2005)
        low, high = 1_000_000_000, 3_000_000_000
        rejected(message, 2008, balance=low)
        admitted(send(message, balance=high))
        while high - low > 1:
            mid = (low + high) // 2
            result = send(message, balance=mid)
            if test.h.admitted(result):
                admitted(result)
                high = mid
            else:
                test.assertEqual(result.get("vm_exit_code"), 2008, result)
                low = mid
        receipts["minimum_initial_balance"] = high
        receipts["one_below_rejected"] = rejected(message, 2008, balance=high - 1)
        receipts["at_balance_boundary"] = admitted(send(message, balance=high))
        balance_guard = "  throw_unless(fee::insufficient_balance, value + fresh_budget <= get_balance().pair_first());\n"
        compile_variant("no-solvency", replace_once(candidate, balance_guard, ""))
        receipts["solvency_mutation_admitted_insufficient_balance"] = admitted(
            send(message, balance=low)
        )
        slot_guard = "  throw_if(fee::wrong_slot, (slot - leaf_slot) >> 1);\n"
        compile_variant("no-slot", replace_once(candidate, slot_guard, ""))
        receipts["slot_mutation_admitted_future"] = admitted(
            send(message, epoch0=loop.slot.EPOCH0 + 3600)
        )
        receipts["slot_mutation_admitted_old"] = admitted(
            send(message, epoch0=loop.slot.EPOCH0 - 7200)
        )
        leaf_guard = "  throw_unless(fee::leaf_mismatch, ss.preload_uint(64) == leaf);\n"
        compile_variant("no-leaf-binding", replace_once(candidate, leaf_guard, ""))
        receipts["leaf_mutation_admitted_wrong_leaf"] = admitted(send(mismatch))
        deadline_guard = "(valid_until > t) & (valid_until <= t + 3600)"
        compile_variant(
            "no-deadline-bound", replace_once(candidate, deadline_guard, "valid_until > t")
        )
        receipts["deadline_mutation_admitted_long_window"] = admitted(send(long_message))
        compile_variant("restored-final", candidate)
        rejected(message, 2008, balance=low)
        rejected(message, 2009, epoch0=loop.slot.EPOCH0 + 3600)
        receipts["restored_final"] = admitted(send(message))
        original_config = native_config(loop.slot.GLOBAL_VERSION)
        entries = read_dict(original_config, 32)
        prices = entries[21].refs[0].slice()
        test.assertEqual(prices.uint(8), 0xD1)
        flat_limit, flat_price = prices.uint(64), prices.uint(64)
        test.assertEqual(prices.uint(8), 0xDE)
        gas_price = prices.uint(64)
        old_compute = flat_price + ((20000 - flat_limit) * gas_price + 65535) // 65536
        raised = loop.Cell().uint(0xD1, 8).uint(flat_limit, 64).uint(flat_price * 2, 64)
        raised.uint(0xDE, 8).uint(gas_price * 2, 64)
        raised.bits += prices.bits
        raised.refs.extend(prices.refs)
        entries[21] = loop.Cell().ref(raised)
        setter = test.em.lib.transaction_emulator_set_config
        setter.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        setter.restype = ctypes.c_bool
        test.assertTrue(setter(test.em.ptr, make_dict(entries, 32).b64()))
        try:
            receipts["raised_gas_price_rejects_old_balance"] = rejected(message, 2008, balance=high)
            receipts["raised_gas_price_with_funding"] = admitted(send(message))
            frozen = replace_once(candidate, "get_compute_fee(0, fee::max_gas)", str(old_compute))
            compile_variant("frozen-compute-fee", frozen)
            receipts["frozen_fee_mutation_admits_old_balance"] = admitted(
                send(message, balance=high)
            )
        finally:
            test.assertTrue(setter(test.em.ptr, original_config.b64()))
        compile_variant("restored-config", candidate)
        receipts["restored_config_and_contract"] = admitted(send(message, balance=high))
        receipts.update(
            scope="fixed layout with current-config bounded fee estimate; not complete v5 admission",
            global_version=loop.slot.GLOBAL_VERSION,
            external_credit=loop.slot.CREDIT,
            source_sha256=hashlib.sha256(original.encode()).hexdigest(),
            candidate_sha256=hashlib.sha256(candidate.encode()).hexdigest(),
        )
        print(json.dumps(receipts, indent=2))
    finally:
        if test is not None:
            test.doCleanups()
        loop.RescueLoopTests.tearDownClass()


if __name__ == "__main__":
    main()
