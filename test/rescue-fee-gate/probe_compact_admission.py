"""Measure a role-gated candidate without changing the deployed prototype wire.

Environment: as test_rescue_e2e.py. This is NOT complete v5 admission: identity,
class, size, current-config solvency and successor witnesses remain open. The
candidate is compiled from the current prototype with exact anchored edits.
"""

import hashlib
import json
import tempfile
from pathlib import Path

import test_rescue_e2e as loop
from probe_role_budget import ANCHOR, GUARD, SOURCE

OLD_DIGEST = """  slice dg = digest.begin_parse();
  throw_unless(fee::digest_mismatch, (dg.slice_bits() == 256) & (dg.slice_refs() == 0));
  throw_unless(fee::digest_mismatch, dg.preload_uint(256) == cell_hash(intent));
"""
NEW_DIGEST = """  slice dg = digest.begin_parse();
  throw_unless(fee::digest_mismatch, dg~load_uint(256) == cell_hash(intent));
  dg.end_parse();
"""


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise RuntimeError("candidate anchor must occur exactly once")
    return source.replace(old, new)


def main():
    original = SOURCE.read_text()
    candidate = replace_once(original, ANCHOR, ANCHOR + GUARD)
    candidate = replace_once(candidate, OLD_DIGEST, NEW_DIGEST)
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

        def send(msg):
            return test.h.submit(test.h.vault(test.fee, per_slot=4), msg)

        def admitted(result):
            test.assertTrue(test.h.admitted(result), result)
            leaf, gas = test.h.state(result)
            test.assertLessEqual(gas, loop.slot.CREDIT)
            return {"next_leaf": leaf, "gas_at_accept": gas}

        def rejected(msg, code=None):
            result = send(msg)
            test.assertFalse(test.h.admitted(result), result)
            if code is not None:
                test.assertEqual(result.get("vm_exit_code"), code, result)
            return result.get("vm_exit_code")

        receipts["baseline"] = admitted(send(message))
        compile_variant("role-gated", candidate)
        result = send(message)
        receipts["candidate"] = admitted(result)
        test.assertEqual(receipts["candidate"]["next_leaf"], test.leaf + 1)
        (forwarded,) = loop.outgoing(loop.from_boc(result["transaction"]))
        _, ar, _, account = test.hop(test.module(), test.account(), forwarded, "candidate lock")
        test.assertTrue(ar["details"]["compute_success"])
        test.assertEqual(test.state(account)["retired"], 1 << 1)
        receipts["receiver_locked"] = True
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
        # A current-config recomputation is only a lower bound on production
        # solvency work: the prototype's size and storage bounds are not proved.
        budget_start = candidate.index("  int fresh_budget = get_compute_fee")
        budget_end = candidate.index("  set_data(", budget_start)
        budget_code = candidate[budget_start:budget_end]
        current_budget = replace_once(candidate, budget_code, "")
        balance_guard = "  throw_unless(fee::insufficient_balance, value + budget <= get_balance().pair_first());"
        current_budget = replace_once(
            current_budget,
            balance_guard,
            budget_code + balance_guard.replace("value + budget", "value + fresh_budget"),
        )
        compile_variant("current-budget", current_budget)
        receipts["current_budget_before_accept_exit"] = rejected(message, -14)
        receipts["current_budget_candidate_sha256"] = hashlib.sha256(
            current_budget.encode()
        ).hexdigest()
        receipts.update(
            scope="optimized digest parser plus role only; not complete v5 admission",
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
