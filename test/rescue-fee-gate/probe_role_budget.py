"""Measure the missing pre-ACCEPT role guard using a real signed rescue submission.

This is a design-gap probe, not a production admission implementation or release
gate. It adds only the inner RESCUE role check, not the remaining v5 wire,
witness, solvency or class checks. Both variants receive the exact same signed
intent against independent copies of the same test account state.

Environment: as test_rescue_e2e.py. Output is a small JSON receipt.
"""

import hashlib
import json
import tempfile
from pathlib import Path

import test_rescue_e2e as loop

SOURCE = loop.slot.ROOT / "crypto/smartcont/rescue-fee-vault-slot.fc"
ANCHOR = "  throw_unless(fee::not_rescue, ps.preload_uint(32) == fee::rescue_submit);\n"
GUARD = """  slice request = ps~load_ref().begin_parse();
  request~skip_bits(32 + 32 + 256);
  request~load_msg_addr();
  request~skip_bits(256);
  throw_unless(fee::not_rescue, request~load_uint(8) == 2);
"""


def main():
    original = SOURCE.read_text()
    if original.count(ANCHOR) != 1:
        raise RuntimeError("role-probe anchor must occur exactly once")
    candidate = original.replace(ANCHOR, ANCHOR + GUARD)
    loop.RescueLoopTests.setUpClass()
    path = None
    try:
        test = loop.RescueLoopTests("test_rescue_lock_through_the_fee_vault")
        test.setUp()
        request = loop.request(loop.RESCUE, loop.K_LOCK, loop.Cell().uint(loop.LOCK, 32).uint(1, 8))
        submission = loop.submission(request, test.sign.slh(loop.digest(request)))
        intent = loop.slot.rescue_intent(test.leaf, submission, value=loop.slot.MAX_VALUE)
        message = loop.slot.body(intent, test.fee.sign_at(test.leaf, intent.hash))
        baseline = test.h.submit(test.vault, message)
        test.assertTrue(test.h.admitted(baseline), baseline.get("error"))
        _, gas = test.h.state(baseline)
        # Positive control traverses the actual module and receiving account.
        (forwarded,) = loop.outgoing(loop.from_boc(baseline["transaction"]))
        _, account_result, _, account = test.hop(
            test.module(), test.account(), forwarded, "probe lock"
        )
        test.assertTrue(account_result["details"]["compute_success"])
        test.assertEqual(test.state(account)["retired"], 1 << 1)

        with tempfile.NamedTemporaryFile(
            mode="w", prefix="role-budget-", suffix=".fc", dir=SOURCE.parent, delete=False
        ) as source:
            source.write(candidate)
            path = Path(source.name)
        test.h.code = loop.compile_contract(path.name, Path(test.tmp.name) / "role-budget.boc")
        result = test.h.submit(test.h.vault(test.fee, per_slot=4), message)
        admitted = test.h.admitted(result)
        if admitted:
            _, candidate_gas = test.h.state(result)
        else:
            candidate_gas = None
            test.assertEqual(result.get("vm_exit_code"), -14, result)
        print(
            json.dumps(
                {
                    "scope": "role check only; not complete v5 admission",
                    "global_version": loop.slot.GLOBAL_VERSION,
                    "external_credit": loop.slot.CREDIT,
                    "source_sha256": hashlib.sha256(original.encode()).hexdigest(),
                    "candidate_sha256": hashlib.sha256(candidate.encode()).hexdigest(),
                    "baseline_admitted": True,
                    "baseline_gas_at_accept": gas,
                    "baseline_receiver_locked": True,
                    "role_guard_admitted": admitted,
                    "role_guard_gas_at_accept": candidate_gas,
                    "role_guard_exit": result.get("vm_exit_code")
                    if not admitted
                    else result["details"]["exit"],
                },
                indent=2,
            )
        )
    finally:
        if path is not None:
            path.unlink()
        loop.RescueLoopTests.tearDownClass()


if __name__ == "__main__":
    main()
