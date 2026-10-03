#!/usr/bin/env python3
"""PR #128 message-policy regressions on the real C++ executor, at v16 and v18.

Usage: test_pq_highload_policy.py --build <build-dir> --signer <test-pq-contracts-sign>

The original wallet suite provides the compiler, signer and transaction helpers, not
mocked outcomes. After a passing baseline, remove each new guard independently in a
temporary sibling source, require a functional assertion failure (never a compile/run
error), then restore the original code and require another passing baseline.
"""

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

import test_pq_highload as wallet

Cell = wallet.Cell
pqtest = wallet.pqtest
native = wallet.native
VERSIONS = (16, 18)
FLAGS_GUARD = (
    "  throw_unless(error::invalid_message, "
    "(extra_flags & MESSAGE_EXTRA_FLAGS_ALLOWED) == extra_flags);\n"
)
COUNT_GUARD = (
    "  throw_unless(error::invalid_action, "
    "(action_count > 0) & (action_count <= max_actions));\n"
)
EXTRA_COLLECTION_GUARD = "  require_valid_extra_currencies(extra);\n"


def extra_currency_dict(entries):
    """HashmapE 32 -> VarUInteger 32 values."""
    return pqtest.make_dict(
        {
            key: Cell().uint((amount.bit_length() + 7) // 8, 5).uint(
                amount, ((amount.bit_length() + 7) // 8) * 8
            )
            for key, amount in entries.items()
        },
        32,
    )


def payment(extra_flags, tag=1, value=10**9, extra=None):
    """The VarUInteger 16 before fwd_fee is extra_flags, not the obsolete ihr_fee."""
    return (
        Cell()
        .uint(0x10, 6)  # internal, ihr_disabled, non-bounceable, src addr_none
        .addr(wallet.PAYEE)
        .coins(value)
        .maybe(extra)
        .coins(extra_flags)
        .coins(0)  # fwd_fee
        .uint(0, 64)
        .uint(0, 32)
        .uint(0, 1)  # no StateInit
        .uint(1, 1)
        .ref(Cell().uint(tag, 32))
    )


class MessagePolicyTest(unittest.TestCase):
    # Reuse assertions, without inheriting and running the original twenty tests again.
    assertExit = wallet.PqHighloadTest.assertExit
    first_verification_gas = wallet.PqHighloadTest.first_verification_gas
    assertRefusedBeforeVerification = wallet.PqHighloadTest.assertRefusedBeforeVerification
    getter = wallet.PqHighloadTest.getter
    dense_wallet = wallet.PqHighloadTest.dense_wallet

    def test_policy_mask_matches_executor(self):
        header = (pqtest.ROOT / "tol/extra-flags-constants.h").read_text()
        executor_mask = int(re.search(r"EXTRA_FLAGS_VALID_MASK\s*=\s*(\d+)", header).group(1))
        source = Path(wallet.ARGS.source).read_text()
        contract_mask = int(
            re.search(r"MESSAGE_EXTRA_FLAGS_ALLOWED\s*=\s*(\d+)", source).group(1)
        )
        self.assertEqual(executor_mask, 3, "update the vectors when the active policy changes")
        self.assertEqual(contract_mask, executor_mask)

    def test_reserved_flags_refused_before_verification(self):
        for version in VERSIONS:
            w = wallet.Wallet(version=version)
            for i, flags in enumerate((4, 5, 7, 8, 12, 16, 1 << 64, 1 << 119)):
                with self.subTest(version=version, flags=flags):
                    qid = 200 + i
                    req = wallet.request([(1, payment(flags))], qid)
                    self.assertRefusedBeforeVerification(
                        w, w.submit(req), "invalid_message", qid
                    )

    def test_all_active_flags_remain_usable(self):
        for version in VERSIONS:
            with self.subTest(version=version):
                w = wallet.Wallet(version=version)
                sends = [(1, payment(flags, flags)) for flags in range(4)]
                d = w.submit(wallet.request(sends, 220))
                self.assertExit(d, 0)
                self.assertEqual([o["dest"] for o in d["out"]], [wallet.RELAYER] + [wallet.PAYEE] * 4)
                self.assertEqual([o["value"] for o in d["out"][1:]], [10**9] * 4)
                self.assertEqual([o["body"].slice().uint(32) for o in d["out"][1:]], list(range(4)))
                self.assertIn(220, wallet.processed_ids(w.shard))

    def test_mixed_batch_refused_whole_and_id_reusable(self):
        for version in VERSIONS:
            with self.subTest(version=version):
                w = wallet.Wallet(version=version)
                bad = [(1, payment(0, 1)), (1, payment(4, 2)), (1, payment(3, 3))]
                self.assertExit(w.submit(wallet.request(bad, 230)), "invalid_message")
                self.assertNotIn(230, wallet.processed_ids(w.shard))
                fixed = [(1, payment(0, 1)), (1, payment(1, 2)), (1, payment(3, 3))]
                d = w.submit(wallet.request(fixed, 230))
                self.assertExit(d, 0)
                self.assertEqual([o["dest"] for o in d["out"]], [wallet.RELAYER] + [wallet.PAYEE] * 3)
                self.assertEqual([o["body"].slice().uint(32) for o in d["out"][1:]], [1, 2, 3])
                self.assertIn(230, wallet.processed_ids(w.shard))

    def test_extra_currency_collection_is_preflighted(self):
        for version in VERSIONS:
            with self.subTest(version=version):
                w = wallet.Wallet(version=version)
                # Three non-zero currencies exceed the active ConfigParam 43 limit of 2.
                too_many = extra_currency_dict({1: 1, 2: 1, 3: 1})
                qid = 235
                req = wallet.request([(1, payment(0, extra=too_many))], qid)
                self.assertRefusedBeforeVerification(w, w.submit(req), "invalid_message", qid)
                self.assertNotIn(qid, wallet.processed_ids(w.shard))

                # Malformed VarUInteger 32 leaf: declares one byte but carries none.
                malformed = pqtest.make_dict({1: Cell().uint(1, 5)}, 32)
                qid = 236
                req = wallet.request([(1, payment(0, extra=malformed))], qid)
                self.assertRefusedBeforeVerification(w, w.submit(req), 9, qid)
                self.assertNotIn(qid, wallet.processed_ids(w.shard))

                # The active maximum remains usable.
                ok = extra_currency_dict({1: 1, 2: 2})
                qid = 237
                d = w.submit(wallet.request([(1, payment(0, extra=ok))], qid))
                self.assertExit(d, 0)
                self.assertIn(qid, wallet.processed_ids(w.shard))

                # Executor removes zero-valued currencies before applying the count limit.
                zeros = extra_currency_dict({1: 0, 2: 0, 3: 0, 4: 0})
                qid = 238
                d = w.submit(wallet.request([(1, payment(0, extra=zeros))], qid))
                self.assertExit(d, 0)
                self.assertIn(qid, wallet.processed_ids(w.shard))

    def test_active_flags_are_still_signed(self):
        for version in VERSIONS:
            with self.subTest(version=version):
                w = wallet.Wallet(version=version)
                original = wallet.request([(1, payment(3))], 240)
                signature = pqtest.stored(pqtest.sign(wallet.OWNER_KEY, original.hash, wallet.CONTEXT))
                tampered = wallet.request([(1, payment(1))], 240)
                self.assertExit(w.submit(tampered, signature=signature), "invalid_signature")
                self.assertNotIn(240, wallet.processed_ids(w.shard))
                self.assertExit(w.submit(original, signature=signature), 0)

    def test_fee_getter_rejects_impossible_counts(self):
        w = wallet.Wallet()
        data, balance = native.account_data(w.shard)
        for count in (-1, 0, 255, 256, (1 << 256) - 1):
            with self.subTest(count=count):
                code, values = pqtest.get_method(
                    wallet.CODE, data, w.address, "get_required_value", (count,), balance=balance
                )
                self.assertEqual(code, wallet.ERR["invalid_action"], (count, code, values))
        for count in (1, wallet.MAX_ACTIONS):
            self.assertGreater(self.getter(w, "get_required_value", count)[0], 0)

    def test_full_batch_active_flags_at_quoted_value(self):
        for version in VERSIONS:
            with self.subTest(version=version):
                w = self.dense_wallet()
                w.emulator = native.Emulator(global_version=version)
                qid = (8191 << 10) | wallet.MAX_ACTIONS
                sends = [(1, payment(3, i, value=1)) for i in range(wallet.MAX_ACTIONS)]
                value = self.getter(w, "get_required_value", wallet.MAX_ACTIONS)[0]
                d = w.submit(wallet.request(sends, qid), value=value)
                self.assertExit(d, 0)
                self.assertEqual(len(d["out"]), wallet.MAX_ACTIONS + 1)
                self.assertEqual(d["out"][0]["dest"], wallet.RELAYER)
                self.assertEqual([o["value"] for o in d["out"][1:]], [1] * wallet.MAX_ACTIONS)
                self.assertIn(qid, wallet.processed_ids(w.shard))


def run_tests(method=None):
    suite = (
        unittest.TestSuite([MessagePolicyTest(method)])
        if method is not None
        else unittest.defaultTestLoader.loadTestsFromTestCase(MessagePolicyTest)
    )
    return unittest.TextTestRunner(verbosity=2).run(suite)


def main():
    baseline = run_tests()
    if not baseline.wasSuccessful():
        return 1
    original_code = wallet.CODE
    source = Path(wallet.ARGS.source).resolve()
    text = source.read_text()
    killed = []
    mutations = (
        ("extra_flags", FLAGS_GUARD, "test_reserved_flags_refused_before_verification"),
        ("fee_count", COUNT_GUARD, "test_fee_getter_rejects_impossible_counts"),
        ("extra_collection", EXTRA_COLLECTION_GUARD, "test_extra_currency_collection_is_preflighted"),
    )
    try:
        for name, guard, method in mutations:
            if text.count(guard) != 1:
                raise RuntimeError(f"expected exactly one {name} guard")
            # Keep the temporary source beside the original for its relative #includes.
            # Never overwrite the checked-in source; compiler errors are not mutant kills.
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".fc", prefix=".pq-policy-mutant-", dir=source.parent
            ) as mutant, tempfile.TemporaryDirectory() as output:
                mutant.write(text.replace(guard, "", 1))
                mutant.flush()
                wallet.CODE = pqtest.compile_source(mutant.name, Path(output) / "mutant.boc")
                print(f"EXPECTED ASSERTION FAILURE: removed {name}", file=sys.stderr)
                result = run_tests(method)
                if result.testsRun == 0 or result.errors or not result.failures:
                    raise RuntimeError(f"{name} was not killed by a functional assertion")
                killed.append({"guard": name, "tests": [test.id() for test, _ in result.failures]})
    finally:
        wallet.CODE = original_code
    restored = run_tests()
    print(json.dumps({"baseline_tests": baseline.testsRun, "killed": killed,
                      "restored_tests": restored.testsRun, "restored_ok": restored.wasSuccessful()}))
    return 0 if restored.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
