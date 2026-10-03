#!/usr/bin/env python3
"""PR #128 policy, resource and delivery regressions on the real C++ executor.

Usage: test_pq_highload_policy.py --build <build-dir> --signer <test-pq-contracts-sign>

Configuration overrides below supply actual ConfigParam 43 cells to both native
emulators. They never replace transaction execution or signature verification.
Mutation kills require behavioral assertion failures, not compiler/setup errors.
"""

import json
import re
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import test_pq_highload as wallet

Cell = wallet.Cell
pqtest = wallet.pqtest
native = wallet.native
VERSIONS = (16, 18)
EXTRA_BUDGET = 8
REPORT = {}


def extra_currency_dict(entries):
    return pqtest.make_dict({key: Cell().varuint(amount, 32) for key, amount in entries.items()}, 32)


def read_extra(root):
    result = {}
    for key, leaf in pqtest.read_dict(root, 32).items():
        s = leaf.slice()
        result[key] = s.varuint(32)
        s.end()
    return result


def message_extra(message):
    s = message.slice()
    s.uint(4)
    s.addr()
    s.addr()
    s.coins()
    return read_extra(s.maybe())


def account_extra(shard):
    s = shard.refs[0].slice()
    assert s.uint(1) == 1
    s.addr()
    s.varuint(7)
    s.varuint(7)
    tag = s.uint(3)
    if tag == 1:
        s.uint(256)
    else:
        assert tag == 0
    s.uint(32)
    if s.uint(1):
        s.coins()
    s.uint(64)
    s.coins()
    return read_extra(s.maybe())


def payment(extra_flags=0, tag=1, value=10**9, extra=None):
    return (Cell().uint(0x10, 6).addr(wallet.PAYEE).coins(value).maybe(extra)
            .coins(extra_flags).coins(0).uint(0, 64).uint(0, 32)
            .uint(0, 1).uint(1, 1).ref(Cell().uint(tag, 32)))


class AssetWallet(wallet.Wallet):
    """Adopt every real post-transaction state and retain the outbound currency maps."""
    def send(self, message):
        before = self.data_hash()
        result = self.emulator.send(self.shard, message)
        details = pqtest.details_of(result)
        self.shard = pqtest.from_boc(result["shard_account"])
        details["data_changed"] = self.data_hash() != before
        messages = native.outgoing(pqtest.from_boc(result["transaction"]))
        details["out"] = [dict(wallet.parse_out(m), extra=message_extra(m)) for m in messages]
        return details


def size_limits43(tag, count):
    """Exact #01/#02/#03 layouts from block.tlb, including the v3 optional field."""
    common = native.size_limits(8192)
    if tag == 1:
        return common
    c = Cell(Cell().uint(tag, 8).bits + common.bits[8:])
    for value in (65536, 2048, 256, 256, count):
        c.uint(value, 32)
    c.uint(8, 8).uint(26, 32)
    if tag == 3:
        c.uint(1, 1).uint(10000, 32).uint(5 << 20, 32).uint(20480, 32)
    return c


@contextmanager
def configured_limit(tag, count=2):
    original = native.config

    def override(global_version=6, max_msg_cells=None):
        entries = pqtest.read_dict(original(global_version, max_msg_cells), 32)
        if tag is None:
            entries.pop(43, None)
        else:
            entries[43] = Cell().ref(size_limits43(tag, count))
        return pqtest.make_dict(entries, 32)

    with patch.object(native, "config", override):
        yield


class MessagePolicyTest(unittest.TestCase):
    assertExit = wallet.PqHighloadTest.assertExit
    first_verification_gas = wallet.PqHighloadTest.first_verification_gas
    assertRefusedBeforeVerification = wallet.PqHighloadTest.assertRefusedBeforeVerification

    def new_wallet(self, version=16, dense=False):
        data = None
        if dense:
            row = Cell().ref(Cell().uint(1, 1023))
            rows = pqtest.make_dict({shift: row for shift in range(0, 8190, 2)}, 13)
            data = wallet.wallet_data(old=rows, queries=rows, last_clean=native.NOW)
        w = AssetWallet(version=version, data=data)
        w.test_version = version
        self.addCleanup(w.emulator.close)
        return w

    def getter(self, w, method, *args):
        data, balance = native.account_data(w.shard)
        code, values = pqtest.get_method(wallet.CODE, data, w.address, method, args,
                                         balance=balance, global_version=w.test_version)
        self.assertEqual(code, 0, (method, values))
        return values

    def credit_assets(self, w, amounts):
        # Separate one-currency deposits keep the fixture valid even with live limit 1.
        for key, amount in amounts.items():
            deposit = (Cell().uint(4, 4).addr(wallet.RELAYER).addr(wallet.WALLET)
                       .coins(10**9).maybe(extra_currency_dict({key: amount}))
                       .coins(0).coins(0).uint(0, 64).uint(native.NOW, 32)
                       .uint(0, 1).uint(0, 1))
            d = w.send(deposit)
            self.assertExit(d, 0)
            self.assertEqual(d["out"], [])
        self.assertEqual(account_extra(w.shard), amounts)

    def assertPayments(self, d, amounts, extras=None, tags=None):
        self.assertExit(d, 0)
        self.assertEqual([o["dest"] for o in d["out"]],
                         [wallet.RELAYER] + [wallet.PAYEE] * len(amounts))
        self.assertEqual([o["value"] for o in d["out"][1:]], amounts)
        self.assertEqual([o["extra"] for o in d["out"][1:]],
                         extras if extras is not None else [{} for _ in amounts])
        if tags is not None:
            self.assertEqual([o["body"].slice().uint(32) for o in d["out"][1:]], tags)

    def test_policy_mask_matches_executor(self):
        header = (pqtest.ROOT / "tol/extra-flags-constants.h").read_text()
        source = Path(wallet.ARGS.source).read_text()
        active = int(re.search(r"EXTRA_FLAGS_VALID_MASK\s*=\s*(\d+)", header).group(1))
        mask = int(re.search(r"MESSAGE_EXTRA_FLAGS_ALLOWED\s*=\s*(\d+)", source).group(1))
        budget = int(re.search(r"BATCH_MAX_EXTRA_ENTRIES\s*=\s*(\d+)", source).group(1))
        self.assertEqual(active, 3)
        self.assertEqual(mask, active)
        self.assertEqual(budget, EXTRA_BUDGET)

    def test_reserved_flags_refused_before_verification(self):
        for version in VERSIONS:
            w = self.new_wallet(version)
            for i, flags in enumerate((4, 5, 7, 8, 12, 16, 1 << 64, 1 << 119)):
                with self.subTest(version=version, flags=flags):
                    qid = 200 + i
                    req = wallet.request([(1, payment(flags))], qid)
                    self.assertRefusedBeforeVerification(w, w.submit(req), "invalid_message", qid)

    def test_all_active_flags_remain_usable(self):
        for version in VERSIONS:
            w = self.new_wallet(version)
            d = w.submit(wallet.request([(1, payment(f, f)) for f in range(4)], 220))
            self.assertPayments(d, [10**9] * 4, tags=list(range(4)))
            self.assertIn(220, wallet.processed_ids(w.shard))

    def test_mixed_batch_refused_whole_and_id_reusable(self):
        for version in VERSIONS:
            w = self.new_wallet(version)
            bad = [(1, payment(0, 1)), (1, payment(4, 2)), (1, payment(3, 3))]
            self.assertExit(w.submit(wallet.request(bad, 230)), "invalid_message")
            self.assertNotIn(230, wallet.processed_ids(w.shard))
            good = [(1, payment(0, 1)), (1, payment(1, 2)), (1, payment(3, 3))]
            self.assertPayments(w.submit(wallet.request(good, 230)), [10**9] * 3, tags=[1, 2, 3])

    def test_extra_currency_collection_is_preflighted(self):
        for version in VERSIONS:
            w = self.new_wallet(version)
            self.credit_assets(w, {1: 10, 2: 20, 3: 30})
            too_many = extra_currency_dict({1: 1, 2: 2, 3: 3})
            req = wallet.request([(1, payment(extra=too_many))], 235)
            self.assertRefusedBeforeVerification(w, w.submit(req), "invalid_message", 235)
            malformed = pqtest.make_dict({1: Cell().uint(1, 5)}, 32)
            req = wallet.request([(1, payment(extra=malformed))], 236)
            self.assertRefusedBeforeVerification(w, w.submit(req), 9, 236)
            self.assertEqual(account_extra(w.shard), {1: 10, 2: 20, 3: 30})
            # This MUST transfer assets, not merely consume the query id with a skipped send.
            ok = extra_currency_dict({1: 1, 2: 2})
            d = w.submit(wallet.request([(1, payment(extra=ok))], 235))
            self.assertPayments(d, [10**9], extras=[{1: 1, 2: 2}])
            self.assertEqual(account_extra(w.shard), {1: 9, 2: 18, 3: 30})
            zeros = extra_currency_dict({1: 0, 2: 0, 3: 0, 4: 0})
            d = w.submit(wallet.request([(1, payment(extra=zeros))], 238))
            self.assertPayments(d, [10**9])
            self.assertEqual(account_extra(w.shard), {1: 9, 2: 18, 3: 30})

    def test_nonminimal_extra_amounts_refused(self):
        for version in VERSIONS:
            w = self.new_wallet(version)
            leaves = (Cell().uint(1, 5).uint(0, 8),
                      Cell().uint(2, 5).uint(1, 16),
                      Cell().uint(31, 5).uint(1, 248))
            for i, leaf in enumerate(leaves):
                with self.subTest(version=version, vector=i):
                    req = wallet.request([(1, payment(extra=pqtest.make_dict({1: leaf}, 32)))], 260 + i)
                    self.assertRefusedBeforeVerification(w, w.submit(req), "invalid_message", 260 + i)
            for leaf in (Cell().uint(0, 5).uint(1, 1), Cell().uint(0, 5).ref(Cell())):
                req = wallet.request([(1, payment(extra=pqtest.make_dict({1: leaf}, 32)))], 265)
                self.assertRefusedBeforeVerification(w, w.submit(req), 9, 265)

    def test_zero_entries_are_bounded(self):
        for version in VERSIONS:
            gas = []
            for n in (EXTRA_BUDGET + 1, 128, 1024, 4096):
                w = self.new_wallet(version)
                zeros = extra_currency_dict({i: 0 for i in range(n)})
                req = wallet.request([(1, payment(extra=zeros))], 270)
                d = w.submit(req)
                self.assertRefusedBeforeVerification(w, d, "invalid_message", 270)
                gas.append(d["gas"])
            # Some extra dictionary depth is permitted, not a walk proportional to n.
            self.assertLess(max(gas) - min(gas), 15_000, gas)
            REPORT[f"bounded_zero_scan_v{version}"] = gas

    def test_extra_budget_is_shared_across_the_batch(self):
        for version in VERSIONS:
            w = self.new_wallet(version)
            extra = extra_currency_dict({i: 0 for i in range(4)})
            shared = payment(extra=extra)
            req = wallet.request([(1, shared)] * 3, 280)
            self.assertRefusedBeforeVerification(w, w.submit(req), "invalid_message", 280)
            # The same cell referenced twice counts twice; 4+4 is exactly the budget.
            req = wallet.request([(1, shared)] * 2, 280)
            self.assertPayments(w.submit(req), [10**9] * 2)
            self.assertIn(280, wallet.processed_ids(w.shard))

    def test_live_config_limits_and_defaults(self):
        cases = [(None, 2), (1, 2)] + [(tag, n) for tag in (2, 3) for n in (0, 1, 2, 3)]
        for version in VERSIONS:
            for tag, limit in cases:
                with self.subTest(version=version, tag=tag, limit=limit), configured_limit(tag, limit):
                    w = self.new_wallet(version)
                    self.assertEqual(self.getter(w, "get_extra_currency_limits"), [limit, EXTRA_BUDGET])
                    denied = extra_currency_dict({i: 1 for i in range(limit + 1)})
                    req = wallet.request([(1, payment(extra=denied))], 290)
                    self.assertRefusedBeforeVerification(w, w.submit(req), "invalid_message", 290)
                    amounts = {i: i + 1 for i in range(limit)}
                    self.credit_assets(w, amounts)
                    allowed = extra_currency_dict(amounts)
                    d = w.submit(wallet.request([(1, payment(extra=allowed))], 290))
                    self.assertPayments(d, [10**9], extras=[amounts])
                    self.assertEqual(account_extra(w.shard), {})
                    # Zero-valued entries remain usable even when the non-zero limit is 0.
                    z = extra_currency_dict({0: 0, 1: 0})
                    self.assertPayments(w.submit(wallet.request([(1, payment(extra=z))], 291)), [10**9])

    def test_active_flags_are_still_signed(self):
        for version in VERSIONS:
            w = self.new_wallet(version)
            original = wallet.request([(1, payment(3))], 240)
            sig = pqtest.stored(pqtest.sign(wallet.OWNER_KEY, original.hash, wallet.CONTEXT))
            tampered = wallet.request([(1, payment(1))], 240)
            self.assertExit(w.submit(tampered, signature=sig), "invalid_signature")
            self.assertNotIn(240, wallet.processed_ids(w.shard))
            self.assertPayments(w.submit(original, signature=sig), [10**9])

    def test_extra_amounts_are_still_signed(self):
        for version in VERSIONS:
            w = self.new_wallet(version)
            self.credit_assets(w, {1: 10})
            original = wallet.request([(1, payment(extra=extra_currency_dict({1: 3})))], 300)
            sig = pqtest.stored(pqtest.sign(wallet.OWNER_KEY, original.hash, wallet.CONTEXT))
            tampered = wallet.request([(1, payment(extra=extra_currency_dict({1: 4})))], 300)
            self.assertExit(w.submit(tampered, signature=sig), "invalid_signature")
            self.assertEqual(account_extra(w.shard), {1: 10})
            self.assertPayments(w.submit(original, signature=sig), [10**9], extras=[{1: 3}])
            self.assertEqual(account_extra(w.shard), {1: 7})

    def test_fee_getter_rejects_impossible_counts(self):
        for version in VERSIONS:
            w = self.new_wallet(version)
            data, balance = native.account_data(w.shard)
            for n in (-1, 0, 255, 256, (1 << 256) - 1):
                code, values = pqtest.get_method(wallet.CODE, data, w.address, "get_required_value", (n,),
                                                 balance=balance, global_version=version)
                self.assertEqual(code, wallet.ERR["invalid_action"], (n, code, values))
            for n in (1, wallet.MAX_ACTIONS):
                self.assertGreater(self.getter(w, "get_required_value", n)[0], 0)

    def test_full_batch_active_flags_at_quoted_value(self):
        for version in VERSIONS:
            w = self.new_wallet(version, dense=True)
            qid = (8191 << 10) | wallet.MAX_ACTIONS
            sends = [(1, payment(3, i, value=1)) for i in range(wallet.MAX_ACTIONS)]
            quote = self.getter(w, "get_required_value", wallet.MAX_ACTIONS)[0]
            self.assertPayments(w.submit(wallet.request(sends, qid), value=quote),
                                [1] * wallet.MAX_ACTIONS, tags=list(range(wallet.MAX_ACTIONS)))

    def test_maximum_extra_work_at_exact_quote(self):
        source = Path(wallet.ARGS.source).read_text()
        profile = {k: int(re.search(rf"const int fee::{k} = (\d+);", source).group(1))
                   for k in ("base_gas", "gas_per_action", "extra_gas")}
        large = (1 << 248) - 1
        for version in VERSIONS:
            for n in (1, wallet.MAX_ACTIONS):
                for spread in (False, True) if n > 1 else (False,):
                    with self.subTest(version=version, actions=n, spread=spread):
                        w = self.new_wallet(version, dense=True)
                        maps = [{} for _ in range(n)]
                        if spread:
                            for i in range(EXTRA_BUDGET):
                                maps[i] = {(1 << 31) + i: large}
                        else:
                            maps[-1] = {i: large if i < 2 else 0 for i in range(EXTRA_BUDGET)}
                        funds = {k: v for m in maps for k, v in m.items() if v}
                        self.credit_assets(w, funds)
                        sends = [(1, payment(3, i, 1, extra_currency_dict(m))) for i, m in enumerate(maps)]
                        qid = (8191 << 10) | n
                        quote = self.getter(w, "get_required_value", n)[0]
                        req = wallet.request(sends, qid)
                        self.assertExit(w.submit(req, value=quote - 1), "insufficient_value")
                        self.assertNotIn(qid, wallet.processed_ids(w.shard))
                        d = w.submit(req, value=quote)
                        expected = [{k: v for k, v in m.items() if v} for m in maps]
                        self.assertPayments(d, [1] * n, extras=expected, tags=list(range(n)))
                        self.assertEqual(account_extra(w.shard), {})
                        self.assertIn(qid, wallet.processed_ids(w.shard))
                        bound = profile["base_gas"] + n * profile["gas_per_action"] + profile["extra_gas"]
                        self.assertLessEqual(d["gas"], bound)
                        self.assertLess(bound, 1_000_000)
                        REPORT[f"extra_work_v{version}_n{n}_spread{int(spread)}"] = {
                            "gas": d["gas"], "bound": bound, "quote": quote,
                            "refund": d["out"][0]["value"], "out_count": len(d["out"])}


def run_tests(method=None):
    suite = (unittest.TestSuite([MessagePolicyTest(method)]) if method else
             unittest.defaultTestLoader.loadTestsFromTestCase(MessagePolicyTest))
    return unittest.TextTestRunner(verbosity=2).run(suite)


def main():
    baseline = run_tests()
    if not baseline.wasSuccessful():
        return 1
    original_code = wallet.CODE
    source = Path(wallet.ARGS.source).resolve()
    text = source.read_text()
    mutations = (
        ("extra_flags", "  throw_unless(error::invalid_message, (extra_flags & MESSAGE_EXTRA_FLAGS_ALLOWED) == extra_flags);\n", "", "test_reserved_flags_refused_before_verification"),
        ("fee_count", "  throw_unless(error::invalid_action, (action_count > 0) & (action_count <= max_actions));\n", "", "test_fee_getter_rejects_impossible_counts"),
        ("extra_collection", "    entries = require_valid_extra_currencies(extra, extra_left);\n", "", "test_extra_currency_collection_is_preflighted"),
        ("zero_scan_bound", "    throw_unless(error::invalid_message, visited < remaining);\n", "", "test_zero_entries_are_bounded"),
        ("batch_work_bound", "    extra_left -= require_valid_message(message, extra_left);\n", "    require_valid_message(message, extra_left);\n", "test_extra_budget_is_shared_across_the_batch"),
        ("minimal_amount", "      throw_unless(error::invalid_message, value.preload_uint(8) != 0);\n", "", "test_nonminimal_extra_amounts_refused"),
        ("live_limit", "  int limit = message_extra_currency_limit();\n", "  int limit = 2;\n", "test_live_config_limits_and_defaults"),
    )
    killed = []
    try:
        for name, old, replacement, method in mutations:
            if text.count(old) != 1:
                raise RuntimeError(f"expected exactly one {name} mutation target")
            with tempfile.NamedTemporaryFile(mode="w", suffix=".fc", prefix=".pq-policy-mutant-",
                                             dir=source.parent) as mutant, tempfile.TemporaryDirectory() as output:
                mutant.write(text.replace(old, replacement, 1))
                mutant.flush()
                wallet.CODE = pqtest.compile_source(mutant.name, Path(output) / "mutant.boc")
                print(f"EXPECTED ASSERTION FAILURE: {name}", file=sys.stderr)
                result = run_tests(method)
                if result.testsRun == 0 or result.errors or not result.failures:
                    raise RuntimeError(f"{name} was not killed by a functional assertion")
                killed.append({"guard": name, "tests": [test.id() for test, _ in result.failures]})
    finally:
        wallet.CODE = original_code
    restored = run_tests()
    print(json.dumps({"baseline_tests": baseline.testsRun, "killed": killed,
                      "restored_tests": restored.testsRun, "restored_ok": restored.wasSuccessful(),
                      "measurements": REPORT}, sort_keys=True))
    return 0 if restored.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
