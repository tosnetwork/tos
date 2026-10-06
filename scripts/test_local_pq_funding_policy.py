"""Regressions for the actual shared deficit/runway policy (no node required)."""

import unittest

from local_pq_funding_policy import DAY, NANO, coins, funding_plan

NOW = 1791250000
GRANT = 6_440_000_000
TARGET = GRANT * 30 * 144
PAYER = "-1:" + "01" * 32


def state(**changes):
    value = dict(
        funds=TARGET,
        allowance=TARGET,
        limit=20 * NANO,
        floor=10 * NANO,
        expires=NOW + 30 * DAY,
        payer=PAYER,
    )
    value.update(changes)
    return value


def plan(**changes):
    return funding_plan(state(**changes), now=NOW, grant=GRANT, payer=PAYER)


class FundingPolicyTests(unittest.TestCase):
    def test_healthy_does_not_deposit(self):
        self.assertIsNone(plan())

    def test_missing_authorization_gets_thirty_days(self):
        result = plan(funds=0, allowance=0, limit=0, floor=0, expires=0, payer="self")
        self.assertEqual(result["deposit"], TARGET)
        self.assertEqual(result["allowance"], TARGET)
        self.assertEqual(result["expires"], NOW + 30 * DAY)

    def test_replenishes_deficit_not_full_target(self):
        result = plan(funds=TARGET // 4)
        self.assertEqual(result["deposit"], TARGET - TARGET // 4)
        self.assertEqual(result["funds"], TARGET)

    def test_expiry_only_renewal_has_zero_deposit(self):
        self.assertEqual(plan(expires=NOW + DAY)["deposit"], 0)

    def test_allowance_only_renewal_has_zero_deposit(self):
        self.assertEqual(plan(allowance=0)["deposit"], 0)

    def test_existing_surplus_is_not_deposited_again(self):
        result = plan(funds=2 * TARGET, expires=NOW + DAY)
        self.assertEqual((result["deposit"], result["funds"]), (0, 2 * TARGET))

    def test_renews_at_twenty_five_percent(self):
        self.assertIsNotNone(plan(allowance=TARGET // 4))
        self.assertIsNone(plan(allowance=TARGET // 4 + 1))

    def test_wrong_payer_requires_new_authorization(self):
        self.assertEqual(plan(payer="different")["payer"], PAYER)

    def test_policy_mismatch_is_not_treated_as_ready(self):
        self.assertIsNotNone(plan(limit=GRANT - 1))
        self.assertIsNotNone(plan(floor=0))

    def test_fee_increase_does_not_raise_the_cap_silently(self):
        with self.assertRaises(ValueError):
            funding_plan(state(), now=NOW, grant=21 * NANO, payer=PAYER)

    def test_zero_deposit_and_integer_boundaries(self):
        self.assertEqual(coins(0, zero=True), 0)
        for value in (True, 1.0, -1, 1 << 120):
            with self.subTest(value=value), self.assertRaises(ValueError):
                coins(value, zero=True)
        with self.assertRaises(ValueError):
            coins(0)

    def test_invalid_lifetime_or_expiry_is_refused(self):
        for changes in (
            dict(days=0),
            dict(days=31),
            dict(period=1),
            dict(now=(1 << 32) - DAY),
            dict(now=True),
        ):
            args = dict(now=NOW, grant=GRANT, payer=PAYER)
            args.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                funding_plan(state(), **args)

    def test_explicit_short_run_target_does_not_change_persistent_default(self):
        result = funding_plan(
            state(funds=0, allowance=0), now=NOW, grant=GRANT, payer=PAYER, target=80 * NANO, days=1
        )
        self.assertEqual(result["deposit"], 80 * NANO)
        self.assertEqual(plan(funds=0)["deposit"], TARGET)


if __name__ == "__main__":
    unittest.main()
