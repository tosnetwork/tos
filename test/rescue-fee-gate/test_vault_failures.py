"""EXPERIMENT: what happens to an admitted fee payment when something after ACCEPT fails.

The question is whether any failure after ACCEPT can leave the fee leaf unconsumed while the
vault still paid for the transaction, which would let one signed intent be charged again and
again. Each case runs a variant of the time-slot vault in the native emulator:

- a compute exception after COMMIT, and one between ACCEPT and COMMIT;
- an outgoing message the vault cannot fund, sent with ignore-errors (mode 1 + 2) and without
  it (mode 1);
- an outgoing message larger than the configured message size limit, with ignore-errors;
- a bounce of the payment back to the vault.

Environment: as test_fee_gate.py.
"""

# ruff: noqa: E402
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_slot_vault as slot
from cells import Cell, from_boc
from native import NOW, Emulator, account_data, compile_contract, internal, outgoing

SOURCE = slot.ROOT / "crypto/smartcont/rescue-fee-vault-slot.fc"
RESULTS = []

COMMIT = "  commit();\n"
BALANCE = (
    "  throw_unless(fee::insufficient_balance, required <= get_balance().pair_first());\n"
)
SEND_MODE = ".store_ref(payload).end_cell(), 1 + 2);"


def variant(name, replacements):
    text = SOURCE.read_text()
    for old, new in replacements:
        if text.count(old) != 1:
            raise AssertionError(f"anchor not found exactly once: {old!r}")
        text = text.replace(old, new)
    path = SOURCE.with_name(f"rescue-fee-vault-{name}.fc")
    path.write_text(text)
    return path


class VaultFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.emulator = Emulator(global_version=19)
        cls.small = Emulator(global_version=19, max_msg_cells=40)
        cls.codes = {}
        variants = {
            "base": [],
            "throw-after-commit": [(COMMIT, COMMIT + "  throw(77);\n")],
            "throw-before-commit": [(COMMIT, "  throw(78);\n" + COMMIT)],
            "oversized-ignore": [
                (
                    "  commit();\n",
                    "  commit();\n"
                    "  repeat (60) { payload = begin_cell().store_uint(fee::rescue_submit, 32)"
                    ".store_ref(payload).end_cell(); }\n",
                )
            ],
            "unfunded-ignore": [(BALANCE, "")],
            "unfunded-strict": [(BALANCE, ""), (SEND_MODE, ".store_ref(payload).end_cell(), 1);")],
            "unfunded-strict-no-commit": [
                (BALANCE, ""),
                (SEND_MODE, ".store_ref(payload).end_cell(), 1);"),
                (COMMIT, ""),
            ],
        }
        for name, replacements in variants.items():
            path = variant("x-" + name, replacements) if replacements else SOURCE
            try:
                cls.codes[name] = compile_contract(path.name, Path(cls.tmp.name) / f"{name}.boc")
            finally:
                if path != SOURCE:
                    path.unlink()

    @classmethod
    def tearDownClass(cls):
        cls.emulator.close()
        cls.small.close()
        cls.tmp.cleanup()

    def setUp(self):
        self.emulator.lib.transaction_emulator_set_unixtime(self.emulator.ptr, NOW)
        self.helper = slot.SlotVaultTests("test_slot_window")
        self.helper.code = None

    def run_case(self, name, value=1_000_000_000, balance=100_000_000_000, emulator=None):
        helper = self.helper
        emulator = emulator or self.emulator
        emulator.lib.transaction_emulator_set_unixtime(emulator.ptr, NOW)
        type(helper).tmp, type(helper).emulator = self.tmp, emulator
        type(helper).count = getattr(type(helper), "count", 0)
        key = helper.device()
        helper.code = self.codes[name]
        shard = helper.vault(key, balance=balance)
        i = slot.intent(slot.START_SLOT, value=value)
        message = slot.body(i, key.sign_at(slot.START_SLOT, i.hash))
        result = helper.submit(shard, message)
        return shard, message, result

    def leaf_and_balance(self, shard_boc):
        data, balance = account_data(shard_boc)
        s = data.slice()
        s.sint(32), s.uint(32), s.uint(32), s.uint(16)
        return s.uint(32), balance

    def record(self, name, result, before):
        after = from_boc(result["shard_account"]) if result["success"] else None
        d = result.get("details", {})
        leaf, balance = self.leaf_and_balance(after) if after else (None, None)
        _, start = self.leaf_and_balance(before)
        RESULTS.append(
            (
                name,
                result["success"],
                d.get("compute_success"),
                d.get("exit"),
                d.get("action"),
                d.get("aborted"),
                leaf,
                None if balance is None else start - balance,
            )
        )
        return after, leaf, balance

    def test_base_pays_and_consumes(self):
        shard, _, result = self.run_case("base")
        after, leaf, _ = self.record("base", result, shard)
        self.assertTrue(result["details"]["compute_success"])
        self.assertEqual(leaf, slot.START_SLOT + 1)
        self.assertEqual(len(outgoing(from_boc(result["transaction"]))), 1)

    def test_exception_after_commit_keeps_the_leaf_consumed(self):
        shard, message, result = self.run_case("throw-after-commit")
        after, leaf, _ = self.record("throw after commit", result, shard)
        self.assertTrue(result["success"], "an accepted external is included even if it throws")
        # The executor reports success for an accepted and committed run, whatever the exit
        # code: monitoring must read the exit code, not the success flag.
        self.assertTrue(result["details"]["compute_success"])
        self.assertEqual(result["details"]["exit"], 77)
        self.assertEqual(leaf, slot.START_SLOT + 1, "COMMIT must keep the consumed leaf")
        self.assertEqual(outgoing(from_boc(result["transaction"])), [])
        again = self.helper.submit(after, message)
        self.assertFalse(again["success"], "the same intent must not be charged twice")
        self.assertEqual(again.get("vm_exit_code"), 2004)

    def test_exception_between_accept_and_commit_is_charged_again(self):
        shard, message, result = self.run_case("throw-before-commit")
        after, leaf, _ = self.record("throw before commit", result, shard)
        self.assertTrue(result["success"])
        self.assertFalse(result["details"]["compute_success"])
        self.assertEqual(leaf, 0, "no COMMIT: the leaf is not consumed")
        again = self.helper.submit(after, message)
        self.assertTrue(again["success"], "the same signed intent is charged again")

    def test_oversized_control_sends_under_the_default_limit(self):
        # Control for the case below: the 61-cell payload is sent when the limit allows it,
        # so a skipped send there is caused by the size limit and nothing else.
        _, _, result = self.run_case("oversized-ignore")
        self.assertTrue(result["success"])
        self.assertEqual(len(outgoing(from_boc(result["transaction"]))), 1)

    def test_oversized_outgoing_message_with_ignore_errors(self):
        shard, message, result = self.run_case("oversized-ignore", emulator=self.small)
        after, leaf, _ = self.record("oversized, mode 1+2", result, shard)
        self.assertTrue(result["success"], result.get("error"))
        action = result["details"]["action"]
        RESULTS.append(("oversized action", action, None, None, None, None, None, None))
        if leaf == 0:
            again = self.small.send(after, self.helper_external(message))
            self.assertTrue(again["success"], "rolled-back leaf must be re-admissible")
        else:
            self.assertEqual(leaf, slot.START_SLOT + 1)
            self.assertEqual(outgoing(from_boc(result["transaction"])), [], "send must be skipped")

    def helper_external(self, message):
        from native import external

        return external(slot.VAULT, message)

    def test_unfunded_send_with_ignore_errors_is_skipped_and_leaf_consumed(self):
        shard, message, result = self.run_case(
            "unfunded-ignore", value=slot.MAX_VALUE, balance=1_000_000_000
        )
        after, leaf, _ = self.record("unfunded, mode 1+2", result, shard)
        self.assertTrue(result["success"])
        self.assertTrue(result["details"]["compute_success"])
        self.assertEqual(leaf, slot.START_SLOT + 1)
        self.assertEqual(outgoing(from_boc(result["transaction"])), [], "send must be skipped")
        again = self.helper.submit(after, message)
        self.assertFalse(again["success"])

    def test_unfunded_send_without_ignore_errors(self):
        # The question: does an action-phase failure roll back the leaf that COMMIT saved?
        for name in ("unfunded-strict", "unfunded-strict-no-commit"):
            with self.subTest(variant=name):
                shard, message, result = self.run_case(name, value=slot.MAX_VALUE, balance=1_000_000_000)
                after, leaf, _ = self.record(name, result, shard)
                self.assertTrue(result["success"])
                action = result["details"]["action"]
                self.assertIsNotNone(action)
                self.assertFalse(action["success"], "the send cannot be funded")
                again = self.helper.submit(after, message)
                replay_leaf = self.leaf_and_balance(from_boc(again["shard_account"]))[0] if again["success"] else None
                RESULTS.append((name + " replay", again["success"], None, again.get("vm_exit_code"), None, None, replay_leaf, None))
                if leaf == 0:
                    # Leaf rolled back: the same signed intent is admitted and charged again.
                    self.assertTrue(again["success"], "rolled-back leaf must be re-admissible")

    def test_bounce_is_bookkeeping_only(self):
        shard, _, result = self.run_case("base")
        after = from_boc(result["shard_account"])
        leaf_before, balance_before = self.leaf_and_balance(after)
        bounced = internal(slot.TARGET, slot.VAULT, Cell().uint(0xFFFFFFFF, 32), value=900_000_000, bounced=True)
        r = self.emulator.send(after, bounced)
        self.assertTrue(r["success"])
        leaf_after, balance_after = self.leaf_and_balance(from_boc(r["shard_account"]))
        self.assertEqual(leaf_after, leaf_before, "a bounce must not roll the leaf back")
        self.assertGreater(balance_after, balance_before)
        RESULTS.append(("bounce", True, r["details"]["compute_success"], r["details"]["exit"], None, None, leaf_after, balance_before - balance_after))


if __name__ == "__main__":
    program = unittest.main(verbosity=2, exit=False)
    print("case | included | compute_ok | exit | action | aborted | next_leaf | balance spent")
    for row in RESULTS:
        print(" | ".join(str(x) for x in row))
    sys.exit(0 if program.result.wasSuccessful() else 1)
