"""Receipt parser controls, not kernel or packet proof.

The old actual nft JSON supplies the 48 flow rules. Only the new identity chain
and rule below are constructed test data; they must later be observed live.
"""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

from x02_nft_rules import RuleManager
from x02_partial_sequence import DIRECTIONS

ORIGINAL = Path("/datax/n6-unit-agents/X02/evidence/procfd-b2c31241a2ba/positive/kernel.jsonl")


def fixture():
    rows = [json.loads(line) for line in ORIGINAL.read_text().splitlines()]
    captures = [bytes.fromhex(row["stdout_hex"]) for row in rows
                if row.get("event") == "nft_command" and row["argv"] ==
                ["/usr/sbin/nft", "-j", "-a", "list", "table", "ip", "x02_2026092600000001"]]
    if len(captures) != 1:
        raise ValueError("actual original snapshot identity differs")
    original = json.loads(captures[0])
    baseline = copy.deepcopy(original)
    baseline["nftables"].extend([
        {"chain": {"family": "ip", "table": "x02_2026092600000001", "name": "identity", "handle": 900}},
        {"rule": {"family": "ip", "table": "x02_2026092600000001", "chain": "identity",
                  "handle": 901, "comment": "x02-owner-2026092600000001",
                  "expr": [{"counter": {"packets": 0, "bytes": 0}}]}}])
    endpoints = {direction: ("127.0.0.1", 32000 + ordinal, "127.0.0.2", 33000 + ordinal)
                 for ordinal, direction in enumerate(DIRECTIONS)}
    manager = RuleManager("2026092600000001", SimpleNamespace(endpoints=endpoints),
                          SimpleNamespace(queues={32600 + ordinal: direction
                                                  for ordinal, direction in enumerate(DIRECTIONS)}), None)
    return manager, original, baseline


def encoded(snapshot):
    return json.dumps(snapshot).encode()


class IdentityReceiptControls(unittest.TestCase):
    def test_constructed_anchor_contract_positive(self):
        manager, original, baseline = fixture()
        owner, counts = manager.validate_snapshot(encoded(baseline))
        self.assertEqual(owner["scheme"], "tos.x02.nft-identity-chain.v2")
        self.assertEqual(owner["marker"], "x02-owner-2026092600000001")
        self.assertEqual(owner["identity_rule"], 901)
        self.assertEqual(len(counts), 48)

    def test_actual_missing_anchor_and_missing_new_rule(self):
        manager, original, baseline = fixture()
        for snapshot in (original, {"nftables": baseline["nftables"][:-1]}):
            with self.assertRaisesRegex(ValueError, "^missing or extra table/chain/rule$"):
                manager.validate_snapshot(encoded(snapshot))

    def test_duplicate_wrong_chain_foreign_token_and_changed_token(self):
        manager, original, baseline = fixture()
        for case, reason in (("duplicate", "duplicate table identity rule"),
                             ("chain", "table identity chain/expression differs"),
                             ("foreign", "table identity marker differs"),
                             ("changed", "table identity marker differs")):
            snapshot = copy.deepcopy(baseline)
            rule = snapshot["nftables"][-1]["rule"]
            if case == "duplicate":
                snapshot["nftables"].append(copy.deepcopy(snapshot["nftables"][-1]))
            elif case == "chain":
                rule["chain"] = "enqueue"
            else:
                rule["comment"] = ("foreign-fixture-" + manager.marker if case == "foreign" else manager.marker + "-changed")
            with self.subTest(case=case), self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                manager.validate_snapshot(encoded(snapshot))

    def test_unhooked_chain_extra_object_and_visible_comment_conflict(self):
        manager, original, baseline = fixture()
        for case, reason in (("hook", "identity chain must be unique and unhooked"),
                             ("extra", "unexpected object in owned table"),
                             ("comment", "table name, visible comment or flags differ")):
            snapshot = copy.deepcopy(baseline)
            if case == "hook":
                snapshot["nftables"][-2]["chain"]["hook"] = "output"
            elif case == "extra":
                snapshot["nftables"].append({"set": {"family": "ip"}})
            else:
                next(item["table"] for item in snapshot["nftables"] if "table" in item)["comment"] = "foreign"
            with self.subTest(case=case), self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                manager.validate_snapshot(encoded(snapshot))

    def test_recorded_identity_handle_change_rejects(self):
        manager, original, baseline = fixture()
        manager.ownership, unused = manager.validate_snapshot(encoded(baseline))
        baseline["nftables"][-1]["rule"]["handle"] = 902
        with self.assertRaisesRegex(ValueError, "^recorded owner handles changed$"):
            manager.validate_snapshot(encoded(baseline))

    def test_otherwise_valid_foreign_fixture_and_install_boundary(self):
        manager, original, baseline = fixture()
        foreign = encoded(baseline).replace(manager.marker.encode(), ("foreign-fixture-" + manager.marker).encode())
        owner, unused = manager.validate_snapshot(foreign, fixture_marker="foreign-fixture-" + manager.marker)
        self.assertEqual(owner["marker"], "foreign-fixture-" + manager.marker)
        self.assertEqual(owner["identity_rule"], 901)
        with self.assertRaisesRegex(ValueError, "^rule owner marker differs$"):
            manager.validate_snapshot(foreign)
        manager.attempted = True
        with self.assertRaisesRegex(ValueError, "^foreign marker verification is fixture-only before install$"):
            manager.validate_snapshot(foreign, fixture_marker="foreign-fixture-" + manager.marker)


if __name__ == "__main__":
    unittest.main()
