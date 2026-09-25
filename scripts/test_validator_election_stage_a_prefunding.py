"""Exercise the actual Stage A followup-capital method without starting nodes."""

import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace
import unittest


SOURCE = Path(__file__).with_name("validator-election-stage-a.py")


def prefund_method():
    tree = ast.parse(SOURCE.read_text())
    method = next(node for cls in tree.body if isinstance(cls, ast.ClassDef)
                  and cls.name == "ValidatorElectionRehearsal" for node in cls.body
                  if isinstance(node, ast.AsyncFunctionDef)
                  and node.name == "prefund_pq_followup_pool")
    namespace = {"WalletV1": object, "NANO": 1, "PQ_STAKE_MESSAGE_VALUE": 11_000,
                 "Cell": SimpleNamespace(empty=lambda: None)}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])),
                 str(SOURCE), "exec"), namespace)
    return namespace[method.name]


class FakeRehearsal:
    def __init__(self):
        self.wallets = [SimpleNamespace(address="wallet")]
        self.pools = [SimpleNamespace(address="pool")]
        self.balances = {"faucet": 30_000, "wallet": 0, "pool": 0}
        self.sends = []
        self.events = []

    async def balance(self, address):
        return self.balances[address]

    async def send_from_wallet(self, source, *, dest, amount, body, label):
        self.sends.append((source.address, dest, amount, label))
        self.balances[source.address] -= amount
        self.balances[dest] += amount

    async def retry(self, supplier, *, predicate, **_):
        value = await supplier()
        if not predicate(value):
            raise AssertionError("fresh capital was not observed")
        return value

    def event(self, name, **values):
        self.events.append((name, values))


class TestFollowupPrefunding(unittest.TestCase):
    def test_two_rounds_are_transferred_before_a_window(self):
        stage = FakeRehearsal()
        asyncio.run(prefund_method()(stage, SimpleNamespace(address="faucet"), 0))
        self.assertEqual([send[:3] for send in stage.sends], [
            ("faucet", "wallet", 22_080), ("wallet", "pool", 22_040)])
        self.assertEqual(stage.balances["pool"], 22_040)
        self.assertEqual(stage.balances["wallet"], 40)
        self.assertEqual(stage.events[0][0], "pq_followup_pool_prefunded")
        self.assertEqual(stage.events[0][1]["rounds"], [2, 3])


if __name__ == "__main__":
    unittest.main()
