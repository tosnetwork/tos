"""Offline controls for the queued-withdrawal stake refusal evidence."""

import ast
import asyncio
import base64
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import unittest


SOURCE = Path(os.environ.get("E16_ROUTE_SOURCE", Path(__file__).with_name("nominator-pool-lifecycle-e2e.py")))


def load_functions(*names):
    tree = ast.parse(SOURCE.read_text())
    selected = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            selected.append(node)
        if isinstance(node, ast.ClassDef) and node.name == "PoolLifecycle":
            selected.extend(item for item in node.body if isinstance(item, ast.AsyncFunctionDef) and item.name in names)
    namespace = {"Any": object, "POOL_STATE_IDLE": 0,
                 "base64": base64, "hashlib": hashlib}
    exec(compile(ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])), str(SOURCE), "exec"), namespace)
    return namespace


class Body:
    def __init__(self, query_id):
        self.query_id = query_id
        self.remaining_bits = 96

    def load_uint(self, bits):
        self.remaining_bits -= bits
        return 0x4E73744B if bits == 32 else self.query_id


class TestQueuedStakeRefusal(unittest.TestCase):
    def test_exact_transaction_and_vm_exit_required(self):
        namespace = load_functions("_queued_stake_refusal")
        namespace["InternalMsgInfo"] = type("InternalMsgInfo", (), {})
        namespace["_decoded_transaction"] = lambda raw: raw
        check = namespace["_queued_stake_refusal"]

        def transaction(query, *, code=85, aborted=True):
            message = SimpleNamespace(info=namespace["InternalMsgInfo"](), body=SimpleNamespace(begin_parse=lambda: Body(query)))
            return SimpleNamespace(in_msg=message, description=SimpleNamespace(aborted=aborted, compute_ph=SimpleNamespace(exit_code=code)), lt=42, data=b"pool-transaction-boc")

        self.assertIsNone(check([], 7))
        self.assertIsNone(check([transaction(8)], 7))
        self.assertIsNone(check([transaction(7, code=0)], 7))
        self.assertIsNone(check([transaction(7, aborted=False)], 7))
        self.assertEqual(check([transaction(7)], 7), {
            "transaction_lt": "42",
            "transaction_boc_base64": base64.b64encode(b"pool-transaction-boc").decode(),
            "transaction_boc_sha256": hashlib.sha256(b"pool-transaction-boc").hexdigest(),
            "exit_code": 85,
        })

    def test_idle_state_without_finalized_refusal_cannot_pass(self):
        namespace = load_functions("stake_must_be_refused")
        async def no_sleep(*args):
            pass
        namespace["asyncio"] = SimpleNamespace(sleep=no_sleep)
        namespace["_transactions_since"] = self._empty_history
        namespace["_queued_stake_refusal"] = lambda transactions, query: None

        class Harness:
            client = object()
            pool_address = object()
            stake_feedback_baselines = {7: (object(), object())}

            async def stake_through_pool(self, election_id, *, label):
                return 7

            async def retry(self, action, *, predicate, **kwargs):
                result = await action()
                if not predicate(result):
                    raise TimeoutError("no exact VM85 transaction")
                return result

            async def pool_data(self):
                return SimpleNamespace(state=0, state_name="idle")

            def check(self, *args, **kwargs):
                raise AssertionError("idle state must not reach a passing check")

        with self.assertRaisesRegex(TimeoutError, "no exact VM85 transaction"):
            asyncio.run(namespace["stake_must_be_refused"](Harness(), 123))

    @staticmethod
    async def _empty_history(*args):
        return [], 0, True, object()


if __name__ == "__main__":
    unittest.main()
