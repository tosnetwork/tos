"""Instrument checks for the real-network state assertions, not proof validation."""
import importlib.util
import asyncio
from pathlib import Path
import sys
import unittest
import tempfile
from types import SimpleNamespace
from unittest.mock import AsyncMock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "test/tostester/src"))
from pytosiq_core import Builder
from tosapi import toslib_api
from toslib.client import ToslibClient

spec = importlib.util.spec_from_file_location("m1_network", REPO / "scripts/m1-real-manager-sync.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CounterStateCheck(unittest.IsolatedAsyncioTestCase):
    async def test_signature_results_match_the_injected_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node = root / "network/node5"
            node.mkdir(parents=True)
            bad, good = "ab" * 32, "cd" * 32
            log = node / "log"
            server = root / "network/node1"
            server.mkdir()
            (server / "log").write_text(f"COUNTER_BAD_SIGNATURE_SENT {bad}\n"
                                        f"COUNTER_REMOTE_PROOF_REJECTED {bad}\n")
            log.write_text(f"COUNTER_REMOTE_PROOF_ACCEPTED {good}\n")
            sent, accepted, rejected = module.signature_proof_results(root)
            self.assertFalse(sent & rejected)
            log.write_text(log.read_text() + f"COUNTER_REMOTE_PROOF_REJECTED {bad.upper()}\n")
            sent, accepted, rejected = module.signature_proof_results(root)
            self.assertEqual(sent & rejected, {bad.upper()})
            self.assertFalse(sent & accepted)
            log.write_text(log.read_text() + f"COUNTER_REMOTE_PROOF_ACCEPTED {bad}\n")
            with self.assertRaisesRegex(AssertionError, "corrupted committee signature"):
                await asyncio.wait_for(module.watch_proof_acceptance(root), 1)

    async def test_client_encodes_pinned_request(self):
        client = object.__new__(ToslibClient)
        response = toslib_api.Raw_fullAccountState().to_dict()
        client._toslib_wrapper = SimpleNamespace(execute=AsyncMock(return_value=response))
        block = toslib_api.Tos_blockIdExt(workchain=2, seqno=17)
        address = module.Address((2, bytes(32)))
        await client.raw_get_account_state(address, block_id=block)
        query = client._toslib_wrapper.execute.call_args.args[0].to_dict()
        self.assertEqual(query["@type"], "withBlock")
        self.assertEqual(query["id"], block.to_dict())
        self.assertEqual(query["function"]["@type"], "raw.getAccountState")
        await client.raw_get_account_state(address)
        query = client._toslib_wrapper.execute.call_args.args[0].to_dict()
        self.assertEqual(query["@type"], "raw.getAccountState")

    async def check_value(self, value):
        block = toslib_api.Tos_blockIdExt(workchain=2, shard=-(1 << 63), seqno=17,
                                        root_hash=bytes(32), file_hash=bytes(32))
        engine = Builder().store_uint(value, 64).end_cell()
        # Only wrapper/engine shape is tested here. Witness proof semantics are
        # deliberately not represented by this synthetic empty second reference.
        wrapper = (Builder().store_uint(0x57424531, 32).store_bit(1)
                   .store_ref(engine).store_ref(Builder().end_cell()).end_cell())
        response = toslib_api.Raw_fullAccountState(
            data=wrapper.to_boc(), block_id=block,
            last_transaction_id=toslib_api.Internal_transactionId(lt=1, hash=bytes(32)))
        calls = []

        class Client:
            async def raw_get_account_state(self, address, *, block_id):
                calls.append((address, block_id))
                return response

        result = await module.counter_state(Client(), block)
        self.assertIs(result, response)
        self.assertEqual(len(calls), 1)
        self.assertIs(calls[0][1], block)
        return result

    async def test_exact_transition_value(self):
        await self.check_value(57)

    async def test_genesis_state_cannot_masquerade_as_synced_state(self):
        with self.assertRaisesRegex(AssertionError, "one increment per confirmed block"):
            await self.check_value(40)

    async def test_off_by_one_state_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, "one increment per confirmed block"):
            await self.check_value(58)


if __name__ == "__main__":
    unittest.main()
