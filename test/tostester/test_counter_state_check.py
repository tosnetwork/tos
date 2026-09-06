"""Instrument checks for the real-network state assertions, not proof validation."""
import importlib.util
import asyncio
import json
from pathlib import Path
import sys
import unittest
import tempfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "test/tostester/src"))
from pytosiq_core import Builder
from tosapi import toslib_api
from toslib.client import ToslibClient

spec = importlib.util.spec_from_file_location("m1_network", REPO / "scripts/m1-real-manager-sync.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CounterStateCheck(unittest.IsolatedAsyncioTestCase):
    async def test_process_memory_requires_live_identity_and_explicit_units(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "123"
            proc.mkdir()
            stat = "123 (node with ) spaces) " + "S " + "0 " * 18 + "456 0\n"
            (proc / "stat").write_text(stat)
            status = "VmRSS:\t2048 kB\nVmHWM:\t4096 kB\n"
            (proc / "status").write_text(status)
            node = SimpleNamespace(process_id=123)
            value = module.node_memory_observation(node, root)
            self.assertEqual(value["process_start_ticks"], 456)
            self.assertEqual(value["rss_bytes"], 2 * 1024**2)
            self.assertEqual(value["kernel_reported_peak_rss_bytes"], 4 * 1024**2)
            for bad in ("", status.replace(" kB", " MB"), status.replace("4096", "0"), status + status):
                (proc / "status").write_text(bad)
                with self.assertRaisesRegex(AssertionError, "memory observation"):
                    module.node_memory_observation(node, root)
            with patch.object(Path, "read_text", side_effect=[stat, status, stat.replace("456", "457")]):
                with self.assertRaisesRegex(AssertionError, "identity changed"):
                    module.node_memory_observation(node, root)
            with self.assertRaisesRegex(AssertionError, "stopped node"):
                module.node_memory_observation(SimpleNamespace(process_id=None), root)

    async def test_streaming_requires_matching_file_and_actor_import(self):
        identity = "(2,8000000000000000,18):" + "AB" * 32 + ":" + "CD" * 32
        file_log = f"finished downloading state {identity}: 2178KB (file)\n"
        actor_log = f"import_persistent_state_streaming for {identity}, cells_persisted=32780\n"
        module.require_checkpoint_streamed(file_log + actor_log)
        for log in (file_log, actor_log, file_log.replace(" (file)", "") + actor_log,
                    file_log + actor_log.replace("CD" * 32, "EF" * 32),
                    file_log + actor_log.replace("cells_persisted=32780", "cells_persisted=0"),
                    (file_log + actor_log).replace(",18)", ",0)")):
            with self.subTest(log=log), self.assertRaisesRegex(AssertionError, "file download and actor-local"):
                module.require_checkpoint_streamed(log)

    async def test_checkpoint_requires_identity_completion_and_nonzero_snapshot(self):
        block = toslib_api.Tos_blockIdExt(workchain=-1, shard=-(1 << 63), seqno=17,
                                         root_hash=bytes([1]) * 32, file_hash=bytes([2]) * 32)
        identity = json.loads(block.to_json())
        selected = ("best handle is [ w=-1 s=9223372036854775808 seq=17 "
                    f"{identity['root_hash']} {identity['file_hash']} ]\n")
        finished = "persistent state download finished\n"
        snapshot = "finished downloading state (2,8000000000000000,15):root:file\n"
        module.require_checkpoint_acquired(selected + finished + snapshot, block)
        for log, reason in ((selected.replace("seq=17 ", "seq=0 ") + finished + snapshot, "select"),
                            (selected.replace(identity["root_hash"], identity["file_hash"]) + finished + snapshot, "select"),
                            (selected + snapshot, "finish persistent"),
                            (selected + finished + snapshot.replace(",15)", ",0)"), "non-genesis")):
            with self.subTest(reason=reason), self.assertRaisesRegex(AssertionError, reason):
                module.require_checkpoint_acquired(log, block)

    async def test_retired_member_acceptance_is_observed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            server, cold = root / "network/node3", root / "network/node6"
            server.mkdir(parents=True)
            cold.mkdir()
            fingerprint = "ab" * 32
            (server / "log").write_text(f"COUNTER_RETIRED_SIGNATURE_SENT {fingerprint}\n")
            (cold / "log").write_text(f"COUNTER_REMOTE_PROOF_REJECTED {fingerprint} unknown node\n")
            sent, accepted, rejected = module.signature_proof_results(root, "node6", "COUNTER_RETIRED_SIGNATURE_SENT")
            self.assertEqual(sent & rejected, {fingerprint.upper()})
            self.assertFalse(sent & accepted)
            (cold / "log").write_text(f"COUNTER_REMOTE_PROOF_ACCEPTED {fingerprint}\n")
            with self.assertRaisesRegex(AssertionError, "retired committee member"):
                await asyncio.wait_for(module.watch_proof_acceptance(root), 1)

    async def test_authenticated_cursor_must_reach_target(self):
        client = SimpleNamespace(sync_toslib=AsyncMock(side_effect=[
            toslib_api.Tos_blockIdExt(seqno=57), toslib_api.Tos_blockIdExt(seqno=58)]))
        result = await module.reach_authenticated(client, 58)
        self.assertEqual(result.seqno, 58)
        self.assertEqual(client.sync_toslib.await_count, 2)

    async def test_client_encodes_signature_request(self):
        client = object.__new__(ToslibClient)
        response = toslib_api.Blocks_blockSignatures_simplex().to_dict()
        client._toslib_wrapper = SimpleNamespace(execute=AsyncMock(return_value=response))
        await client.get_masterchain_block_signatures(58)
        query = client._toslib_wrapper.execute.call_args.args[0].to_dict()
        self.assertEqual(query, {"@type": "blocks.getMasterchainBlockSignatures", "seqno": 58})

    async def test_membership_signer_instrument(self):
        block = toslib_api.Tos_blockIdExt(workchain=-1, seqno=58)
        new, old, other = bytes([1]) * 32, bytes([2]) * 32, bytes([3]) * 32

        def response(keys):
            return toslib_api.Blocks_blockSignatures_simplex(id=block, signatures=[
                toslib_api.Blocks_signature(node_id_short=key, signature=bytes(64)) for key in keys])

        # Synthetic signature bytes exercise observation only, not cryptography.
        module.require_membership_signers(response([new, other]), block, new, old)
        for keys in ([other], [old, new]):
            with self.subTest(keys=keys), self.assertRaisesRegex(AssertionError, "replacement signer"):
                module.require_membership_signers(response(keys), block, new, old)
        with self.assertRaisesRegex(AssertionError, "not block-bound"):
            module.require_membership_signers(response([new]), toslib_api.Tos_blockIdExt(seqno=59), new, old)
        with self.assertRaisesRegex(AssertionError, "list shape"):
            module.require_membership_signers(response([new, new]), block, new, old)

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
            sent, _, rejected = module.signature_proof_results(root, "node6")
            self.assertFalse(sent & rejected)
            observer = root / "network/node6"
            observer.mkdir()
            (observer / "log").write_text(f"COUNTER_REMOTE_PROOF_REJECTED {bad}\n")
            sent, _, rejected = module.signature_proof_results(root, "node6")
            self.assertEqual(sent & rejected, {bad.upper()})
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

    async def check_value(self, value, payload=None, expected_payload=None):
        block = toslib_api.Tos_blockIdExt(workchain=2, shard=-(1 << 63), seqno=17,
                                        root_hash=bytes(32), file_hash=bytes(32))
        builder = Builder().store_uint(value, 64)
        if payload is not None:
            builder.store_ref(payload)
        engine = builder.end_cell()
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

        result = await module.counter_state(Client(), block, expected_payload)
        self.assertIs(result, response)
        self.assertEqual(len(calls), 1)
        self.assertIs(calls[0][1], block)
        return result

    async def test_exact_transition_value(self):
        await self.check_value(57)

    async def test_payload_content_is_checked_independently_of_counter(self):
        payload = module.counter_payload_tree()
        pending = [(payload, 14)]
        cells, leaves = set(), []
        while pending:
            cell, depth = pending.pop()
            self.assertNotIn(cell.hash, cells)
            cells.add(cell.hash)
            part = cell.begin_parse()
            if depth:
                self.assertEqual(part.remaining_bits, 0)
                self.assertEqual(part.remaining_refs, 2)
                left, right = part.load_ref(), part.load_ref()
                pending.extend(((right, depth - 1), (left, depth - 1)))
            else:
                self.assertEqual(part.remaining_bits, 960)
                self.assertEqual(part.remaining_refs, 0)
                leaves.append(part.load_uint(64))
                self.assertEqual(part.load_bytes(112), bytes(112))
        self.assertEqual(len(cells), 32767)
        self.assertEqual(leaves, list(range(16384)))
        await self.check_value(57, payload, payload)
        wrong = Builder().store_uint(0, 64).end_cell()
        with self.assertRaisesRegex(AssertionError, "payload content changed"):
            await self.check_value(57, wrong, payload)
        with self.assertRaisesRegex(AssertionError, "invalid Counter engine state"):
            await self.check_value(57, None, payload)

    async def test_genesis_state_cannot_masquerade_as_synced_state(self):
        with self.assertRaisesRegex(AssertionError, "one increment per confirmed block"):
            await self.check_value(40)

    async def test_off_by_one_state_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, "one increment per confirmed block"):
            await self.check_value(58)


if __name__ == "__main__":
    unittest.main()
