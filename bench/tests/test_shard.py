"""Shard-scaling bench: hop wire format, address derivation and per-shard accounting.

Run: uv run python bench/tests/test_shard.py [--build PATH]
With --build, the contract is compiled and its address derivation is checked
against the exact StateInit layout hop.fc builds on chain.
"""

import argparse
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "bench/shard"), str(ROOT / "test/tostester/src")]

import hopbench  # noqa: E402
from pytosiq_core import Builder  # noqa: E402

_parser = argparse.ArgumentParser(add_help=False)
_parser.add_argument("--build")
ARGS, _REST = _parser.parse_known_args()
CODE = Builder().store_uint(0xC0DE, 16).end_cell()


def contract_state_init(code, index: int, salt: int):
    """The StateInit exactly as hop.fc's state_init() serializes it."""
    data = Builder().store_uint(index, 32).store_uint(salt, 64).store_ref(code).end_cell()
    return (
        Builder()
        .store_uint(0, 2)
        .store_bit(1)
        .store_ref(code)
        .store_bit(1)
        .store_ref(data)
        .store_uint(0, 1)
        .end_cell()
    )


class Family(unittest.TestCase):
    def test_address_matches_contract_layout(self):
        family = hopbench.HopFamily(CODE, 0x1122334455667788, 16)
        for i in (0, 1, 15):
            self.assertEqual(
                family.address(i).hash_part, contract_state_init(CODE, i, family.salt).hash
            )

    def test_ids_and_salts_give_distinct_addresses(self):
        a = hopbench.HopFamily(CODE, 1, 64).addresses()
        b = hopbench.HopFamily(CODE, 2, 64).addresses()
        self.assertEqual(len({x.hash_part for x in a}), 64)
        self.assertFalse({x.hash_part for x in a} & {x.hash_part for x in b})

    def test_bounds(self):
        with self.assertRaises(ValueError):
            hopbench.HopFamily(CODE, 1, 1)
        with self.assertRaises(ValueError):
            hopbench.HopFamily(CODE, 1 << 64, 4)
        with self.assertRaises(ValueError):
            hopbench.HopFamily(CODE, 1, 4).data(1 << 32)


class Bodies(unittest.TestCase):
    def test_start_body_layout(self):
        body = hopbench.start_body(255, 7, 3, 65535, 2, 1_800_000_000, 4096)
        s = body.begin_parse()
        self.assertEqual(s.load_uint(32), hopbench.OP_START)
        self.assertEqual(
            [s.load_uint(n) for n in (8, 32, 8, 16, 8, 32, 32)],
            [255, 7, 3, 65535, 2, 1_800_000_000, 4096],
        )
        self.assertEqual(s.load_uint(8), 0)  # flags
        self.assertIsNone(s.load_maybe_ref())  # no payload
        self.assertEqual(len(body.bits), 32 + 8 + 32 + 8 + 16 + 8 + 32 + 32 + 8 + 1)
        self.assertEqual(len(body.refs), 0)

    def test_start_body_with_flags_and_payload(self):
        payload = hopbench.payload_cell(300)
        flags = hopbench.FLAG_WITH_INIT | hopbench.FLAG_VERIFY_SENDER
        s = hopbench.start_body(1, 2, 0, 0, 0, 3, 4, flags, payload).begin_parse()
        s.skip_bits(32 + 8 + 32 + 8 + 16 + 8 + 32 + 32)
        self.assertEqual(s.load_uint(8), 3)
        self.assertEqual(s.load_maybe_ref().hash, payload.hash)

    def test_payload_cells(self):
        self.assertIsNone(hopbench.payload_cell(0))
        for size in (1, 127, 128, 300, hopbench.MAX_PAYLOAD):
            cell, total = hopbench.payload_cell(size), 0
            while cell is not None:
                self.assertLessEqual(len(cell.bits), 8 * hopbench.PAYLOAD_CELL_BYTES)
                total += len(cell.bits) // 8
                cell = cell.refs[0] if cell.refs else None
            self.assertEqual(total, size)
        for bad in (-1, hopbench.MAX_PAYLOAD + 1):
            with self.assertRaises(ValueError):
                hopbench.payload_cell(bad)

    def test_deploy_body_layout(self):
        s = hopbench.deploy_body(0, 4096).begin_parse()
        self.assertEqual(
            [s.load_uint(32), s.load_uint(32), s.load_uint(32)], [hopbench.OP_DEPLOY, 0, 4096]
        )

    def test_rejects_out_of_range(self):
        for bad in (
            lambda: hopbench.start_body(0, 1, 0, 0, 0, 1, 2),
            lambda: hopbench.start_body(256, 1, 0, 0, 0, 1, 2),
            lambda: hopbench.start_body(1, 1, 256, 0, 0, 1, 2),
            lambda: hopbench.start_body(1, 1, 0, 65536, 0, 1, 2),
            lambda: hopbench.start_body(1, 1, 0, 0, 61, 1, 2),
            lambda: hopbench.start_body(1, 1, 0, 0, 0, 1 << 32, 2),
            lambda: hopbench.start_body(1, 1 << 32, 0, 0, 0, 1, 2),
            lambda: hopbench.deploy_body(5, 5),
            lambda: hopbench.start_body(1, 1, 0, 0, 0, 1, 2, flags=4),
        ):
            with self.assertRaises(ValueError):
                bad()

    def test_local_scaling(self):
        self.assertEqual(hopbench.local_scaled(0.0), 0)
        self.assertEqual(hopbench.local_scaled(1.0), 65535)
        self.assertEqual(hopbench.local_scaled(0.5), 32768)
        with self.assertRaises(ValueError):
            hopbench.local_scaled(1.5)


class Shards(unittest.TestCase):
    def test_shard_of(self):
        full = bytes([0xFF] * 32)
        zero = bytes(32)
        self.assertEqual(hopbench.shard_of(zero, 0), -(1 << 63))
        self.assertEqual(hopbench.shard_label(hopbench.shard_of(zero, 1)), "4000000000000000")
        self.assertEqual(hopbench.shard_label(hopbench.shard_of(full, 1)), "c000000000000000")
        self.assertEqual(hopbench.shard_label(hopbench.shard_of(full, 2)), "e000000000000000")
        self.assertEqual(
            hopbench.shard_label(hopbench.shard_of(bytes([0x40]) + bytes(31), 2)),
            "6000000000000000",
        )

    def test_depth_roundtrip(self):
        for depth in range(0, 5):
            for top in (0x00, 0x5A, 0xFF):
                shard = hopbench.shard_of(bytes([top]) + bytes(31), depth)
                self.assertEqual(hopbench.shard_depth(shard), depth)

    def test_accounts_spread_over_every_shard(self):
        family = hopbench.HopFamily(CODE, 7, 4096)
        counts: dict[int, int] = {}
        for x in family.addresses():
            s = hopbench.shard_of(x.hash_part, 2)
            counts[s] = counts.get(s, 0) + 1
        self.assertEqual(len(counts), 4)
        self.assertTrue(all(800 < c < 1250 for c in counts.values()), counts)


def block(shard, seqno, t, txs, cross=0, cat_gas=0):
    b = hopbench.ScannedBlock(shard, seqno, t, bytes([seqno % 256]) * 32, txs)
    b.collation = hopbench.Collation(
        shard,
        seqno,
        txs,
        1000,
        10,
        1,
        {"bytes": 0, "gas": cat_gas, "lt_delta": 0, "collated_data_bytes": 0},
        0.01,
        cross,
        0,
    )
    return b


class Summary(unittest.TestCase):
    def test_per_shard_and_total(self):
        left, right = hopbench.to_signed(0x4000000000000000), hopbench.to_signed(0xC000000000000000)
        blocks = [block(left, i, 100 + i, 50, cross=5) for i in range(10)]
        blocks += [block(right, i, 100 + i, 30, cat_gas=2) for i in range(10)]
        blocks.append(block(left, 99, 99, 1000))  # before the window
        blocks.append(block(left, 98, 110, 1000))  # at the window's end
        s = hopbench.summarize(blocks, 100, 110)
        self.assertEqual(s["shard_count"], 2)
        self.assertEqual(s["transactions"], 800)
        self.assertAlmostEqual(s["tx_per_second"], 80.0)
        self.assertEqual([x["tx_per_second"] for x in s["shards"]], [50.0, 30.0])
        self.assertAlmostEqual(s["shards"][0]["block_interval_mean"], 1.0)
        self.assertEqual(s["cross_shard_messages_in"], 50)
        self.assertEqual(s["shards"][1]["full_by"], {"gas": 10})
        self.assertEqual(s["unmatched_blocks"], 0)

    def test_empty_window_is_refused(self):
        with self.assertRaises(ValueError):
            hopbench.summarize([], 5, 5)

    def test_tail_ratio(self):
        shard = hopbench.to_signed(0x8000000000000000)
        steady = [block(shard, i, i, 10) for i in range(40)]
        self.assertAlmostEqual(hopbench.tail_ratio(steady, 0, 40), 1.0)
        thinning = [block(shard, i, i, 10 if i < 30 else 0) for i in range(40)]
        self.assertAlmostEqual(hopbench.tail_ratio(thinning, 0, 40), 0.0)
        self.assertIsNone(hopbench.tail_ratio(steady, 0, 10))


class Collations(unittest.TestCase):
    def test_reads_basechain_records_and_cross_shard_imports(self):
        import base64
        import json

        own = "4611686018427387904"  # 0x4000000000000000
        other = "-4611686018427387904"  # 0xc000000000000000
        record = {
            "@type": "validatorStats.collatedBlock",
            "block_id": {
                "workchain": 0,
                "shard": own,
                "seqno": 9,
                "root_hash": base64.b64encode(b"r" * 32).decode(),
            },
            "bytes": 777,
            "cpu_work_time": 0.5,
            "block_limits": {
                "gas": 9,
                "lt_delta": 3,
                "cat_bytes": 0,
                "cat_gas": 2,
                "cat_lt_delta": 1,
            },
            "block_stats": {
                "transactions": 42,
                "new_out_msg_queue_size": "17",
                "neighbors": [
                    {"shard": {"workchain": 0, "shard": own}, "processed_msgs": 100},
                    {"shard": {"workchain": 0, "shard": other}, "processed_msgs": 8},
                    {
                        "shard": {"workchain": -1, "shard": "-9223372036854775808"},
                        "processed_msgs": 1,
                    },
                ],
            },
        }
        mc = dict(
            record,
            block_id=dict(
                record["block_id"], workchain=-1, root_hash=base64.b64encode(b"m" * 32).decode()
            ),
        )
        with tempfile.TemporaryDirectory() as d:
            node = Path(d) / "node1"
            node.mkdir()
            (node / "session-logs").write_text(
                json.dumps(record) + "\nnot json\n" + json.dumps(mc) + "\n"
            )
            got = hopbench.collations(Path(d))
        self.assertEqual(list(got), [b"r" * 32])
        c = got[b"r" * 32]
        self.assertEqual((c.transactions, c.cross_shard_in, c.queue_after, c.seqno), (42, 8, 17, 9))
        self.assertEqual(c.categories["gas"], 2)


@unittest.skipUnless(ARGS.build, "needs --build with crypto/func and crypto/fift")
class Compiled(unittest.TestCase):
    def test_compiled_code_derives_addresses(self):
        with tempfile.TemporaryDirectory() as d:
            code = hopbench.build(Path(ARGS.build), Path(d))
        family = hopbench.HopFamily(code, 99, 8)
        self.assertEqual(family.address(3).hash_part, contract_state_init(code, 3, 99).hash)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], *_REST])
