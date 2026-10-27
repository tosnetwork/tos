"""Real deep BOCs and exact bounded-decoder failure controls."""

import hashlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-extensions"))
from cells import Cell, LibraryReference
from root_cells import crc32c, from_boc, prime


def chain(edges):
    result = Cell().uint(3, 8)
    for _ in range(edges):
        result = Cell().uint(2, 8).ref(result)
    return result


def wire(records, *, count=None, root=0):
    count = len(records) if count is None else count
    w = max(1, (count.bit_length() + 7) // 8)
    payload = b"".join(
        bytes([len(refs), 2, value]) + b"".join(r.to_bytes(w, "big") for r in refs)
        for value, refs in records
    )
    ow = max(1, (len(payload).bit_length() + 7) // 8)
    return (
        bytes.fromhex("b5ee9c72")
        + bytes([w, ow])
        + count.to_bytes(w, "big")
        + (1).to_bytes(w, "big")
        + bytes(w)
        + len(payload).to_bytes(ow, "big")
        + root.to_bytes(w, "big")
        + payload
    )


class RootCellsTests(unittest.TestCase):
    def test_empty_and_shallow_hashes_are_unchanged(self):
        self.assertEqual(
            from_boc(Cell().boc()).hash.hex(),
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
        )
        original = Cell().uint(3, 2).ref(Cell().uint(17, 8))
        expected = original.hash
        original.__dict__.update(hash=b"wrong", depth=700)
        original.refs[0].__dict__.update(hash=b"wrong", depth=700)
        self.assertEqual(prime(original).hash, expected)
        self.assertEqual(original.depth, 1)

    def test_real_400_edge_boc_under_default_recursion_limit(self):
        self.assertEqual(sys.getrecursionlimit(), 1000)
        original = chain(400)
        encoded = original.boc()
        result = from_boc(encoded)
        self.assertEqual(result.depth, 400)
        self.assertEqual(result.boc(), encoded)
        # Independent bottom-up ordinary-cell formula, without cached properties.
        value = hashlib.sha256(bytes([0, 2, 3])).digest()
        for depth in range(400):
            value = hashlib.sha256(bytes([1, 2, 2]) + depth.to_bytes(2, "big") + value).digest()
        self.assertEqual(result.hash, value)

    def test_exact_edge_depth_limit(self):
        self.assertEqual(prime(chain(1024)).depth, 1024)
        self.assertEqual(
            from_boc(wire([(0, [i + 1]) for i in range(1024)] + [(0, [])])).depth, 1024
        )
        with self.assertRaisesRegex(AssertionError, "root edge-depth limit"):
            from_boc(wire([(0, [i + 1]) for i in range(1025)] + [(0, [])]))
        with self.assertRaisesRegex(AssertionError, "root edge-depth limit"):
            prime(chain(1025))

    def test_shared_child_reached_later_by_a_deeper_path(self):
        shared = chain(3)
        deeper = Cell().ref(Cell().ref(shared))
        root = Cell().ref(shared).ref(deeper)
        with self.assertRaisesRegex(AssertionError, "root edge-depth limit"):
            prime(root, max_depth=5)
        self.assertEqual(prime(root, max_depth=6).depth, 6)

    def test_cycle(self):
        root = Cell()
        root.ref(root)
        with self.assertRaisesRegex(AssertionError, "cyclic root graph"):
            prime(root)

    def test_exact_visit_and_pending_bounds(self):
        leaf = Cell()
        root = Cell().ref(Cell(refs=[leaf] * 4)).ref(Cell(refs=[leaf] * 4))
        self.assertEqual(prime(root, max_work=11).depth, 2)
        with self.assertRaisesRegex(AssertionError, "root visit-work limit"):
            prime(root, max_work=10)
        with self.assertRaisesRegex(AssertionError, "root pending-work limit"):
            prime(Cell(refs=[Cell()] * 4), max_work=4)

    def test_declared_count_rejected_before_cell_allocation(self):
        valid = wire([(0, [1]), (0, [2]), (0, [])])
        with patch(
            "root_cells.Cell", side_effect=RuntimeError("allocated before admission")
        ) as allocate:
            with self.assertRaisesRegex(AssertionError, "root BOC declared-cell limit"):
                from_boc(valid, max_work=2)
            allocate.assert_not_called()
        data = wire([(0, [])], count=2_000_001)
        with self.assertRaisesRegex(AssertionError, "root BOC declared-cell limit"):
            from_boc(data)
        with self.assertRaisesRegex(AssertionError, "root BOC impossible cell count"):
            from_boc(wire([(0, [])], count=100))

    def test_truncation_and_invalid_references(self):
        good = wire([(1, [1]), (2, [])])
        self.assertEqual(from_boc(good).depth, 1)
        for value in [good[:-1], good + b"x"]:
            with self.assertRaisesRegex(AssertionError, "root BOC size/truncation mismatch"):
                from_boc(value)
        for records in [[(0, [0])], [(0, [9])], [(0, [1]), (0, [0])]]:
            with self.assertRaisesRegex(AssertionError, "invalid root BOC reference"):
                from_boc(wire(records))

    def test_library_representation_preserved(self):
        value = LibraryReference(123).boc()
        with self.assertRaisesRegex(AssertionError, "unsupported root exotic cell"):
            from_boc(value)
        self.assertEqual(from_boc(value, allow_library=True).hash, LibraryReference(123).hash)

    def test_index_and_crc(self):
        # Two 3/4-byte cells, with cumulative end offsets as native serializes.
        plain = wire([(1, [1]), (2, [])])
        indexed = plain[:4] + bytes([0xC1]) + plain[5:11] + bytes([4, 7]) + plain[11:]
        indexed += crc32c(indexed)
        self.assertEqual(crc32c(b"123456789"), bytes.fromhex("839206e3"))
        self.assertEqual(from_boc(indexed).hash, from_boc(plain).hash)
        with self.assertRaisesRegex(AssertionError, "root BOC CRC32C mismatch"):
            from_boc(indexed[:-1] + bytes([indexed[-1] ^ 1]))
        invalid = plain[:4] + bytes([0x81]) + plain[5:11] + bytes([3, 7]) + plain[11:]
        with self.assertRaisesRegex(AssertionError, "invalid root BOC cell index"):
            from_boc(invalid)


if __name__ == "__main__":
    unittest.main()
