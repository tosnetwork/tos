"""Real SQLite quote allocation, finite history and safe recovery regressions."""

import base64
import concurrent.futures
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/bonded-relayer"))
from relay_core import Engine, Journal, Refused, encode  # noqa: E402
from test_engine import FakeAdapter, release, request  # noqa: E402


class JournalLimitsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "journal.sqlite"

    def journal(self, **kwargs):
        journal = Journal(self.path, release(), **kwargs)
        self.addCleanup(journal.close)
        return journal

    @staticmethod
    def make_quote(journal, now=1000):
        allocation, index = journal.allocate_quote(now)
        terms = dict(
            release=release().scope,
            nonce=allocation,
            note_index=index,
            issued_at=now,
            valid_until=now + 300,
            slot=2,
            amount=10,
            funding_cap=100,
            descriptor=base64.b64encode(b"test-only").decode(),
        )
        # Signature plumbing is isolated here; cryptographic authentication is
        # exercised by the native adapter, not substituted by this fake signature.
        signed = encode(dict(terms=terms, signature="TEST ONLY"))
        identity = journal.publish_quote(allocation, terms, signed)
        return identity, terms

    def test_quote_allocation_survives_restart_without_key_reuse(self):
        a = self.journal()
        first = a.allocate_quote(1000)
        b = self.journal()
        second = b.allocate_quote(1000)
        self.assertEqual((first[1], second[1]), (0, 1))
        self.assertNotEqual(first[0], second[0])

    def test_two_connections_allocate_distinct_indices_concurrently(self):
        a, b = self.journal(), self.journal()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda j: j.allocate_quote(1000), [a, b] * 10))
        self.assertEqual(sorted(index for _, index in results), list(range(20)))

    def test_quote_quota_refuses_then_expires_without_reusing_counter(self):
        j = self.journal(max_quotes=1)
        j.allocate_quote(1000)
        with self.assertRaisesRegex(Refused, "quote queue quota"):
            j.allocate_quote(1000)
        _, index = j.allocate_quote(1301)
        self.assertEqual(index, 1)

    def test_quote_signature_is_persisted_exactly(self):
        j = self.journal()
        identity, terms = self.make_quote(j)
        self.assertEqual(json.loads(j.quote(identity))["terms"], terms)
        b = self.journal()
        self.assertEqual(b.quote(identity), j.quote(identity))

    def test_quote_cannot_change_index_or_republish(self):
        j = self.journal()
        identity, terms = self.make_quote(j)
        with self.assertRaisesRegex(Refused, "no unused"):
            j.publish_quote(identity, terms, b"fake")
        allocation, index = j.allocate_quote(1000)
        bad = dict(terms, nonce=allocation, note_index=index + 1)
        with self.assertRaisesRegex(Refused, "durable allocation"):
            j.publish_quote(allocation, bad, b"fake")

    def test_production_reservation_requires_one_exact_quote(self):
        j = self.journal(require_quotes=True)
        identity, terms = self.make_quote(j)
        req = request(quote_hash=identity, fee_note_index=terms["note_index"])
        engine = Engine(j, FakeAdapter(), clock=lambda: 1000)
        self.assertEqual(engine.submit(req), "broadcast")
        self.assertEqual(engine.submit(req), "broadcast")
        with self.assertRaisesRegex(Refused, "quote unavailable"):
            engine.submit(request(n=20, quote_hash=identity, fee_note_index=terms["note_index"]))

    def test_changed_quote_conditions_are_rejected_before_reservation(self):
        j = self.journal(require_quotes=True)
        identity, terms = self.make_quote(j)
        for changes in (
            {"fee_slot": 1},
            {"fee_note_index": 8},
            {"valid_until": 1301},
            {"funding_cap": 101},
        ):
            args = dict(quote_hash=identity, fee_note_index=terms["note_index"])
            args.update(changes)
            with self.assertRaisesRegex(Refused, "changed the accepted quote"):
                j.reserve(request(**args), 10, 1000)
        self.assertEqual(j.metrics()["jobs"], 0)

    def test_history_quota_keeps_terminal_tombstones(self):
        j = self.journal(max_history=1)
        a = FakeAdapter()
        engine = Engine(j, a, clock=lambda: 1000)
        req = request()
        engine.submit(req)
        a.outcome = "executed"
        engine.reconcile(req.identity)
        with self.assertRaisesRegex(Refused, "history quota"):
            engine.submit(request(n=20))
        self.assertEqual(engine.submit(req), "executed")
        self.assertEqual(len(a.writes), 1)

    def test_cancel_only_expired_never_prepared_reservations(self):
        j = self.journal()
        req = request()
        j.reserve(req, 10, 1000)
        with self.assertRaisesRegex(Refused, "not expired"):
            j.cancel_unprepared(req.identity, 1200)
        j.cancel_unprepared(req.identity, 1201)
        engine = Engine(j, FakeAdapter(), clock=lambda: 1201)
        self.assertEqual(engine.submit(req), "cancelled")
        self.assertEqual(j.get(req.identity)["slot"], 1)
        self.assertFalse(j.pending())
        self.assertEqual(j.db.execute("SELECT COUNT(*) FROM input_locks").fetchone()[0], 0)

    def test_unknown_attempt_cannot_be_cancelled_after_expiry(self):
        j = self.journal()
        a = FakeAdapter()
        a.raise_broadcast = True
        engine = Engine(j, a, clock=lambda: 1000)
        req = request()
        engine.submit(req)
        with self.assertRaisesRegex(Refused, "only an unprepared"):
            j.cancel_unprepared(req.identity, 99999)
        self.assertEqual(j.get(req.identity)["state"], "unknown")
        self.assertEqual(j.db.execute("SELECT COUNT(*) FROM input_locks").fetchone()[0], 2)

    def test_compaction_never_drops_live_jobs_or_spent_input_tombstones(self):
        j = self.journal()
        a = FakeAdapter()
        engine = Engine(j, a, clock=lambda: 1000)
        done, live = request(), request(n=20)
        engine.submit(done)
        a.outcome = "executed"
        engine.reconcile(done.identity)
        engine.submit(live)
        self.assertEqual(j.compact(1001), 0)
        self.assertEqual(j.compact(100000), 1)
        self.assertIsNone(j.get(done.identity)["message"])
        self.assertIsNotNone(j.get(live.identity)["message"])
        self.assertEqual(engine.submit(done), "executed")
        self.assertEqual(j.db.execute("SELECT COUNT(*) FROM input_locks").fetchone()[0], 4)

    def test_disk_quota_refuses_admission_but_preserves_existing_work(self):
        j = self.journal(max_pending=1, max_disk_bytes=16 * 1024 * 1024)
        j.db.execute("CREATE TABLE padding(data BLOB)")
        j.db.execute("INSERT INTO padding VALUES (zeroblob(6000000))")
        # Keep a genuine reader snapshot to pin the WAL while the writer grows it.
        other = self.journal(max_pending=1, max_disk_bytes=16 * 1024 * 1024)
        other.db.execute("BEGIN")
        other.db.execute("SELECT * FROM padding").fetchone()
        for _ in range(2):
            j.db.execute("UPDATE padding SET data=randomblob(6000000)")
        with self.assertRaisesRegex(Refused, "disk admission quota"):
            j.reserve(request(), 10, 1000)
        other.db.execute("ROLLBACK")
        j.compact(100000)
        self.assertEqual(j.reserve(request(), 10, 1000)[0]["slot"], 1)

    def test_linked_sidecar_is_never_opened(self):
        target = Path(self.tmp.name) / "target"
        target.write_text("untouched")
        target.chmod(0o600)
        Path(str(self.path) + "-wal").symlink_to(target)
        with self.assertRaisesRegex(Refused, "unsafe SQLite sidecar"):
            Journal(self.path, release())
        self.assertEqual(target.read_text(), "untouched")

    def test_counter_exhaustion_is_checked_without_reuse(self):
        j = self.journal()
        j.db.execute("UPDATE metadata SET value=? WHERE key='next_note_index'", (str(1 << 63),))
        with self.assertRaisesRegex(Refused, "out of range"):
            j.allocate_quote(1000)
        self.assertEqual(j.db.execute("SELECT COUNT(*) FROM quotes").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
