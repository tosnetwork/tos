"""Real SQLite quote allocation, finite history and safe recovery regressions."""

import base64
import concurrent.futures
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/bonded-relayer"))
from relay_core import (  # noqa: E402
    MAX_ACCEPTANCE,
    MAX_BODY,
    MAX_PREPARED,
    MAX_QUOTE,
    Engine,
    Evidence,
    Journal,
    Prepared,
    Refused,
    encode,
)
from test_engine import FakeAdapter, h, release, request  # noqa: E402


class MaximumPreparedAdapter(FakeAdapter):
    def prepare(self, profile, req, slot, issued, funding):
        self.prepares += 1
        suffix = f":{funding}".encode()
        return Prepared(
            b"M" * (MAX_PREPARED - len(suffix)) + suffix,
            h(1000 + slot),
            b"A" * MAX_ACCEPTANCE,
        )


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
        # Cryptographic authentication remains a production-adapter requirement;
        # this journal test uses a fake signature.
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
        with self.assertRaisesRegex(Refused, "history quota"):
            j.allocate_quote(1000)
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

    @staticmethod
    def maximum_request(n=100):
        body = b"B" * MAX_BODY
        return request(
            n=n,
            body_b64=base64.b64encode(body).decode(),
            body_sha256=hashlib.sha256(body).hexdigest(),
        )

    def test_sqlite_page_ceiling_refuses_before_signing(self):
        j = self.journal(max_pending=1, max_disk_bytes=16 * 1024 * 1024)
        j.db.execute("PRAGMA max_page_count=256")
        a = MaximumPreparedAdapter()
        engine = Engine(j, a, clock=lambda: 1000)
        try:
            engine.submit(self.maximum_request())
        except Exception as exc:
            self.assertIsInstance(exc, Refused)
            self.assertIn("SQLite main database admission quota", str(exc))
        else:
            self.fail("admitted a job without main-database completion headroom")
        self.assertEqual((a.prepares, len(a.writes)), (0, 0))
        self.assertEqual(j.metrics()["jobs"], 0)
        self.assertEqual(j.db.execute("SELECT COUNT(*) FROM input_locks").fetchone()[0], 0)
        self.assertEqual(
            j.db.execute("SELECT value FROM metadata WHERE key='next_slot'").fetchone()[0], "1"
        )

    def test_storage_pressure_refuses_new_work_before_signing(self):
        j = self.journal(max_pending=1, max_disk_bytes=16 * 1024 * 1024)
        a = MaximumPreparedAdapter()
        a.outcome = "executed"
        engine = Engine(j, a, clock=lambda: 1000)
        completed = 0
        for n in range(100, 160, 3):
            req = self.maximum_request(n)
            before = a.prepares
            try:
                engine.submit(req)
            except Exception as exc:
                self.assertIsInstance(exc, Refused)
                self.assertIn("admission quota", str(exc))
                self.assertEqual(a.prepares, before)
                self.assertIsNone(j.get(req.identity))
                break
            self.assertEqual(engine.reconcile(req.identity), "executed")
            completed += 1
            # No receipt is old enough to remove; just checkpoint committed pages.
            self.assertEqual(j.compact(1000), 0)
        else:
            self.fail("finite storage did not stop admission")
        self.assertGreater(completed, 0)
        self.assertEqual(len(a.writes), completed)
        self.assertFalse(j.pending())
        self.assertEqual(j.metrics()["states"], {"executed": completed})

    def test_freelist_reuse_preserves_admitted_completion(self):
        j = self.journal(max_pending=1, max_disk_bytes=16 * 1024 * 1024)
        j.db.execute("CREATE TABLE padding(data BLOB)")
        j.db.execute("INSERT INTO padding VALUES (zeroblob(7000000))")
        j.db.execute("DROP TABLE padding")
        j.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.assertGreater(j.db.execute("PRAGMA freelist_count").fetchone()[0], 1000)
        a = MaximumPreparedAdapter()
        a.outcome = "executed"
        engine = Engine(j, a, clock=lambda: 1000)
        req = self.maximum_request()
        self.assertEqual(engine.submit(req), "broadcast")
        self.assertEqual(engine.reconcile(req.identity), "executed")
        self.assertEqual((a.prepares, len(a.writes)), (1, 1))

    def test_default_storage_budget_accepts_maximum_job(self):
        j = self.journal()
        a = MaximumPreparedAdapter()
        a.outcome = "executed"
        engine = Engine(j, a, clock=lambda: 1000)
        req = self.maximum_request()
        self.assertEqual(engine.submit(req), "broadcast")
        self.assertEqual(engine.reconcile(req.identity), "executed")

    def test_allocated_quotes_and_job_can_finish_with_pinned_wal(self):
        j = self.journal(max_pending=1, max_quotes=256, max_disk_bytes=16 * 1024 * 1024)
        req = self.maximum_request()
        row, _ = j.reserve(req, 10, 1000)
        reader = self.journal(max_pending=1, max_quotes=256, max_disk_bytes=16 * 1024 * 1024)
        reader.db.execute("BEGIN")
        reader.db.execute("SELECT * FROM jobs").fetchone()
        allocated = []
        try:
            for _ in range(257):
                try:
                    allocated.append(j.allocate_quote(1000))
                except Refused:
                    break
            else:
                self.fail("quote admission was not bounded")
            self.assertTrue(allocated)
            for allocation, index in allocated:
                terms = dict(
                    release=release().scope,
                    nonce=allocation,
                    note_index=index,
                    issued_at=1000,
                    valid_until=1300,
                    slot=2,
                    amount=10,
                    funding_cap=100,
                    padding="",
                )
                terms["padding"] = "x" * (MAX_QUOTE - len(encode(terms)))
                self.assertEqual(len(encode(terms)), MAX_QUOTE)
                try:
                    identity = j.publish_quote(allocation, terms, b"Q" * MAX_QUOTE)
                except Exception as exc:
                    self.fail(f"admitted quote could not publish its bounded bytes: {exc}")
                self.assertEqual(j.quote(identity), b"Q" * MAX_QUOTE)
            a = MaximumPreparedAdapter()
            prepared = a.prepare(release(), req, row["slot"], row["issued"], row["funding"])
            j.store_prepared(req.identity, prepared)
            engine = Engine(j, a, clock=lambda: 1000)
            self.assertEqual(engine.dispatch(req.identity), "broadcast")
            a.outcome = "executed"
            self.assertEqual(engine.reconcile(req.identity), "executed")
            self.assertLess(
                sum(p.stat().st_size for p in Path(self.tmp.name).iterdir()), j.max_disk_bytes
            )
        finally:
            reader.db.execute("ROLLBACK")

    def test_mutated_evidence_cannot_exceed_reserved_storage(self):
        j = self.journal()
        a = FakeAdapter()
        engine = Engine(j, a, clock=lambda: 1000)
        req = request()
        engine.submit(req)
        credit = {"padding": "small"}
        evidence = Evidence(
            release().scope,
            req.identity,
            j.get(req.identity)["message_hash"],
            "executed",
            h(21),
            h(22),
            credit,
        )
        credit["padding"] = "x" * (16 * 1024)
        with self.assertRaisesRegex(Refused, "terminal evidence exceeds storage bound"):
            j.finish(evidence)
        self.assertEqual(j.get(req.identity)["state"], "broadcast")
        a.outcome = "executed"
        self.assertEqual(engine.reconcile(req.identity), "executed")

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
