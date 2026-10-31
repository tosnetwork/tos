"""Durability/binding tests with a deliberately fake transport, NOT chain evidence."""

import base64
import dataclasses
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/bonded-relayer"))
from relay_core import (  # noqa: E402
    MAX_BODY,
    Engine,
    Evidence,
    Journal,
    Prepared,
    Refused,
    Release,
    Request,
)


def h(n):
    return f"{n:064x}"


def release():
    return Release(42, h(1), h(2), "0:" + h(3), h(4), h(5), h(6), "0:" + h(7), h(8), h(9))


def request(profile=None, n=11, **kw):
    body = f"TEST-ONLY-body-{n}".encode()
    values = dict(
        release=(profile or release()).scope,
        intent=h(n),
        body_b64=base64.b64encode(body).decode(),
        body_sha256=hashlib.sha256(body).hexdigest(),
        nullifiers=(h(n + 1), h(n + 2)),
        quote_hash=h(5),
        fee_note_body=h(6),
        fee_slot=2,
        fee_note_index=7,
        valid_until=1200,
        funding_cap=100,
    )
    values.update(kw)
    return Request(**values)


class FakeAdapter:
    """No real signature/proof/network. Isolates the journal's safety properties."""

    def __init__(self):
        self.prepares, self.writes = 0, []
        self.cost = 10
        self.raise_broadcast = False
        self.reject_preflight = False
        self.reject_recheck = False
        self.reject_prepared = False
        self.outcome = None
        self.wrong_evidence = False

    def preflight(self, profile, req):
        if self.reject_preflight:
            raise Refused("test invalid proof/fee/identity")
        return self.cost

    def prepare(self, profile, req, slot, issued, funding):
        self.prepares += 1
        return Prepared(
            f"TEST-ONLY-message:{req.identity}:{funding}".encode(),
            h(1000 + slot),
            f"TEST-ONLY-acceptance:{slot}:{issued}:{req.identity}".encode(),
        )

    def validate_prepared(self, profile, req, slot, issued, funding, prepared):
        if self.reject_prepared or not prepared.message.endswith(f":{funding}".encode()):
            raise Refused("test prepared binding/funding mismatch")

    def recheck(self, profile, req, prepared):
        if self.reject_recheck:
            raise Refused("test stale/revoked/insolvent state")

    def broadcast(self, message):
        self.writes.append(message)
        if self.raise_broadcast:
            raise TimeoutError("test ambiguous write")

    def evidence(self, profile, req, prepared):
        if self.outcome is None:
            return None
        return Evidence(
            profile.scope,
            req.identity,
            h(999) if self.wrong_evidence else prepared.message_hash,
            self.outcome,
            h(21),
            h(22),
        )


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "journal.sqlite"
        self.adapter = FakeAdapter()
        self.journal = Journal(self.path, release())
        self.addCleanup(self.journal.close)
        self.engine = Engine(self.journal, self.adapter, clock=lambda: 1000)

    def test_exactly_one_write_and_not_a_finality_claim(self):
        req = request()
        self.assertEqual(self.engine.submit(req), "broadcast")
        for _ in range(5):
            self.assertEqual(self.engine.submit(req), "broadcast")
        self.assertEqual(self.adapter.prepares, 1)
        self.assertEqual(len(self.adapter.writes), 1)
        self.assertEqual(self.engine.reconcile(req.identity), "broadcast")

    def test_unknown_write_survives_restart_without_resigning_or_resending(self):
        self.adapter.raise_broadcast = True
        req = request()
        self.assertEqual(self.engine.submit(req), "unknown")
        reopened = Journal(self.path, release())
        self.addCleanup(reopened.close)
        recovered = Engine(reopened, self.adapter, clock=lambda: 1001)
        self.assertEqual(recovered.submit(req), "unknown")
        self.assertEqual(recovered.reconcile(req.identity), "unknown")
        self.assertEqual((self.adapter.prepares, len(self.adapter.writes)), (1, 1))

    def test_conflicting_request_cannot_steal_a_reserved_nullifier(self):
        req = request()
        self.engine.submit(req)
        conflict = request(n=13, nullifiers=req.nullifiers)
        with self.assertRaises(Refused):
            self.engine.submit(conflict)
        self.assertEqual(self.adapter.prepares, 1)

    def test_invalid_preflight_never_reserves_or_signs(self):
        self.adapter.reject_preflight = True
        req = request()
        with self.assertRaises(Refused):
            self.engine.submit(req)
        self.assertIsNone(self.journal.get(req.identity))
        self.assertEqual(self.adapter.prepares, 0)

    def test_invalid_prepared_binding_never_broadcasts(self):
        self.adapter.reject_prepared = True
        req = request()
        with self.assertRaises(Refused):
            self.engine.submit(req)
        self.assertEqual(self.journal.get(req.identity)["state"], "reserved")
        self.assertFalse(self.adapter.writes)
        self.assertEqual(self.engine.submit(req), "reserved")

    def test_failed_last_moment_recheck_keeps_reservation(self):
        self.adapter.reject_recheck = True
        req = request()
        self.assertEqual(self.engine.submit(req), "unknown")
        self.assertFalse(self.adapter.writes)
        with self.assertRaises(Refused):
            self.engine.submit(request(n=13, nullifiers=req.nullifiers))

    def test_pending_and_unrelated_evidence_do_not_release_funds(self):
        req = request()
        self.engine.submit(req)
        self.assertEqual(self.engine.reconcile(req.identity), "broadcast")
        self.adapter.outcome, self.adapter.wrong_evidence = "executed", True
        with self.assertRaises(Refused):
            self.engine.reconcile(req.identity)
        self.assertEqual(self.journal.get(req.identity)["state"], "broadcast")

    def test_terminal_refusal_releases_inputs_but_never_retries_old_request(self):
        req = request()
        self.engine.submit(req)
        self.adapter.outcome = "rejected"
        self.assertEqual(self.engine.reconcile(req.identity), "rejected")
        self.assertEqual(self.engine.submit(req), "rejected")
        self.assertEqual(self.engine.submit(request(n=13, nullifiers=req.nullifiers)), "broadcast")
        self.assertEqual(len(self.adapter.writes), 2)

    def test_success_keeps_spent_nullifier_tombstone(self):
        req = request()
        self.engine.submit(req)
        self.adapter.outcome = "executed"
        self.assertEqual(self.engine.reconcile(req.identity), "executed")
        with self.assertRaises(Refused):
            self.engine.submit(request(n=13, nullifiers=req.nullifiers))

    def test_terminal_decision_cannot_be_reversed(self):
        req = request()
        self.engine.submit(req)
        self.adapter.outcome = "executed"
        self.engine.reconcile(req.identity)
        row = self.journal.get(req.identity)
        with self.assertRaises(Refused):
            self.journal.finish(
                Evidence(
                    release().scope, req.identity, row["message_hash"], "rejected", h(21), h(22)
                )
            )

    def test_expired_and_future_requests(self):
        for deadline in (1000, 999, 1301):
            with self.assertRaises(Refused):
                self.engine.submit(request(valid_until=deadline))
        self.assertFalse(self.adapter.writes)

    def test_wrong_release_and_journal_reuse(self):
        other = dataclasses.replace(release(), global_id=43)
        with self.assertRaises(Refused):
            self.engine.submit(request(profile=other))
        with self.assertRaises(Refused):
            Journal(self.path, other)

    def test_funding_cannot_exceed_request_or_queue_exposure(self):
        self.adapter.cost = 101
        with self.assertRaises(Refused):
            self.engine.submit(request())
        self.adapter.cost = 10
        self.journal.max_reserved = 15
        self.engine.submit(request())
        with self.assertRaises(Refused):
            self.engine.submit(request(n=20))
        self.assertEqual(len(self.adapter.writes), 1)

    def test_queue_cap_and_failed_reservation_do_not_consume_slot(self):
        self.journal.max_pending = 1
        self.engine.submit(request())
        with self.assertRaises(Refused):
            self.engine.submit(request(n=20))
        next_slot = self.journal.db.execute(
            "SELECT value FROM metadata WHERE key='next_slot'"
        ).fetchone()[0]
        self.assertEqual(next_slot, "2")

    def test_two_connections_cannot_claim_the_same_broadcast(self):
        req = request()
        row, _ = self.journal.reserve(req, 10, 1000)
        prepared = self.adapter.prepare(release(), req, row["slot"], row["issued"], row["funding"])
        self.journal.store_prepared(req.identity, prepared)
        other = Journal(self.path, release())
        self.addCleanup(other.close)
        self.assertTrue(other.claim_broadcast(req.identity))
        self.assertFalse(self.journal.claim_broadcast(req.identity))

    def test_prepared_crash_can_resume_only_persisted_bytes(self):
        req = request()
        row, _ = self.journal.reserve(req, 10, 1000)
        prepared = self.adapter.prepare(release(), req, row["slot"], row["issued"], row["funding"])
        self.journal.store_prepared(req.identity, prepared)
        self.assertEqual(self.engine.submit(req), "broadcast")
        self.assertEqual(self.adapter.writes, [prepared.message])
        self.assertEqual(self.adapter.prepares, 1)

    def test_tampered_persisted_request_is_refused(self):
        req = request()
        row, _ = self.journal.reserve(req, 10, 1000)
        prepared = self.adapter.prepare(release(), req, row["slot"], row["issued"], row["funding"])
        self.journal.store_prepared(req.identity, prepared)
        self.journal.db.execute(
            "UPDATE jobs SET request=? WHERE id=?", (request(n=20).wire, req.identity)
        )
        with self.assertRaises(Refused):
            self.engine.dispatch(req.identity)
        self.assertFalse(self.adapter.writes)

    def test_strict_wire_round_trip_and_duplicates(self):
        req = request()
        self.assertEqual(Request.parse(req.wire), req)
        bad = b'{"release":"' + req.release.encode() + b'",' + req.wire[1:]
        with self.assertRaises(Refused):
            Request.parse(bad)
        obj = json.loads(req.wire)
        obj["unexpected"] = 1
        with self.assertRaises(Refused):
            Request.parse(json.dumps(obj).encode())

    def test_boolean_float_negative_and_noncanonical_fields(self):
        for fields in (
            {"funding_cap": True},
            {"fee_slot": 2.0},
            {"fee_slot": -1},
            {"fee_slot": 3},
            {"fee_note_index": 1 << 64},
            {"intent": "F" * 64},
            {"intent": "f" * 64},
            {"nullifiers": (h(1), h(1))},
            {"body_sha256": h(1)},
            {"body_b64": "YQ="},
        ):
            with self.subTest(fields=fields), self.assertRaises(Refused):
                request(**fields)

    def test_resource_bounds(self):
        with self.assertRaises(Refused):
            Request.parse(b" " * (2 * MAX_BODY + 1))
        with self.assertRaises(Refused):
            Prepared(b"", h(1), b"test")
        with self.assertRaises(Refused):
            Evidence(release().scope, request().identity, h(1), "pending", h(2), h(3))

    def test_journal_refuses_symlink(self):
        target = Path(self.tmp.name) / "linked.sqlite"
        target.symlink_to(self.path)
        with self.assertRaises(Refused):
            Journal(target, release())
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
