"""Real process/SQLite boundaries; fake native replies are NOT chain evidence."""

import dataclasses
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/bonded-relayer"))
from native_adapter import CAPABILITIES, NativeAdapter, b64, unb64  # noqa: E402
from native_process import MAX_INPUT, NativeRPC, PinnedProgram, Unavailable  # noqa: E402
from relay_core import Engine, Journal, Prepared, Refused, Release, Request, encode  # noqa: E402

# This executable only tests process I/O, ceilings and cleanup, never the chain.
HELPER = r"""
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static char data[3 * 1024 * 1024];
static void output(int fd, const char *bytes, size_t length) {
  while (length) {
    ssize_t sent = write(fd, bytes, length);
    if (sent <= 0) _exit(3);
    bytes += sent; length -= (size_t)sent;
  }
}
int main(void) {
  size_t used = 0;
  for (;;) {
    ssize_t count = read(0, data + used, sizeof(data) - used - 1);
    if (count < 0) return 4;
    if (count == 0) break;
    used += (size_t)count;
    if (used == sizeof(data) - 1) return 5;
  }
  if (!strcmp(data, "fail")) { output(2, "SECRET-NOT-FOR-HTTP", 19); return 7; }
  if (!strcmp(data, "flood-out") || !strcmp(data, "flood-err")) {
    int fd = data[6] == 'o' ? 1 : 2;
    memset(data, 'x', sizeof(data)); output(fd, data, sizeof(data)); return 0;
  }
  if (!strcmp(data, "hang") || !strcmp(data, "orphan")) {
    int orphan = !strcmp(data, "orphan");
    pid_t child = fork();
    if (child < 0) return 6;
    if (child == 0) {
      if (orphan) { close(0); close(1); close(2); }
      sleep(30); return 0;
    }
    FILE *file = fopen("owned-child.pid", "w");
    if (!file) return 8;
    fprintf(file, "%ld", (long)child); fclose(file);
    if (!orphan) sleep(30);
    output(1, "ok", 2); return 0;
  }
  output(1, data, used); return 0;
}
"""


def h(n):
    return f"{n:064x}"


def release():
    return Release(
        42,
        h(1),
        h(2),
        "0:" + h(3),
        h(4),
        h(5),
        hashlib.sha256(b"k" * 1312).hexdigest(),
        "0:" + h(7),
        h(8),
        h(9),
    )


class ProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.root.cleanup)
        root = Path(cls.root.name)
        source, cls.binary = root / "helper.c", root / "native"
        source.write_text(HELPER)
        compiler = shutil.which("cc")
        if compiler is None:
            raise RuntimeError("native boundary tests require a C compiler; not a skip")
        subprocess.run(
            [
                compiler,
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(source),
                "-o",
                str(cls.binary),
            ],
            check=True,
            timeout=30,
        )
        cls.sha = hashlib.sha256(cls.binary.read_bytes()).hexdigest()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.program = PinnedProgram(self.binary, self.sha, self.work, timeout=1)
        self.addCleanup(self.program.close)

    def test_real_native_roundtrip_and_sealed_snapshot(self):
        self.assertEqual(self.program.exchange("preflight", b"public-test"), b"public-test")
        with self.assertRaises(PermissionError):
            os.write(self.program.fd, b"replacement")

    def test_path_replacement_and_in_place_writes_do_not_replace_snapshot(self):
        candidate = self.work / "candidate"
        shutil.copyfile(self.binary, candidate)
        candidate.chmod(0o700)
        pinned = PinnedProgram(candidate, self.sha, self.work)
        self.addCleanup(pinned.close)
        candidate.write_bytes(b"corrupted in-place")
        self.assertEqual(pinned.exchange("capabilities", b"old-bytes"), b"old-bytes")
        candidate.unlink()
        candidate.write_text("#!/bin/sh\necho changed\n")
        candidate.chmod(0o700)
        self.assertEqual(pinned.exchange("capabilities", b"still-pinned"), b"still-pinned")

    def test_close_cannot_recycle_an_inflight_executable_descriptor(self):
        original = self.program._exchange

        def close_before_exec(operation, wire, executable):
            self.program.close()
            replacement = os.open("/bin/false", os.O_RDONLY)
            try:
                return original(operation, wire, executable)
            finally:
                os.close(replacement)

        with patch.object(self.program, "_exchange", side_effect=close_before_exec):
            self.assertEqual(self.program.exchange("preflight", b"immutable"), b"immutable")
        with self.assertRaisesRegex(Unavailable, "closed"):
            self.program.exchange("preflight", b"closed")

    def test_digest_permissions_symlinks_and_scripts_refuse(self):
        with self.assertRaisesRegex(Refused, "digest mismatch"):
            PinnedProgram(self.binary, h(23), self.work)
        linked = self.work / "linked"
        linked.symlink_to(self.binary)
        with self.assertRaisesRegex(Refused, "canonical"):
            PinnedProgram(linked, self.sha, self.work)
        writable = self.work / "writable"
        shutil.copyfile(self.binary, writable)
        writable.chmod(0o777)
        with self.assertRaisesRegex(Refused, "unsafe native"):
            PinnedProgram(writable, self.sha, self.work)
        writable.write_text("#!/bin/sh\necho no\n")
        writable.chmod(0o700)
        with self.assertRaisesRegex(Refused, "ELF"):
            PinnedProgram(writable, hashlib.sha256(writable.read_bytes()).hexdigest(), self.work)

    def test_input_operations_and_closed_program_refuse_before_exec(self):
        with self.assertRaisesRegex(Refused, "input outside"):
            self.program.exchange("prepare", b"x" * (MAX_INPUT + 1))
        with self.assertRaisesRegex(Refused, "unknown native"):
            self.program.exchange("prepare; echo no", b"x")
        self.program.close()
        with self.assertRaisesRegex(Unavailable, "closed"):
            self.program.exchange("prepare", b"x")

    def test_stdout_and_stderr_bounds(self):
        for wire in (b"flood-out", b"flood-err"):
            with self.subTest(wire=wire), self.assertRaisesRegex(Unavailable, "output outside"):
                self.program.exchange("evidence", wire)

    def _child_is_dead(self):
        pid = int((self.work / "owned-child.pid").read_text())
        for _ in range(100):
            try:
                state = Path(f"/proc/{pid}/stat").read_text().split(")", 1)[1].split()[0]
                if state == "Z":
                    return
            except FileNotFoundError:
                return
            time.sleep(0.01)
        self.fail("owned child survived process-group cleanup")

    def test_deadline_kills_owned_process_group(self):
        start = time.monotonic()
        with self.assertRaisesRegex(Unavailable, "deadline"):
            self.program.exchange("evidence", b"hang")
        self.assertLess(time.monotonic() - start, 4)
        self._child_is_dead()

    def test_success_also_terminates_process_group(self):
        self.assertEqual(self.program.exchange("evidence", b"orphan"), b"ok")
        self._child_is_dead()

    def test_exit_status_not_stderr_controls_success(self):
        with self.assertRaisesRegex(Unavailable, "operation failed") as caught:
            self.program.exchange("broadcast", b"fail")
        self.assertNotIn("SECRET", str(caught.exception))

    def test_concurrency_is_bounded(self):
        self.program._slots.acquire()
        self.program._slots.acquire()
        try:
            with self.assertRaisesRegex(Unavailable, "concurrency"):
                self.program.exchange("preflight", b"x")
        finally:
            self.program._slots.release()
            self.program._slots.release()


class ReplyFixture:
    """A protocol-only fake, not a native verifier."""

    def __init__(self):
        self.mutate = lambda value: value
        self.raw = None

    def exchange(self, operation, wire):
        reply = {
            "schema": "tos.br1.native.reply.v1",
            "request_sha256": hashlib.sha256(wire).hexdigest(),
            "status": "ok",
            "result": {"fixture": operation},
        }
        return self.raw if self.raw is not None else encode(self.mutate(reply))


class ProtocolTests(unittest.TestCase):
    def test_exact_invocation_bound_reply(self):
        rpc = NativeRPC(ReplyFixture())
        self.assertEqual(rpc.call("evidence", {"id": 1}), {"fixture": "evidence"})

    def test_unrelated_and_schema_drift_replies_refuse(self):
        fixture = ReplyFixture()
        for key, value in (
            ("schema", "other"),
            ("request_sha256", h(7)),
            ("extra", True),
            ("status", "maybe"),
            ("result", []),
        ):
            with self.subTest(key=key):
                fixture.mutate = lambda reply: {**reply, key: value}
                with self.assertRaises(Unavailable):
                    NativeRPC(fixture).call("evidence", {})

    def test_duplicate_json_and_nonfinite_members_refuse(self):
        fixture = ReplyFixture()
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b"[]"):
            fixture.raw = raw
            with self.subTest(raw=raw), self.assertRaises(Refused):
                NativeRPC(fixture).call("evidence", {})

    def test_canonical_binary_fields(self):
        self.assertEqual(unb64(b64(b"abc"), 3, exact=3), b"abc")
        for text in ("YWJj=", "", "a!", b"YWJj"):
            with self.subTest(text=text), self.assertRaises(Refused):
                unb64(text, 3)


class BackendFixture:
    """Trust-boundary fake: all chain, signing and proof results are fabricated."""

    def __init__(self, profile):
        self.release = profile
        self.operations = []
        self.mutate = lambda operation, value: value
        self.final = None
        self.broadcast_error = False

    def call(self, operation, payload):
        self.operations.append(operation)
        req = payload.get("request")
        identity = Request.parse(encode(req)).identity if req else None
        prepared = payload.get("prepared")
        checkpoint = {"seqno": 10, "root_hash": h(21), "file_hash": h(22), "utime": 1000}
        if operation == "capabilities":
            value = {
                "scope": self.release.scope,
                "protocol": "tos.br1.native.v1",
                "features": sorted(CAPABILITIES),
            }
        elif operation == "verify_quote":
            value = {
                "terms_sha256": hashlib.sha256(encode(payload["envelope"]["terms"])).hexdigest(),
                "worker_key_hash": self.release.worker_key_hash,
            }
        elif operation == "descriptor":
            data = bytearray(2573)
            data[:5] = b"SHD1\x01"
            data[37:45] = payload["note_index"].to_bytes(8, "big")
            value = {
                "scope": self.release.scope,
                "note_index": payload["note_index"],
                "descriptor_b64": b64(bytes(data)),
            }
        elif operation == "sign_quote":
            value = {"public_key_b64": b64(b"k" * 1312), "signature_b64": b64(b"s" * 2420)}
        elif operation == "preflight":
            value = {
                "scope": self.release.scope,
                "request": identity,
                "body_sha256": req["body_sha256"],
                "funding": 10,
                "checkpoint": checkpoint,
            }
        elif operation == "prepare":
            value = {
                "message_b64": b64(b"TEST-ONLY-message"),
                "message_hash": h(30),
                "acceptance_b64": b64(b"TEST-ONLY-acceptance"),
            }
        elif operation == "validate_prepared":
            value = {
                "scope": self.release.scope,
                "request": identity,
                "slot": payload["slot"],
                "issued_at": payload["issued_at"],
                "funding": payload["funding"],
                "message_hash": prepared["message_hash"],
                "message_sha256": hashlib.sha256(
                    unb64(prepared["message_b64"], MAX_INPUT)
                ).hexdigest(),
                "acceptance_sha256": hashlib.sha256(
                    unb64(prepared["acceptance_b64"], MAX_INPUT)
                ).hexdigest(),
            }
        elif operation == "recheck":
            value = {
                "scope": self.release.scope,
                "request": identity,
                "message_hash": prepared["message_hash"],
                "checkpoint": checkpoint,
                "permit": h(31),
            }
        elif operation == "broadcast":
            if self.broadcast_error:
                raise Unavailable("fixture ambiguous write")
            value = {
                "submitted_sha256": hashlib.sha256(
                    unb64(payload["message_b64"], MAX_INPUT)
                ).hexdigest()
            }
        elif operation == "evidence":
            value = self.final
        else:
            raise AssertionError(f"unexpected fixture operation {operation}")
        return self.mutate(operation, value)


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.profile = release()
        self.journal = Journal(
            Path(self.tmp.name) / "jobs.sqlite", self.profile, require_quotes=True
        )
        self.addCleanup(self.journal.close)
        self.backend = BackendFixture(self.profile)
        self.adapter = NativeAdapter(self.journal, self.backend, clock=lambda: 1000)
        allocation, index = self.journal.allocate_quote(1000, 100)
        self.terms = {
            "schema": "tos.br1.quote.terms.v1",
            "descriptor_b64": self.adapter.descriptor(index),
            "status_hash": h(41),
            "success": "pool_execution",
            "release": self.profile.scope,
            "nonce": allocation,
            "note_index": index,
            "issued_at": 1000,
            "valid_until": 1100,
            "slot": 2,
            "amount": 7,
            "funding_cap": 100,
        }
        signed = self.adapter.sign_quote(self.terms)
        quote = self.journal.publish_quote(allocation, self.terms, signed)
        body = b"TEST-ONLY-body"
        self.request = Request(
            self.profile.scope,
            h(10),
            b64(body),
            hashlib.sha256(body).hexdigest(),
            (h(11), h(12)),
            quote,
            h(13),
            2,
            index,
            1100,
            100,
        )
        self.prepared = Prepared(b"TEST-ONLY-message", h(30), b"TEST-ONLY-acceptance")
        self.engine = Engine(self.journal, self.adapter, clock=lambda: 1000)

    def test_real_journal_uses_one_write_and_unknown_is_not_finality(self):
        self.assertEqual(self.engine.submit(self.request), "broadcast")
        for _ in range(3):
            self.assertEqual(self.engine.submit(self.request), "broadcast")
            self.assertEqual(self.engine.reconcile(self.request.identity), "broadcast")
        self.assertEqual(self.backend.operations.count("prepare"), 1)
        self.assertEqual(self.backend.operations.count("broadcast"), 1)

    def test_missing_native_capabilities_refuse(self):
        self.backend.mutate = lambda op, value: (
            {**value, "features": []} if op == "capabilities" else value
        )
        with self.assertRaisesRegex(Unavailable, "lacks required"):
            NativeAdapter(self.journal, self.backend)

    def test_wrong_identity_stale_state_and_excess_funding_never_sign(self):
        for field, changed in (
            ("request", h(23)),
            ("scope", h(23)),
            ("body_sha256", h(23)),
            ("funding", 101),
            ("funding", True),
            ("checkpoint", {"seqno": 9, "root_hash": h(21), "file_hash": h(22), "utime": 500}),
        ):
            self.backend.mutate = lambda op, value: (
                {**value, field: changed} if op == "preflight" else value
            )
            with self.subTest(field=field), self.assertRaises((Refused, Unavailable)):
                self.engine.submit(self.request)
        self.assertEqual(self.backend.operations.count("prepare"), 0)
        self.assertEqual(self.journal.pending(), [])

    def test_prepared_binding_checks_every_field(self):
        for field in (
            "scope",
            "request",
            "slot",
            "issued_at",
            "funding",
            "message_hash",
            "message_sha256",
            "acceptance_sha256",
        ):
            self.backend.mutate = lambda op, value: (
                {**value, field: True} if op == "validate_prepared" else value
            )
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(Unavailable, "identity mismatch"),
            ):
                self.adapter.validate_prepared(
                    self.profile, self.request, 1, 1000, 10, self.prepared
                )

    def test_exact_permit_is_consumed_even_after_ambiguous_write(self):
        with self.assertRaisesRegex(Unavailable, "no current"):
            self.adapter.broadcast(self.prepared.message)
        self.adapter.recheck(self.profile, self.request, self.prepared)
        with self.assertRaisesRegex(Unavailable, "no current"):
            self.adapter.broadcast(b"other bytes")
        self.backend.broadcast_error = True
        with self.assertRaisesRegex(Unavailable, "ambiguous"):
            self.adapter.broadcast(self.prepared.message)
        with self.assertRaisesRegex(Unavailable, "no current"):
            self.adapter.broadcast(self.prepared.message)
        self.assertEqual(self.backend.operations.count("broadcast"), 1)

    def test_expired_permit_and_expired_request_refuse(self):
        self.adapter.recheck(self.profile, self.request, self.prepared)
        with patch("native_adapter.time.monotonic", return_value=time.monotonic() + 10):
            with self.assertRaisesRegex(Unavailable, "no current"):
                self.adapter.broadcast(self.prepared.message)
        self.adapter.clock = lambda: 1100
        with self.assertRaisesRegex(Refused, "expired"):
            self.adapter.recheck(self.profile, self.request, self.prepared)

    def receipt(self):
        return {
            "kind": "pool_execution",
            "scope": self.profile.scope,
            "request": self.request.identity,
            "message_hash": self.prepared.message_hash,
            "pool": self.profile.pool,
            "intent": self.request.intent,
            "body_sha256": self.request.body_sha256,
            "checkpoint": {"seqno": 10, "root_hash": h(21), "file_hash": h(22), "utime": 1000},
            "proof_digest": h(23),
            "transaction": h(24),
            "fee_credit": {
                "schema": "tos.relayer.fee-credit.v1",
                "note_body": self.request.fee_note_body,
                "note_key_index": self.request.fee_note_index,
                "slot": 2,
                "checkpoint_root": h(21),
                "leaf_index": 4,
                "transaction": h(24),
                "amount": "7",
            },
        }

    def test_exact_fee_credit_is_required_for_terminal_state(self):
        self.engine.submit(self.request)
        self.backend.final = self.receipt()
        self.assertEqual(self.engine.reconcile(self.request.identity), "executed")
        self.assertEqual(self.journal.get(self.request.identity)["state"], "executed")

    def test_source_only_nullifier_only_and_unrelated_proofs_refuse(self):
        for field, value in (
            ("kind", "source_wallet_send"),
            ("kind", "spent_nullifier"),
            ("pool", "0:" + h(88)),
            ("request", h(88)),
            ("body_sha256", h(88)),
        ):
            self.backend.final = {**self.receipt(), field: value}
            with self.subTest(field=field, value=value), self.assertRaises(Unavailable):
                self.adapter.evidence(self.profile, self.request, self.prepared)

    def test_fee_credit_substitutions_refuse(self):
        for field, value in (
            ("amount", "8"),
            ("slot", 1),
            ("note_key_index", True),
            ("note_body", h(88)),
            ("checkpoint_root", h(88)),
            ("transaction", h(88)),
        ):
            self.backend.final = self.receipt()
            self.backend.final["fee_credit"][field] = value
            with self.subTest(field=field), self.assertRaises(Unavailable):
                self.adapter.evidence(self.profile, self.request, self.prepared)

    def test_historical_execution_is_not_rejected_for_quote_expiry(self):
        self.backend.final = self.receipt()
        self.adapter.clock = lambda: 2000
        self.assertEqual(
            self.adapter.evidence(self.profile, self.request, self.prepared).outcome, "executed"
        )
        with self.assertRaisesRegex(Refused, "not currently valid"):
            self.adapter.verify_quote(self.journal.quote(self.request.quote_hash))

    def test_rejection_cannot_credit_a_fee(self):
        self.backend.final = {**self.receipt(), "kind": "terminal_refusal"}
        with self.assertRaisesRegex(Unavailable, "not exact"):
            self.adapter.evidence(self.profile, self.request, self.prepared)
        self.backend.final["fee_credit"] = None
        self.assertEqual(
            self.adapter.evidence(self.profile, self.request, self.prepared).outcome, "rejected"
        )

    def test_malformed_quote_terms_do_not_reach_native_authentication(self):
        envelope = json.loads(self.journal.quote(self.request.quote_hash))
        for key, value in (
            ("extra", True),
            ("success", "source_send"),
            ("slot", True),
            ("descriptor_b64", "bad"),
        ):
            mutated = {**envelope, "terms": {**envelope["terms"], key: value}}
            before = self.backend.operations.count("verify_quote")
            with self.subTest(key=key), self.assertRaises(Refused):
                self.adapter.verify_quote(encode(mutated))
            self.assertEqual(self.backend.operations.count("verify_quote"), before)

    def test_candidate_quote_substitution_refuses_before_native_preflight(self):
        for changes in (
            {"fee_slot": 1},
            {"fee_note_index": 9},
            {"valid_until": 1101},
            {"funding_cap": 101},
        ):
            changed = dataclasses.replace(self.request, **changes)
            with (
                self.subTest(changes=changes),
                self.assertRaisesRegex(Refused, "authenticated quote"),
            ):
                self.adapter.preflight(self.profile, changed)
        self.assertNotIn("preflight", self.backend.operations)

    def test_wrong_worker_quote_refuses_before_native_verification(self):
        signed = json.loads(self.journal.quote(self.request.quote_hash))
        signed["public_key_b64"] = b64(b"z" * 1312)
        with self.assertRaisesRegex(Refused, "pinned worker"):
            self.adapter.verify_quote(encode(signed))

    def test_adapter_never_accepts_another_release(self):
        other = dataclasses.replace(self.profile, global_id=43)
        with self.assertRaisesRegex(Refused, "release mismatch"):
            self.adapter.preflight(other, self.request)


if __name__ == "__main__":
    unittest.main()
