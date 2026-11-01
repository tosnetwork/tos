"""Process-isolated transport fixture. NO native chain, real signatures or funds.

Each child uses the real NativeAdapter, service, HTTP server and private SQLite
journal. Only the native provider is fabricated. The control pipe is test-local,
never a public/admin HTTP route. Do not use this harness as activation evidence.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import multiprocessing
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/bonded-relayer"))
from native_adapter import NativeAdapter, b64  # noqa: E402
from relay_client import Client  # noqa: E402
from relay_core import Engine, Journal, Refused, Release, Request, encode  # noqa: E402
from relay_service import RelayServer, Service  # noqa: E402
from test_native_boundary import BackendFixture, h, release  # noqa: E402


def profile(worker: int) -> Release:
    return dataclasses.replace(
        release(),
        bond="0:" + h(worker),
        worker_key_hash=hashlib.sha256(bytes([worker]) * 1312).hexdigest(),
    )


class NativeFixture(BackendFixture):
    """Fake native provider; durable counters measure orchestration, not consensus."""

    def __init__(self, journal, worker):
        super().__init__(journal.release)
        self.journal, self.worker = journal, worker
        self.path = journal.path.parent / "TEST-ONLY-counters.json"
        self.counts = (
            json.loads(self.path.read_text())
            if self.path.exists()
            else {"prepare": 0, "broadcast": 0}
        )
        self.invalid = False
        self.outcome = None
        self.bad_receipt = False

    def record(self, key):
        self.counts[key] += 1
        temporary = self.path.with_suffix(".tmp")
        with temporary.open("wb") as stream:
            stream.write(encode(self.counts))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.path)

    def call(self, operation, payload):
        if operation == "preflight" and self.invalid:
            raise Refused("TEST-ONLY invalid proof")
        if operation in ("prepare", "broadcast"):
            self.record(operation)
        if operation == "evidence":
            if self.outcome is None:
                return None
            req = Request.parse(encode(payload["request"]))
            terms = json.loads(self.journal.quote(req.quote_hash))["terms"]
            tx = h(900 + self.worker)
            root = h(800 + self.worker)
            fee = {
                "schema": "tos.relayer.fee-credit.v1",
                "note_body": req.fee_note_body,
                "note_key_index": req.fee_note_index,
                "slot": req.fee_slot,
                "checkpoint_root": root,
                "leaf_index": 4,
                "transaction": tx,
                "amount": str(terms["amount"]),
            }
            return {
                "kind": "pool_execution" if self.outcome == "executed" else "terminal_refusal",
                "scope": self.release.scope,
                "request": req.identity,
                "message_hash": h(99) if self.bad_receipt else payload["prepared"]["message_hash"],
                "pool": self.release.pool,
                "intent": req.intent,
                "body_sha256": req.body_sha256,
                "checkpoint": {"seqno": 10, "root_hash": root, "file_hash": h(22), "utime": 1000},
                "proof_digest": h(23),
                "transaction": tx,
                "fee_credit": fee if self.outcome == "executed" else None,
            }
        value = super().call(operation, payload)
        if operation == "sign_quote":
            value["public_key_b64"] = b64(bytes([self.worker]) * 1312)
        if operation == "prepare":
            identity = Request.parse(encode(payload["request"])).identity
            message = b"TEST-ONLY-message:" + identity.encode()
            value.update(message_b64=b64(message), message_hash=hashlib.sha256(message).hexdigest())
        return value


def child(root: str, worker: int, control):
    journal = server = None
    try:
        journal = Journal(
            Path(root) / "journal.sqlite", profile(worker), max_pending=8, require_quotes=True
        )
        backend = NativeFixture(journal, worker)
        adapter = NativeAdapter(journal, backend, clock=lambda: 1000)
        engine = Engine(journal, adapter, clock=lambda: 1000)
        service = Service(engine, fee=7, funding_cap=100, enabled=True)
        server = RelayServer(service, ("127.0.0.1", 0))
        server.timeout = 0.01
        control.send({"ready": True, "pid": os.getpid(), "port": server.server_address[1]})
        while True:
            server.handle_request()
            if not control.poll():
                continue
            message = control.recv()
            action = message["action"]
            if action == "stop":
                control.send({"stopped": True})
                break
            if action == "settings":
                for key in ("invalid", "outcome", "bad_receipt", "broadcast_error"):
                    if key in message:
                        setattr(backend, key, message[key])
                result = {"configured": True}
            elif action == "tick":
                result = service.tick()
            elif action == "counts":
                result = backend.counts
            elif action == "prepare_only":
                req = Request.parse(encode(message["request"]))
                funding = adapter.preflight(engine.release, req)
                row, created = journal.reserve(req, funding, 1000)
                if not created:
                    raise RuntimeError("fixture expected a fresh request")
                prepared = adapter.prepare(
                    engine.release, req, row["slot"], row["issued"], row["funding"]
                )
                adapter.validate_prepared(
                    engine.release, req, row["slot"], row["issued"], row["funding"], prepared
                )
                journal.store_prepared(req.identity, prepared)
                result = {"message_hash": prepared.message_hash}
            else:
                raise RuntimeError("unknown private fixture control")
            control.send(result)
    except BaseException as error:
        try:
            control.send({"ready": False, "error": type(error).__name__})
        except (OSError, EOFError):
            pass
        raise
    finally:
        if server is not None:
            server.server_close()
        if journal is not None:
            journal.close()
        control.close()


class Operator:
    def __init__(self, root: Path, worker: int):
        self.root, self.worker = root, worker
        root.mkdir(mode=0o700)
        self.process = self.pipe = None
        self.start()

    def start(self):
        context = multiprocessing.get_context("spawn")
        self.pipe, remote = context.Pipe()
        self.process = context.Process(target=child, args=(str(self.root), self.worker, remote))
        self.process.start()
        remote.close()
        if not self.pipe.poll(10):
            self.stop(crash=True)
            raise RuntimeError("operator fixture startup timed out")
        state = self.pipe.recv()
        if not state.get("ready"):
            self.stop(crash=True)
            raise RuntimeError("operator fixture startup refused")
        self.pid, self.port = state["pid"], state["port"]
        self.release = profile(self.worker)
        self.client = Client(
            f"http://127.0.0.1:{self.port}",
            self.release.scope,
            self.verify,
            allow_loopback=True,
            clock=lambda: 1000,
        )

    def verify(self, wire):
        # This is deliberately not a cryptographic verifier. Real ML-DSA quote
        # primitives are tested in the Rust crate, separately from this fixture.
        value = json.loads(wire)
        if (
            value["schema"] != "tos.br1.quote.v1"
            or base64.b64decode(value["public_key_b64"]) != bytes([self.worker]) * 1312
            or base64.b64decode(value["signature_b64"]) != b"s" * 2420
            or value["terms"]["release"] != self.release.scope
        ):
            raise Refused("TEST-ONLY quote mismatch")
        return value["terms"]

    def control(self, action, **values):
        self.pipe.send({"action": action, **values})
        if not self.pipe.poll(5):
            raise RuntimeError("operator control timed out")
        result = self.pipe.recv()
        if "error" in result:
            raise RuntimeError("operator fixture failed")
        return result

    def stop(self, *, crash=False):
        if self.process is None:
            return
        if self.process.is_alive():
            if crash:
                self.process.kill()
            else:
                try:
                    self.control("stop")
                except (OSError, EOFError, RuntimeError):
                    self.process.kill()
        self.process.join(timeout=2)
        if self.process.is_alive():
            self.process.kill()
            self.process.join(timeout=2)
        if self.process.is_alive():
            raise RuntimeError("operator fixture could not be reaped")
        self.pipe.close()
        self.process.close()
        self.pipe = self.process = None

    def restart(self):
        self.stop(crash=True)
        self.start()


def candidate(operator: Operator, quote, nonce=11) -> Request:
    body = f"TEST-ONLY-SHIELD-CANDIDATE:{nonce}".encode()
    return Request(
        operator.release.scope,
        h(nonce),
        b64(body),
        hashlib.sha256(body).hexdigest(),
        (h(nonce + 1), h(nonce + 2)),
        quote.identity,
        h(nonce + 3),
        quote.terms["slot"],
        quote.terms["note_index"],
        quote.terms["valid_until"],
        quote.terms["funding_cap"],
    )
