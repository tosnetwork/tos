"""BR1 quote/submit/status service over the existing durable engine.

The listener is loopback-only. It is not an anonymity transport or a production
activation approval. Supply a reviewed native adapter; no fixture is importable
through the wire protocol. Status and acceptance receipts require a client-held
capability bound into the signed quote. There is no public recovery/evidence API.
"""

from __future__ import annotations

import base64
import fcntl
import hmac
import os
import socketserver
import stat
import threading
import time

from relay_core import (
    MAX_LIFETIME,
    MAX_QUOTE,
    Engine,
    Refused,
    Request,
    checked_add,
    digest,
    encode,
    integer,
)
from relay_http import HTTPRefused, receive, respond
from relay_wire import BODY_LIMIT, check_terms, exact, parse, status_hash
from tor_transport import OnionEndpoint


class Service:
    def __init__(self, engine: Engine, *, fee: int, funding_cap: int, enabled: bool = False):
        if not engine.journal.require_quotes:
            raise Refused("service requires local quote binding")
        if engine.journal.max_pending > 64:
            raise Refused("service recovery supports at most 64 live jobs")
        if type(enabled) is not bool:
            raise Refused("invalid service switch")
        self.engine, self.journal = engine, engine.journal
        self.release, self.authority = engine.release, engine.adapter
        self.fee = integer(fee, 1, (1 << 63) - 1)
        self.funding_cap = integer(funding_cap, 1, self.journal.max_reserved)
        self.enabled = enabled
        self._busy = threading.Lock()
        self._healthy = False
        if enabled:
            self.authority.check_capabilities()
            self._healthy = True

    def handle(self, method: str, path: str, wire: bytes) -> tuple[int, dict]:
        if method == "GET" and path == "/v1/health" and not wire:
            return (200 if self.enabled and self._healthy else 503), {
                "schema": "tos.br1.health.v1",
                "ready": self.enabled and self._healthy,
                "release": self.release.scope,
                "production_approved": False,
            }
        if method != "POST":
            return 405, {"error": "method_not_allowed"}
        if path not in ("/v1/quote", "/v1/submit", "/v1/status"):
            return 404, {"error": "not_found"}
        if not self.enabled:
            return 503, {"error": "service_disabled"}
        if not self._busy.acquire(blocking=False):
            return 429, {"error": "worker_busy"}
        try:
            data = parse(wire, BODY_LIMIT if path == "/v1/submit" else 2048)
            if path == "/v1/quote":
                return 200, self._quote(data)
            if path == "/v1/submit":
                return self._submit(data)
            return self._status(data)
        except Refused:
            # Do not echo native stderr, SQL, bearer transactions or note data.
            return 422, {"error": "request_refused"}
        except Exception:
            self._healthy = False
            return 503, {"error": "backend_unavailable"}
        finally:
            self._busy.release()

    def _quote(self, data: dict) -> dict:
        exact(data, {"slot", "lifetime", "status_token"})
        slot = integer(data["slot"], 0, 2)
        lifetime = integer(data["lifetime"], 1, MAX_LIFETIME)
        access = status_hash(data["status_token"])
        now = int(self.engine.clock())
        allocation, index = self.journal.allocate_quote(now, lifetime)
        terms = {
            "schema": "tos.br1.quote.terms.v1",
            "release": self.release.scope,
            "nonce": allocation,
            "note_index": index,
            "issued_at": now,
            "valid_until": checked_add(now, lifetime, (1 << 32) - 1),
            "slot": slot,
            "amount": self.fee,
            "funding_cap": self.funding_cap,
            "descriptor_b64": self.authority.descriptor(index),
            "status_hash": access,
            "success": "pool_execution",
        }
        check_terms(terms, self.release.scope)
        signed = self.authority.sign_quote(terms)
        authenticated = self.authority.verify_quote(signed)
        if encode(authenticated) != encode(terms):
            raise Refused("signer changed quote terms")
        identity = self.journal.publish_quote(allocation, terms, signed)
        return {
            "schema": "tos.br1.quote.response.v1",
            "quote_id": identity,
            "quote": parse(signed, MAX_QUOTE),
        }

    def _access(self, request: Request, token: str):
        expected = status_hash(token)
        saved = parse(self.journal.quote(request.quote_hash), MAX_QUOTE)
        terms = saved.get("terms")
        check_terms(terms, self.release.scope)
        if not hmac.compare_digest(expected, terms["status_hash"]):
            raise Refused("status capability mismatch")
        return terms

    def _submit(self, data: dict) -> tuple[int, dict]:
        exact(data, {"request", "status_token"})
        if type(data["request"]) is not dict:
            raise Refused("request object required")
        request = Request.parse(encode(data["request"]))
        if request.release != self.release.scope:
            raise Refused("request release mismatch")
        # Capability and quote checks precede costly proof work and signing.
        terms = self._access(request, data["status_token"])
        if (
            request.fee_slot != terms["slot"]
            or request.fee_note_index != terms["note_index"]
            or request.valid_until > terms["valid_until"]
            or request.funding_cap > terms["funding_cap"]
        ):
            raise Refused("request changed the accepted quote")
        self.engine.submit(request)
        return 202, self._view(request.identity)

    def _status(self, data: dict) -> tuple[int, dict]:
        exact(data, {"request_id", "status_token"})
        row = self.journal.get(digest(data["request_id"]))
        if row is None:
            return 404, {"error": "status_unavailable"}
        try:
            self._access(Request.parse(bytes(row["request"])), data["status_token"])
        except Refused:
            return 404, {"error": "status_unavailable"}
        return 200, self._view(data["request_id"])

    def _view(self, identity: str) -> dict:
        row = self.journal.get(identity)
        if row is None:
            raise Refused("unknown request")
        evidence = parse(bytes(row["evidence"]), 16 * 1024) if row["evidence"] is not None else None
        return {
            "schema": "tos.br1.status.v1",
            "request_id": identity,
            "release": self.release.scope,
            "status": row["state"],
            "message_hash": row["message_hash"],
            "acceptance_b64": base64.b64encode(bytes(row["acceptance"])).decode("ascii")
            if row["acceptance"] is not None
            else None,
            "finality": {
                "checkpoint_root": evidence["finalized_block"],
                "proof_digest": evidence["proof_digest"],
            }
            if evidence
            else None,
            "requires_independent_verification": True,
        }

    def tick(self, *, stop: threading.Event | None = None) -> dict:
        """Internal bounded recovery; never invoked by a public status request."""
        if not self.enabled or not self._busy.acquire(blocking=False):
            return {"processed": 0, "unavailable": 0}
        count = failed = 0
        try:
            try:
                self.authority.check_capabilities()
            except Exception:
                self._healthy = False
                return {"processed": 0, "unavailable": 1}
            for identity in self.journal.pending(self.journal.max_pending):
                if stop is not None and stop.is_set():
                    break
                try:
                    row = self.journal.get(identity)
                    request = self.engine._request(row)
                    if row["state"] == "reserved" and request.valid_until < int(
                        self.engine.clock()
                    ):
                        self.journal.cancel_unprepared(identity, int(self.engine.clock()))
                    elif row["state"] == "prepared":
                        self.engine.dispatch(identity)
                    elif row["state"] in ("unknown", "broadcast"):
                        self.engine.reconcile(identity)
                    count += 1
                except Exception:
                    failed += 1
            self._healthy = failed == 0
            return {"processed": count, "unavailable": failed}
        finally:
            self._busy.release()


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            line, headers, wire = receive(
                self.request, BODY_LIMIT, time.monotonic() + self.server.read_timeout
            )
            parts = line.split(" ")
            if len(parts) != 3 or parts[2] != "HTTP/1.1" or not headers.get("host"):
                raise HTTPRefused("invalid request line or host")
            if self.server.onion is not None and headers["host"] != self.server.onion.authority:
                raise HTTPRefused("onion Host binding mismatch")
            status, result = self.server.service.handle(parts[0], parts[1], wire)
        except (OSError, Refused):
            status, result = 400, {"error": "invalid_http_request"}
        try:
            respond(self.request, status, result, time.monotonic() + self.server.write_timeout)
        except OSError:
            pass


class RelayServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = False
    daemon_threads = False
    request_queue_size = 8

    def __init__(self, service: Service, address: tuple[str, int], *, onion_endpoint=None):
        self.onion = OnionEndpoint.parse(onion_endpoint) if onion_endpoint is not None else None
        self.read_timeout = 30 if self.onion is not None else 5
        self.write_timeout = 10 if self.onion is not None else 2
        if address[0] != "127.0.0.1":
            raise Refused("BR1 service must bind IPv4 loopback behind a reviewed transport")
        integer(address[1], 0, 65535)
        self.service = service
        self._connections = threading.BoundedSemaphore(4)
        self._rate_lock = threading.Lock()
        self._tokens, self._updated = 16.0, time.monotonic()
        lock_path = service.journal.path.with_name(service.journal.path.name + ".service.lock")
        self._owner = os.open(
            lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
        try:
            metadata = os.fstat(self._owner)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077
            ):
                raise Refused("unsafe service lock")
            fcntl.flock(self._owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            super().__init__(address, _Handler)
        except BaseException:
            if self._owner >= 0:
                os.close(self._owner)
                self._owner = -1
            raise

    def process_request(self, request, client_address):
        with self._rate_lock:
            now = time.monotonic()
            self._tokens = min(16.0, self._tokens + (now - self._updated) * 4)
            self._updated = now
            admitted = self._tokens >= 1
            if admitted:
                self._tokens -= 1
        acquired = admitted and self._connections.acquire(blocking=False)
        if not acquired:
            try:
                respond(request, 429, {"error": "connection_limit"}, time.monotonic() + 0.1)
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connections.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connections.release()

    def server_close(self):
        try:
            super().server_close()
        finally:
            if self._owner >= 0:
                os.close(self._owner)
                self._owner = -1

    def handle_error(self, request, client_address):
        # Socket errors must not print a traceback containing bearer payloads.
        self.service._healthy = False
