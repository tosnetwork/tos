"""BR1 journal adapter to the private, pinned native backend protocol.

The process boundary and its binding checks are implemented here. The native
chain/signer/finality provider is NOT supplied by this module. Its missing
capabilities must refuse startup, never turn an RPC assertion into finality.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import threading
import time

from native_process import NativeRPC, Unavailable, object_from_bytes
from relay_core import (
    MAX_ACCEPTANCE,
    MAX_PREPARED,
    MAX_QUOTE,
    Evidence,
    Journal,
    Prepared,
    Refused,
    Release,
    Request,
    digest,
    encode,
    integer,
)
from relay_wire import check_terms

CAPABILITIES = frozenset(
    {
        "live_bond_v1",
        "shield_exact_simulation_v1",
        "worker_mldsa44_v1",
        "funded_wallet_v1",
        "wallet_sequence_lease_v1",
        "destination_finality_v1",
        "fee_note_import_v1",
        "quote_descriptor_v1",
    }
)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str, maximum: int, *, exact: int | None = None) -> bytes:
    if type(text) is not str or not 0 < len(text) <= 4 * ((maximum + 2) // 3):
        raise Refused("base64 outside byte bound")
    try:
        data = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as error:
        raise Refused("invalid base64") from error
    if (
        not 0 < len(data) <= maximum
        or b64(data) != text
        or (exact is not None and len(data) != exact)
    ):
        raise Refused("noncanonical base64 or wrong width")
    return data


def fields(value: dict, expected: set[str]) -> dict:
    if type(value) is not dict or set(value) != expected:
        raise Unavailable("native result fields mismatch")
    return value


def matches(value: dict, expected: dict):
    # Python bool is an int subclass; equality alone is not a type check.
    for key, item in expected.items():
        if type(value.get(key)) is not type(item) or value[key] != item:
            raise Unavailable("native result identity mismatch")


class NativeAdapter:
    def __init__(self, journal: Journal, rpc: NativeRPC, *, clock=time.time):
        if not journal.require_quotes:
            raise Refused("native adapter requires durable authenticated quotes")
        self.journal, self.rpc, self.clock = journal, rpc, clock
        self.release = journal.release
        self._permits: dict[str, tuple[str, float]] = {}
        self._permit_lock = threading.Lock()
        self.check_capabilities()

    def _call(self, operation: str, **payload):
        return self.rpc.call(operation, {"release": dataclasses.asdict(self.release), **payload})

    def check_capabilities(self):
        value = fields(self._call("capabilities"), {"scope", "protocol", "features"})
        matches(value, {"scope": self.release.scope, "protocol": "tos.br1.native.v1"})
        features = value["features"]
        if (
            type(features) is not list
            or len(features) > 32
            or any(type(item) is not str for item in features)
            or len(set(features)) != len(features)
            or not CAPABILITIES.issubset(features)
        ):
            raise Unavailable("native backend lacks required capabilities")

    def verify_endpoint(self, endpoint: str):
        value = fields(self._call("verify_endpoint", endpoint=endpoint), {"scope", "endpoint"})
        matches(value, {"scope": self.release.scope, "endpoint": endpoint})

    def _scope(self, release: Release):
        if release != self.release:
            raise Refused("adapter release mismatch")

    def _checkpoint(self, value: dict, *, fresh: bool) -> dict:
        fields(value, {"seqno", "root_hash", "file_hash", "utime"})
        integer(value["seqno"], 1, (1 << 32) - 1)
        integer(value["utime"], 1, (1 << 32) - 1)
        digest(value["root_hash"])
        digest(value["file_hash"])
        now = int(self.clock())
        if fresh and not now - 60 <= value["utime"] <= now + 5:
            raise Unavailable("native checkpoint is not fresh")
        return value

    def _quote(self, request: Request) -> dict:
        envelope = self.journal.quote(request.quote_hash)
        terms = self.verify_quote(envelope)
        if (
            request.fee_slot != terms["slot"]
            or request.fee_note_index != terms["note_index"]
            or request.valid_until > terms["valid_until"]
            or request.funding_cap > terms["funding_cap"]
        ):
            raise Refused("candidate does not match the authenticated quote")
        if hashlib.sha256(b"TOS-BR1-QUOTE\0" + encode(terms)).hexdigest() != request.quote_hash:
            raise Refused("local quote digest mismatch")
        return object_from_bytes(envelope, MAX_QUOTE)

    def preflight(self, release: Release, request: Request) -> int:
        self._scope(release)
        value = fields(
            self._call(
                "preflight",
                request=dataclasses.asdict(request),
                quote=self._quote(request),
            ),
            {"scope", "request", "body_sha256", "funding", "checkpoint"},
        )
        matches(
            value,
            {
                "scope": release.scope,
                "request": request.identity,
                "body_sha256": request.body_sha256,
            },
        )
        self._checkpoint(value["checkpoint"], fresh=True)
        return integer(value["funding"], 1, min(request.funding_cap, self.journal.max_reserved))

    def prepare(self, release, request, slot, issued_at, funding) -> Prepared:
        self._scope(release)
        value = fields(
            self._call(
                "prepare",
                request=dataclasses.asdict(request),
                quote=self._quote(request),
                slot=slot,
                issued_at=issued_at,
                funding=funding,
            ),
            {"message_b64", "message_hash", "acceptance_b64"},
        )
        return Prepared(
            unb64(value["message_b64"], MAX_PREPARED),
            value["message_hash"],
            unb64(value["acceptance_b64"], MAX_ACCEPTANCE),
        )

    @staticmethod
    def _prepared(value: Prepared) -> dict:
        return {
            "message_b64": b64(value.message),
            "message_hash": value.message_hash,
            "acceptance_b64": b64(value.acceptance),
        }

    def validate_prepared(self, release, request, slot, issued_at, funding, prepared):
        self._scope(release)
        expected = {
            "scope": release.scope,
            "request": request.identity,
            "slot": slot,
            "issued_at": issued_at,
            "funding": funding,
            "message_hash": prepared.message_hash,
            "message_sha256": hashlib.sha256(prepared.message).hexdigest(),
            "acceptance_sha256": hashlib.sha256(prepared.acceptance).hexdigest(),
        }
        value = fields(
            self._call(
                "validate_prepared",
                request=dataclasses.asdict(request),
                prepared=self._prepared(prepared),
                slot=slot,
                issued_at=issued_at,
                funding=funding,
                # Expiry is checked before a write, not when inspecting old signed bytes.
            ),
            set(expected),
        )
        matches(value, expected)

    def recheck(self, release, request, prepared):
        self._scope(release)
        if int(self.clock()) >= request.valid_until:
            raise Refused("request expired before broadcast")
        value = fields(
            self._call(
                "recheck",
                request=dataclasses.asdict(request),
                prepared=self._prepared(prepared),
            ),
            {"scope", "request", "message_hash", "checkpoint", "permit"},
        )
        matches(
            value,
            {
                "scope": release.scope,
                "request": request.identity,
                "message_hash": prepared.message_hash,
            },
        )
        self._checkpoint(value["checkpoint"], fresh=True)
        permit = digest(value["permit"])
        key = hashlib.sha256(prepared.message).hexdigest()
        with self._permit_lock:
            now = time.monotonic()
            self._permits = {key: val for key, val in self._permits.items() if val[1] > now}
            if len(self._permits) >= 2 or key in self._permits:
                raise Unavailable("broadcast permit capacity or duplicate")
            self._permits[key] = (permit, now + 5)

    def broadcast(self, exact_message: bytes):
        key = hashlib.sha256(exact_message).hexdigest()
        with self._permit_lock:
            value = self._permits.pop(key, None)
        if value is None or value[1] <= time.monotonic():
            raise Unavailable("no current one-use broadcast permit")
        result = fields(
            self._call(
                "broadcast",
                message_b64=b64(exact_message),
                permit=value[0],
            ),
            {"submitted_sha256"},
        )
        matches(result, {"submitted_sha256": key})
        # This is transport acknowledgement only. The journal remains nonterminal.

    def evidence(self, release, request, prepared) -> Evidence | None:
        self._scope(release)
        value = self._call(
            "evidence", request=dataclasses.asdict(request), prepared=self._prepared(prepared)
        )
        if value is None:
            return None
        fields(
            value,
            {
                "kind",
                "scope",
                "request",
                "message_hash",
                "pool",
                "intent",
                "body_sha256",
                "checkpoint",
                "proof_digest",
                "transaction",
                "fee_credit",
            },
        )
        matches(
            value,
            {
                "scope": release.scope,
                "request": request.identity,
                "message_hash": prepared.message_hash,
                "pool": release.pool,
                "intent": request.intent,
                "body_sha256": request.body_sha256,
            },
        )
        checkpoint = self._checkpoint(value["checkpoint"], fresh=False)
        digest(value["proof_digest"])
        digest(value["transaction"])
        if value["kind"] == "pool_execution":
            fee = fields(
                value["fee_credit"],
                {
                    "schema",
                    "note_body",
                    "note_key_index",
                    "slot",
                    "checkpoint_root",
                    "leaf_index",
                    "transaction",
                    "amount",
                },
            )
            # A finalized historical transaction may outlive its quote. Verify
            # the signature and binding, without applying live quote expiry.
            terms = self.verify_quote(self.journal.quote(request.quote_hash), historical=True)
            if hashlib.sha256(b"TOS-BR1-QUOTE\0" + encode(terms)).hexdigest() != request.quote_hash:
                raise Unavailable("historical quote digest mismatch")
            matches(
                fee,
                {
                    "schema": "tos.relayer.fee-credit.v1",
                    "note_body": request.fee_note_body,
                    "note_key_index": request.fee_note_index,
                    "slot": request.fee_slot,
                    "checkpoint_root": checkpoint["root_hash"],
                    "transaction": value["transaction"],
                    "amount": str(terms["amount"]),
                },
            )
            integer(fee["leaf_index"], 0, (1 << 32) - 1)
            outcome = "executed"
        elif value["kind"] == "terminal_refusal" and value["fee_credit"] is None:
            fee, outcome = None, "rejected"
        else:
            raise Unavailable("not exact destination execution or terminal refusal")
        return Evidence(
            release.scope,
            request.identity,
            prepared.message_hash,
            outcome,
            checkpoint["root_hash"],
            value["proof_digest"],
            fee,
        )

    def descriptor(self, index: int) -> str:
        integer(index, 0, (1 << 63) - 1)
        value = fields(
            self._call("descriptor", note_index=index), {"scope", "note_index", "descriptor_b64"}
        )
        matches(value, {"scope": self.release.scope, "note_index": index})
        unb64(value["descriptor_b64"], 8192)
        return value["descriptor_b64"]

    def sign_quote(self, terms: dict) -> bytes:
        check_terms(terms, self.release.scope)
        wire = encode(terms)
        if len(wire) > 16 * 1024 or terms.get("release") != self.release.scope:
            raise Refused("quote terms outside bound or release")
        value = fields(
            self._call("sign_quote", terms_b64=b64(wire)), {"public_key_b64", "signature_b64"}
        )
        envelope = encode({"schema": "tos.br1.quote.v1", "terms": terms, **value})
        self.verify_quote(envelope)
        return envelope

    def verify_quote(self, wire: bytes, *, historical: bool = False) -> dict:
        value = fields(
            object_from_bytes(wire, MAX_QUOTE),
            {"schema", "terms", "public_key_b64", "signature_b64"},
        )
        if value["schema"] != "tos.br1.quote.v1" or type(value["terms"]) is not dict:
            raise Refused("invalid quote envelope")
        key = unb64(value["public_key_b64"], 1312, exact=1312)
        unb64(value["signature_b64"], 2420, exact=2420)
        if hashlib.sha256(key).hexdigest() != self.release.worker_key_hash:
            raise Refused("quote signer is not the pinned worker")
        terms = value["terms"]
        check_terms(terms, self.release.scope)
        if terms.get("release") != self.release.scope:
            raise Refused("quote release mismatch")
        integer(terms.get("issued_at"), 1, (1 << 32) - 1)
        integer(
            terms.get("valid_until"),
            terms["issued_at"] + 1,
            min((1 << 32) - 1, terms["issued_at"] + 300),
        )
        integer(terms.get("amount"), 1, (1 << 63) - 1)
        if not historical and not terms["issued_at"] <= int(self.clock()) < terms["valid_until"]:
            raise Refused("quote is not currently valid")
        expected = {
            "terms_sha256": hashlib.sha256(encode(terms)).hexdigest(),
            "worker_key_hash": self.release.worker_key_hash,
        }
        result = fields(self._call("verify_quote", envelope=value), set(expected))
        matches(result, expected)
        return terms
