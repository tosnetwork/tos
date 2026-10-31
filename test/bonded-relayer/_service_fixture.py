"""TEST ONLY. No real signatures, proof verification, gas, or chain execution."""

import base64
import dataclasses
import hashlib
import hmac
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/bonded-relayer"))
from relay_core import Evidence, Prepared, Refused, Release, Request, encode  # noqa: E402


def h(n):
    return f"{n:064x}"


def profile(worker=3):
    return Release(
        42, h(1), h(2), "0:" + h(worker), h(4), h(5), h(worker + 100), "0:" + h(7), h(8), h(9)
    )


def candidate(release, quote, n=11, **changes):
    body = f"TEST-ONLY-body-{n}".encode()
    terms = quote["quote"]["terms"]
    values = dict(
        release=release.scope,
        intent=h(n),
        body_b64=base64.b64encode(body).decode(),
        body_sha256=hashlib.sha256(body).hexdigest(),
        nullifiers=(h(n + 1), h(n + 2)),
        quote_hash=quote["quote_id"],
        fee_note_body=h(n + 3),
        fee_slot=terms["slot"],
        fee_note_index=terms["note_index"],
        valid_until=terms["valid_until"],
        funding_cap=terms["funding_cap"],
    )
    values.update(changes)
    return Request(**values)


class FixtureAuthority:
    """An explicit HMAC/chain fake; never a configurable daemon backend."""

    def __init__(self, journal):
        self.journal = journal
        self.key = ("TEST-ONLY-" + journal.release.scope).encode()
        self.preflights = self.prepares = 0
        self.writes = []
        self.ambiguous = self.invalid_proof = self.bad_prepare = self.bad_quote = False
        self.outcome = None

    def check_capabilities(self):
        return None

    def descriptor(self, index):
        data = bytearray(2573)
        data[:5] = b"SHD1\x01"
        data[5:37] = (1).to_bytes(32, "big")
        data[37:45] = index.to_bytes(8, "big")
        return base64.b64encode(data).decode()

    def sign_quote(self, terms):
        if self.bad_quote:
            raise Refused("fixture signing failed")
        return encode(
            {
                "terms": terms,
                "fixture_mac": hmac.new(self.key, encode(terms), hashlib.sha256).hexdigest(),
            }
        )

    def verify_quote(self, wire, *, historical=False):
        obj = json.loads(wire)
        expected = hmac.new(self.key, encode(obj["terms"]), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, obj["fixture_mac"]):
            raise Refused("fixture quote authentication failed")
        return obj["terms"]

    def preflight(self, release, request):
        self.preflights += 1
        if self.invalid_proof:
            raise Refused("fixture invalid proof")
        return 10

    def prepare(self, release, request, slot, issued_at, funding):
        self.prepares += 1
        return Prepared(
            f"TEST-ONLY-message:{request.identity}:{funding}".encode(),
            h(1000 + slot),
            f"TEST-ONLY-acceptance:{slot}:{issued_at}:{request.identity}".encode(),
        )

    def validate_prepared(self, release, request, slot, issued_at, funding, prepared):
        if self.bad_prepare or not prepared.message.endswith(f":{funding}".encode()):
            raise Refused("fixture prepared mismatch")

    def recheck(self, release, request, prepared):
        return None

    def broadcast(self, message):
        self.writes.append(message)
        if self.ambiguous:
            raise TimeoutError("fixture ambiguous network write")

    def evidence(self, release, request, prepared):
        if self.outcome is None:
            return None
        terms = json.loads(self.journal.quote(request.quote_hash))["terms"]
        fee = (
            None
            if self.outcome == "rejected"
            else {
                "schema": "tos.relayer.fee-credit.v1",
                "note_body": request.fee_note_body,
                "note_key_index": request.fee_note_index,
                "slot": request.fee_slot,
                "checkpoint_root": h(21),
                "leaf_index": 1,
                "transaction": h(24),
                "amount": str(terms["amount"]),
            }
        )
        return Evidence(
            release.scope, request.identity, prepared.message_hash, self.outcome, h(21), h(22), fee
        )


def submission(request, token):
    return encode({"request": dataclasses.asdict(request), "status_token": token})
