"""Canonical public BR1 quote and API shapes, shared by native boundary and client.

These are structural checks, not signature verification or chain authentication.
No server, process transport or platform-specific module is imported here.
"""

from __future__ import annotations

import base64
import hashlib
import json

from relay_core import MAX_BODY, MAX_LIFETIME, Refused, checked_add, digest, integer, unique_object

BODY_LIMIT = 2 * MAX_BODY + 4096
TERMS_FIELDS = frozenset(
    {
        "schema",
        "release",
        "nonce",
        "note_index",
        "issued_at",
        "valid_until",
        "slot",
        "amount",
        "funding_cap",
        "descriptor_b64",
        "status_hash",
        "success",
    }
)


def parse(wire: bytes, maximum: int) -> dict:
    if type(wire) is not bytes or not 0 < len(wire) <= maximum:
        raise Refused("API body outside byte bound")
    try:
        obj = json.loads(
            wire,
            object_pairs_hook=unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(Refused("nonfinite JSON")),
        )
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Refused("invalid API object") from error
    if type(obj) is not dict:
        raise Refused("API object required")
    return obj


def exact(value: dict, expected: set[str]):
    if set(value) != expected:
        raise Refused("unknown or missing API member")


def status_hash(token: str) -> str:
    digest(token)
    return hashlib.sha256(b"TOS-BR1-STATUS\0" + bytes.fromhex(token)).hexdigest()


def check_terms(terms: dict, release: str):
    if type(terms) is not dict or set(terms) != TERMS_FIELDS:
        raise Refused("quote terms shape")
    if (
        terms["schema"] != "tos.br1.quote.terms.v1"
        or terms["release"] != release
        or terms["success"] != "pool_execution"
    ):
        raise Refused("quote semantics mismatch")
    digest(terms["nonce"])
    digest(terms["status_hash"])
    integer(terms["slot"], 0, 2)
    integer(terms["note_index"], 0, (1 << 63) - 1)
    integer(terms["amount"], 1, (1 << 63) - 1)
    integer(terms["funding_cap"], 1, (1 << 63) - 1)
    integer(terms["issued_at"], 1, (1 << 32) - 1)
    maximum = checked_add(terms["issued_at"], MAX_LIFETIME, (1 << 32) - 1)
    integer(terms["valid_until"], terms["issued_at"] + 1, maximum)
    descriptor = terms["descriptor_b64"]
    if type(descriptor) is not str or len(descriptor) != 3432:
        raise Refused("descriptor width")
    try:
        decoded = base64.b64decode(descriptor, validate=True)
    except ValueError as error:
        raise Refused("descriptor encoding") from error
    if len(decoded) != 2573 or base64.b64encode(decoded).decode("ascii") != descriptor:
        raise Refused("descriptor encoding")
    if decoded[:5] != b"SHD1\x01" or int.from_bytes(decoded[37:45], "big") != terms["note_index"]:
        raise Refused("descriptor index or version mismatch")
    # Domain, PQ-key and recipient derivation are verified by the native authority,
    # not inferred from these structural checks.
