"""Differential corpus for the BR1 wire rules: the Python reference computes
every expected value; the Rust client (`tools/bonded-relayer/client`) checks
the same inputs against the committed fixture. Regenerate with

    python3 -I test/bonded-relayer/br1_wire_corpus.py > test/bonded-relayer/fixtures/br1-wire-corpus.json

`test_wire_corpus.py` fails when the committed fixture is not what this script
produces. Public test values only; nothing here is a key or a secret.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/bonded-relayer"))
from relay_core import MAX_BODY, Refused, Release, Request, encode  # noqa: E402
from relay_wire import BODY_LIMIT, check_terms, status_hash  # noqa: E402


def h(n: int) -> str:
    return f"{n:064x}"


def refuses(call) -> bool:
    try:
        call()
    except Refused:
        return True
    return False


def descriptor(index: int, version: bytes = b"SHD1\x01") -> str:
    data = bytearray(2573)
    data[:5] = version
    data[5:37] = (1).to_bytes(32, "big")
    data[37:45] = index.to_bytes(8, "big")
    return base64.b64encode(data).decode("ascii")


def corpus() -> dict:
    release = Release(3, h(1), h(2), "0:" + h(3), h(4), h(5), h(6), "0:" + h(7), h(8), h(9))
    token = "0c" * 32
    terms = {
        "schema": "tos.br1.quote.terms.v1",
        "release": release.scope,
        "nonce": "0a" * 32,
        "note_index": 5,
        "issued_at": 1700000000,
        "valid_until": 1700000300,
        "slot": 2,
        "amount": 7,
        "funding_cap": 250000000,
        "descriptor_b64": descriptor(5),
        "status_hash": status_hash(token),
        "success": "pool_execution",
    }
    body = b"TEST-ONLY-body"
    request = Request(
        release=release.scope,
        intent=h(11),
        body_b64=base64.b64encode(body).decode("ascii"),
        body_sha256=hashlib.sha256(body).hexdigest(),
        nullifiers=(h(12), h(13)),
        quote_hash=hashlib.sha256(b"TOS-BR1-QUOTE\0" + encode(terms)).hexdigest(),
        fee_note_body=h(14),
        fee_slot=2,
        fee_note_index=5,
        valid_until=1700000300,
        funding_cap=250000000,
    )
    canonical_inputs = [
        {"z": {"b": 2, "a": 1}, "a": 0},
        {"n": 18446744073709551615, "s": 'a"b\\c/\u0001'},
        {"empty": {}, "list": [3, {"y": 1, "x": [True, False, None]}]},
    ]
    parse_inputs = [
        ('{"a":1,"a":2}', True),
        ('{"a":[{"x":1,"x":2}]}', True),
        ('{"a":1.5}', True),
        ("{}{}", True),
        ("[1]", True),
        ("", True),
        ('{"a":1e2}', True),
        ('{"a":NaN}', True),
        ('{"a":-1}', False),
        ('{"a":{"b":{"c":[]}}}', False),
    ]
    terms_cases = [
        ("schema", "tos.br1.quote.terms.v2"),
        ("release", h(99)),
        ("success", "broadcast"),
        ("nonce", "00" * 32),
        ("slot", 3),
        ("amount", 0),
        ("funding_cap", 1 << 63),
        ("valid_until", 1700000301),
        ("valid_until", 1700000000),
        ("issued_at", 0),
        ("note_index", 6),
        ("descriptor_b64", descriptor(5)[1:]),
        ("descriptor_b64", descriptor(5, b"SHD1\x02")),
        ("status_hash", "0D" * 32),
        ("amount", 7.0),
    ]
    terms_vectors = []
    for field, value in terms_cases:
        altered = dict(terms)
        altered[field] = value
        terms_vectors.append(
            {
                "field": field,
                "value": value,
                "refused": refuses(lambda: check_terms(altered, release.scope)),
            }
        )
    extra = dict(terms)
    extra["extra"] = 1
    terms_vectors.append(
        {
            "field": "extra",
            "value": 1,
            "refused": refuses(lambda: check_terms(extra, release.scope)),
        }
    )
    request_cases = [
        ("nullifiers", [h(12), h(12)]),
        ("intent", "f" * 64),
        ("fee_slot", 3),
        ("funding_cap", 0),
        ("funding_cap", 1 << 63),
        ("valid_until", 0),
        ("body_sha256", h(1)),
        ("body_b64", base64.b64encode(body).decode("ascii") + "="),
        ("body_b64", base64.b64encode(b"x" * (MAX_BODY + 1)).decode("ascii")),
        ("fee_note_index", -1),
    ]
    request_vectors = []
    for field, value in request_cases:
        wire = json.loads(request.wire)
        wire[field] = value
        request_vectors.append(
            {
                "field": field,
                "value": value,
                "refused": refuses(lambda: Request.parse(encode(wire))),
            }
        )

    # The client's status-line predicate, copied from relay_client.Client._request:
    # "HTTP/1.1", a three-digit ASCII code whose first digit is 1..5, a phrase.
    def answered(line: str) -> bool:
        parts = line.split(" ", 2)
        return (
            len(parts) == 3
            and parts[0] == "HTTP/1.1"
            and len(parts[1]) == 3
            and parts[1].isascii()
            and parts[1].isdigit()
            and parts[1][0] in "12345"
        )

    status_lines = [
        "HTTP/1.1 200 OK",
        "HTTP/1.1 202 Accepted",
        "HTTP/1.1 429 Too Many Requests",
        "HTTP/1.1 503 Service Unavailable",
        "HTTP/1.1 4x9 Odd",
        "HTTP/1.0 429 Old",
        "HTTP/1.1 999 High",
        "HTTP/1.1 099 Low",
        "HTTP/1.1 429",
        "HTTP/2 200 OK",
        "HTTP/1.1  200 OK",
    ]
    return {
        "schema": "tos.br1.wire-corpus.v1",
        "release": {"fields": release.__dict__, "scope": release.scope},
        "canonical": [
            {"input": value, "encoded": encode(value).decode("ascii")} for value in canonical_inputs
        ],
        "parse": [{"text": text, "refused": refused} for text, refused in parse_inputs],
        "status_hash": {"token": token, "hash": status_hash(token)},
        "terms": {
            "value": terms,
            "identity": hashlib.sha256(b"TOS-BR1-QUOTE\0" + encode(terms)).hexdigest(),
            "cases": terms_vectors,
        },
        "request": {
            "value": json.loads(request.wire),
            "wire": request.wire.decode("ascii"),
            "identity": request.identity,
            "cases": request_vectors,
        },
        "limits": {
            "max_body": MAX_BODY,
            "max_request_wire": 2 * MAX_BODY,
            "http_body_limit": BODY_LIMIT,
        },
        "status_lines": [{"line": line, "answered": answered(line)} for line in status_lines],
    }


if __name__ == "__main__":
    sys.stdout.write(json.dumps(corpus(), indent=1, sort_keys=True) + "\n")
