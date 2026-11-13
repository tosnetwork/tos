# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Helpers shared by the crypto migration and cross-check scripts (crypto_*.py)."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, cast

Json = dict[str, Any]

# The consensus key-id domain of crypto/pq/pq-consensus.h. Only used to build inputs that the
# generators built the same way; every effect still comes from the C++ reference.
KEY_ID_DOMAIN = b"TOS-PQ-CONSENSUS-KEY-v1"
MLDSA44_PUBLIC_KEY_BYTES = 1312


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def hexb(text: str) -> str:
    """Hex text to base64."""
    return b64(bytes.fromhex(text))


def fill(byte: int) -> str:
    return f"{byte:02x}" * 32


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive_key_id(algorithm: int, public_key: bytes) -> str:
    return sha256_hex(KEY_ID_DOMAIN + algorithm.to_bytes(2, "little") + public_key)


def ctx(
    scheme: str, operation: str, inputs: Mapping[str, Any], edits: list[Json] | None = None
) -> Json:
    out: Json = {"scheme": scheme, "operation": operation, "inputs": dict(inputs)}
    if edits:
        out["edits"] = edits
    return out


def entry(fixture_id: str, context: Json, note: str | None = None) -> Json:
    out: Json = {"fixture_id": fixture_id, "context": context}
    if note:
        out["note"] = note
    return out


def write_contexts(path: Path, entries: Iterable[Json]) -> int:
    items = list(entries)
    ids = [e["fixture_id"] for e in items]
    if len(ids) != len(set(ids)):
        raise SystemExit(f"{path}: duplicate fixture ids")
    if not items:
        raise SystemExit(f"{path}: no contexts")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in items))
    return len(items)


def load_fixtures(path: Path) -> dict[str, Json]:
    """Fixtures of one family by id, with blob references resolved."""
    blobs_file = path.with_name(path.stem + ".blobs.json")
    blobs: dict[str, str] = (
        cast(dict[str, str], json.loads(blobs_file.read_text())) if blobs_file.exists() else {}
    )

    def resolve(value: Any) -> Any:
        if isinstance(value, dict):
            item = cast(dict[str, Any], value)
            if set(item) == {"blob"}:
                return blobs[cast(str, item["blob"])]
            return {k: resolve(v) for k, v in item.items()}
        if isinstance(value, list):
            return [resolve(v) for v in cast(list[Any], value)]
        return value

    out: dict[str, Json] = {}
    for line in path.read_text().splitlines():
        fixture = cast(Json, json.loads(line))
        fixture["context"] = resolve(fixture["context"])
        out[fixture["metadata"]["fixture_id"]] = fixture
    return out


class Checker:
    """Counts rows and differences; one line per difference."""

    def __init__(self, family: str) -> None:
        self.family = family
        self.rows = 0
        self.differences = 0

    def expect(self, fixture_id: str, expected: object, actual: object) -> None:
        self.rows += 1
        if expected != actual:
            self.differences += 1
            print(f"DIFF {self.family}/{fixture_id}: frozen {expected!r} fixture {actual!r}")

    def missing(self, fixture_id: str) -> None:
        self.rows += 1
        self.differences += 1
        print(f"DIFF {self.family}/{fixture_id}: no fixture for this frozen row")

    def done(self) -> int:
        print(f"{self.family}: checked {self.rows} rows, {self.differences} differences")
        return self.differences


def effects_of(fixtures: Mapping[str, Json], fixture_id: str, check: Checker) -> Json | None:
    fixture = fixtures.get(fixture_id)
    if fixture is None:
        check.missing(fixture_id)
        return None
    return cast(Json, fixture["effects"])


def require_all_used(fixtures: Mapping[str, Json], used: set[str], check: Checker) -> None:
    for fixture_id in sorted(set(fixtures) - used):
        check.rows += 1
        check.differences += 1
        print(f"DIFF {check.family}/{fixture_id}: fixture without a frozen row")


def rows(path: Path, sep: str = "\t") -> list[list[str]]:
    return [
        line.split(sep)
        for line in path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
