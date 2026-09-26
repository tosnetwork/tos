"""Load explicit local Genesis custody inputs without claiming final signatures.

The manifest binds raw input bytes. It is a development freeze, not a signed
Genesis or a trust anchor. Private bytes never appear in the public receipt.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any


SCHEMA = "tos.z01.fixed-local-inputs.v1"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load(path: Path, expected_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected_sha256,
            "fixed input manifest differs from committed SHA-256")
    manifest = json.loads(raw)
    require(manifest.get("schema") == SCHEMA, "wrong fixed input schema")
    require(manifest.get("scope") == "development-fixed",
            "local input freeze cannot claim final signed Genesis")
    epoch = manifest.get("genesis_time")
    require(type(epoch) is int and 0 <= epoch <= 0xFFFF_FFFF,
            "fixed Genesis time must fit uint32")
    validators = manifest.get("validators")
    require(isinstance(validators, list) and len(validators) == 4,
            "fixed Genesis needs exactly four validator identities")

    def secret(entry: Any, label: str) -> bytes:
        require(isinstance(entry, dict), f"missing custody commitment: {label}")
        require(isinstance(entry.get("path"), str), f"missing custody path: {label}")
        candidate = path.parent / entry["path"]
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = os.open(candidate, flags)
        with os.fdopen(fd, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            require(stat.S_ISREG(metadata.st_mode), f"custody input is not regular: {label}")
            require(metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o600,
                    f"custody input must be owner-only0600: {label}")
            data = handle.read(33)
        require(len(data) == 32, f"custody input must be exactly32bytes: {label}")
        require(hashlib.sha256(data).hexdigest() == entry.get("sha256"),
                f"custody input differs from commitment: {label}")
        return data

    wallet = secret(manifest.get("wallet_seed"), "wallet")
    private_validators = []
    seen_ids: set[str] = set()
    seen_adnl: set[bytes] = set()
    seen_pq: set[bytes] = set()
    for index, entry in enumerate(validators):
        require(isinstance(entry, dict), f"invalid validator: {index}")
        identity = entry.get("validator_id")
        require(isinstance(identity, str) and len(identity) == 64
                and all(c in "0123456789abcdef" for c in identity),
                f"invalid validator ID: {index}")
        adnl = secret(entry.get("adnl_seed"), f"validator{index}.adnl")
        pq = secret(entry.get("pq_seed"), f"validator{index}.pq")
        require(identity not in seen_ids and adnl not in seen_adnl and pq not in seen_pq,
                "fixed validator identities and custody seeds must be distinct")
        seen_ids.add(identity)
        seen_adnl.add(adnl)
        seen_pq.add(pq)
        private_validators.append({"validator_id": bytes.fromhex(identity),
                                   "adnl_seed": adnl, "pq_seed": pq})
    require(seen_adnl.isdisjoint(seen_pq),
            "ADNL and PQ custody roles must use distinct seeds")
    require(wallet not in seen_adnl and wallet not in seen_pq,
            "wallet custody must be distinct from validator custody")
    public = {"schema": SCHEMA, "scope": "development-fixed",
              "manifest_path": str(path.resolve()), "manifest_sha256": expected_sha256,
              "genesis_time": epoch, "wallet_commitment": manifest["wallet_seed"]["sha256"],
              "validators": [{"validator_id": entry["validator_id"],
                              "adnl_seed_commitment": entry["adnl_seed"]["sha256"],
                              "pq_seed_commitment": entry["pq_seed"]["sha256"]}
                             for entry in validators],
              "commitment_encoding": "SHA-256 of exactly32rawseedbytes",
              "final_signed_genesis": False}
    private = {"genesis_time": epoch, "wallet_seed": wallet,
               "validators": private_validators}
    return public, private
