"""Deterministic post-quantum initial validators for repository test networks."""

from __future__ import annotations

import hashlib
from typing import Protocol


class InitialPqValidatorNode(Protocol):
    def make_initial_pq_validator(self, validator_id: bytes, seed: bytes) -> None: ...


_DOMAIN = b"tos-test-pq-initial-validator-v1\x00"


def deterministic_pq_initial_validator_seed(index: int) -> bytes:
    """Return the stable test-only consensus seed before a controller is derived."""
    if isinstance(index, bool) or not 0 <= index < 2**32:
        raise ValueError(f"post-quantum initial validator index is outside uint32: {index!r}")
    encoded_index = index.to_bytes(4, "big")
    return hashlib.sha256(_DOMAIN + b"consensus-seed\x00" + encoded_index).digest()


def make_deterministic_pq_initial_validator(
    node: InitialPqValidatorNode, index: int, *, validator_id: bytes | None = None
) -> None:
    """Provision a stable test key, optionally bound to its controller address."""
    seed = deterministic_pq_initial_validator_seed(index)
    encoded_index = index.to_bytes(4, "big")
    if validator_id is None:
        validator_id = hashlib.sha256(_DOMAIN + b"validator-id\x00" + encoded_index).digest()
    if len(validator_id) != 32:
        raise ValueError("post-quantum validator id must be 32 bytes")
    node.make_initial_pq_validator(validator_id, seed)
