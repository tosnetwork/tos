#!/usr/bin/env python3
"""Pin the node-produced stake authorization's self-consistent TL fields."""

from __future__ import annotations

import sys
from pathlib import Path

DECLARATION = (
    "engine.validator.pqStakeAuthorization validator_id:int256 key_id:int256 "
    "algorithm_id:int public_key:bytes signature:bytes = engine.validator.PqStakeAuthorization;"
)
FUNCTION = (
    "engine.validator.createPqStakeAuthorization election_date:int max_factor:int "
    "adnl_addr:int256 stake_owner:int256 = engine.validator.PqStakeAuthorization;"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"PQ_STAKE_AUTH_RESPONSE_FAILURE: {message}")


def main(root: Path) -> None:
    for relative in ("tl/generate/scheme/tos_api.tl", "tosctl/src/tl/api/tl/tos_api.tl"):
        source = (root / relative).read_text(encoding="utf-8")
        require(DECLARATION in source, f"{relative} lost the five-field authorization response")
        require(FUNCTION in source, f"{relative} lost the authorization request")
    engine = " ".join(
        (root / "validator-engine/validator-engine.cpp").read_text(encoding="utf-8").split()
    )
    start = engine.index("class PqStakeAuthorizationCreator")
    end = engine.index("class ValidatorProposalVoteCreator", start)
    creator = engine[start:end]
    require(
        "sign_stake_authorization(*self.signer" in creator,
        "stake signature no longer comes from the local signer",
    )
    require(
        "const auto &held_key = self.signer->consensus_key();" in creator,
        "algorithm and public key no longer come from the signing key",
    )
    require(
        "self.validator_id.value, authorization->key_id, static_cast<td::int32>(held_key.algorithm_id), "
        "td::BufferSlice(held_key.public_key), td::BufferSlice(authorization->signature.signature)"
        in creator,
        "response no longer binds identity, key id, algorithm, public key and signature together",
    )
    generated = (
        root / "tosctl/src/tl/api/src/tos/engine/validator/pqstakeauthorization.rs"
    ).read_text(encoding="utf-8")
    for field in ("validator_id", "key_id", "algorithm_id", "public_key", "signature"):
        require(f"pub {field} :" in generated, f"generated Rust response is missing {field}")
    print(
        "PQ_STAKE_AUTH_RESPONSE_OK: both TL schemas and generated Rust carry five fields from one node signer"
    )


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise RuntimeError("expected repository root")
        main(Path(sys.argv[1]))
    except (OSError, ValueError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
