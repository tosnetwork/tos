#!/usr/bin/env python3
"""Pin the two pool stake callers to node authorization and refuse direct bids."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise RuntimeError(f"TOSCTL_PQ_STAKE_BUILDER_FAILURE: {message}")


def collapsed(path: Path) -> str:
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]).resolve()
    pool_callers = {
        "election daemon": (
            root / "tosctl/src/node-control/elections/src/runner.rs",
            "cannot stake directly from a wallet to the PQ elector",
        ),
        "config-wallet pool command": (
            root / "tosctl/src/node-control/commands/src/commands/nodectl/config_wallet_cmd.rs",
            "let pool_address = resolve_pool_address(pool_cfg, &wallet_address)?;",
        ),
    }

    for name, (path, route_marker) in pool_callers.items():
        source = collapsed(path)
        for marker in (
            route_marker,
            "create_pq_stake_authorization(",
            "nominator::new_stake(&nominator::NewStakeParams {",
            "validator_pubkey: authorization.public_key.as_slice()"
            if name == "election daemon"
            else "validator_pubkey: &authorization.public_key",
            "signature: authorization.signature.as_slice()"
            if name == "election daemon"
            else "signature: &authorization.signature",
        ):
            if source.count(marker) != 1:
                fail(f"{name} has {source.count(marker)} occurrences of {marker!r}, expected 1")
        if "0x654C5074" in source or ".sign(" in source:
            fail(f"{name} still contains the classical stake tag or a local signer call")

    direct_path = collapsed(
        root / "tosctl/src/node-control/commands/src/commands/nodectl/vote_cmd.rs"
    )
    refusal = "a wallet cannot stake directly to the PQ elector"
    if direct_path.count(refusal) != 1 or "nominator::new_stake(" in direct_path:
        fail("interactive bid does not refuse direct-to-elector PQ staking")
    if "0x654C5074" in direct_path or ".sign(" in direct_path or "Bid signed" in direct_path:
        fail("interactive bid still exposes classical stake signing")

    multi_pool_test = collapsed(
        root / "tosctl/src/node-control/contracts/tests/nominator_pool_sandbox.rs"
    )
    marker = "new_stake(&NewStakeParams {"
    if multi_pool_test.count(marker) != 1:
        fail(
            "multi-nominator pool harness reaches the production PQ stake builder "
            f"{multi_pool_test.count(marker)} times, expected 1"
        )

    print(
        "TOSCTL_PQ_STAKE_BUILDER_OK: two pool callers use node authorization, the direct bid refuses, and the multi-pool harness uses the production builder"
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
