#!/usr/bin/env python3
"""Pin election read routing to chain RPC, not the validator control socket."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"TOSCTL_ELECTION_CHAIN_READS_FAILURE: {message}")


def collapsed(path: Path) -> str:
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))


def main() -> None:
    root = Path(sys.argv[1]).resolve()
    provider = collapsed(root / "tosctl/src/node-control/elections/src/providers/default.rs")
    for operation, marker in {
        "account balance": "self.chain_provider.get_balance(&address).await?",
        "current validator set": "self.chain_provider.get_config_param(34).await?",
        "next validator set": "self.chain_provider .get_optional_config_param(36)",
        "exact validator-set hash": "self.chain_provider.get_config_param_cell(34).await?",
    }.items():
        require(provider.count(marker) == 1, f"{operation} is not read once through chain RPC")
    require(
        not re.search(r"self\.client\.(?:get_account_state|get_config_param)\s*\(", provider),
        "account or config read still uses a lite-server query on the control socket",
    )

    chain = collapsed(root / "tosctl/src/node-control/contracts/src/chain_provider.rs")
    rpc = collapsed(root / "tosctl/src/node-control/chain-rpc-client/src/v2/client_json_rpc.rs")
    for marker in (
        "self.client.get_config_param_cell(param_id).await",
        "self.client.get_optional_config_param(param_id).await",
    ):
        require(marker in chain, f"chain provider lost {marker!r}")
    for marker in (
        'json_rpc_read("getConfigParam", serde_json::json!({"config_id": param_id}))',
        "decode_config_param_cell(config_info)",
        "Ok(read_boc(boc)?.withdraw_single_root()?)",
    ):
        require(marker in rpc, f"exact config-cell read lost {marker!r}")
    print(
        "TOSCTL_ELECTION_CHAIN_READS_OK: account balance, ConfigParam 34/36, and exact "
        "ConfigParam 34 cell use chain RPC; no lite-server read uses the control socket"
    )


if __name__ == "__main__":
    try:
        main()
    except (IndexError, OSError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
