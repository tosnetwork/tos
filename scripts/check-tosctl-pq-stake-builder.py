#!/usr/bin/env python3
"""Pin the two stake callers to node authorization for the staking account."""

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
    stake_callers = {
        "election daemon": (
            root / "tosctl/src/node-control/elections/src/runner.rs",
            "authorization.validator_id == src_addr,",
        ),
        "config-wallet stake command": (
            root / "tosctl/src/node-control/commands/src/commands/nodectl/config_wallet_cmd.rs",
            "authorization.validator_id == route.staking_account_id,",
        ),
    }

    # Both callers ask the node for an ML-DSA-44 authorization over the account the
    # stake is sent from, refuse one made for any other account before a message is
    # built, and build the body with the shared builders: the pool body when a pool
    # sends the stake, the elector body when the wallet sends it itself.
    for name, (path, identity_check) in stake_callers.items():
        source = collapsed(path)
        for marker in (
            identity_check,
            "create_pq_stake_authorization(",
            "nominator::new_stake(&params)",
            "nominator::elector_new_stake(&params)",
        ):
            if source.count(marker) != 1:
                fail(f"{name} has {source.count(marker)} occurrences of {marker!r}, expected 1")
        if "0x654C5074" in source or ".sign(" in source:
            fail(f"{name} still contains the classical stake tag or a local signer call")
        if "new_stake_with_witness" in source or "birth" in source:
            fail(f"{name} still builds a stake with a controller birth witness")

    wallet = collapsed(stake_callers["config-wallet stake command"][0])
    roles_read = wallet.find(
        'live_pool.get_roles().await.context("read live single-nominator pool roles")?'
    )
    payload = wallet.find("build_manual_stake_payload(")
    message = wallet.find("let msg = wallet.message(")
    if not (0 <= roles_read < payload < message):
        fail("config-wallet does not check live pool roles and build the order before the wallet message")
    stake_command = wallet.split("impl WalletStakeCmd", 1)[1]
    seqno_check = stake_command.find("let initial_seqno = require_observable_wallet_seqno(")
    broadcast = stake_command.find("provider.send_boc(&msg_boc).await")
    if seqno_check < 0 or broadcast < 0 or seqno_check >= broadcast:
        fail(
            "config-wallet stake can send without a wallet type and seqno that chain RPC can observe"
        )

    # The CLI embeds this V1R3 code; chain RPC must recognize its cell hash or
    # getWalletInformation returns wallet=false/seqno=null forever.
    v1r3_hash = "587cc789eff1c84f46ec3797e45fc809a14ff5ae24f1e0c7a6a99cc9dc9061ff"
    wallet_code = collapsed(
        root / "tosctl/src/node-control/contracts/src/wallet/wallet_contract.rs"
    )
    account_model = collapsed(root / "validator-engine/json-rpc-account-model.cpp")
    if v1r3_hash not in wallet_code or v1r3_hash.upper() not in account_model:
        fail("tosctl V1R3 code hash is not pinned in both the wallet test and chain RPC recognizer")
    parser = collapsed(root / "tosctl/src/node-control/common/src/tvm_stack_parser.rs")
    list_parser = parser.split("pub fn list_or_empty", 1)[1].split("pub fn tuple", 1)[0]
    for marker in (
        "StackEntry::Tvm_StackEntryTuple(_) =>",
        "slots.len() == 2",
        "self.i64(index)? == 0",
        'number.number.number() == "0"',
        "stack cons list has a non-null tail",
    ):
        if marker not in list_parser:
            fail(f"JSON-RPC TVM cons-list parser lost its strict {marker!r} check")
    if (
        re.search(
            r"StackEntry::Tvm_StackEntryList\(list\)\s+if\s+list\.list\.elements\(\)\.is_empty\(\)\s*=>",
            list_parser,
        )
        is None
    ):
        fail("JSON-RPC TVM cons-list parser no longer requires an empty List tail")

    policy_provider = collapsed(root / "tosctl/src/node-control/elections/src/providers/default.rs")
    if policy_provider.count("chain_provider.get_config_param(15).await?") != 1:
        fail("election parameters no longer come from the live chain provider")
    if "client.get_config_param(15)" in policy_provider:
        fail("election parameters are routed to validator control instead of chain JSON-RPC")
    if policy_provider.count("chain_provider.send_boc(msg_boc).await") != 1:
        fail("stake BOC is not broadcast through the chain provider")
    if "client.send_boc(msg_boc)" in policy_provider:
        fail("stake BOC is routed to validator control instead of chain JSON-RPC")

    direct_path = collapsed(
        root / "tosctl/src/node-control/commands/src/commands/nodectl/vote_cmd.rs"
    )
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
        "TOSCTL_PQ_STAKE_BUILDER_OK: the election daemon and the config-wallet command request node authorization for the staking account, refuse any other before building, and use the shared pool and elector builders; election parameters and stake BOC use chain JSON-RPC; config-wallet checks live pool roles and an observable wallet seqno before sending; tosctl V1R3 code hash appears in the wallet test and chain RPC recognizer; TVM cons lists require pairs and an actual nil tail; the interactive bid signs nothing; the multi-pool harness uses the production builder"
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
