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
            "live_controller_policy().await?",
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
        builder_calls = re.findall(
            r"nominator::new_stake_from_birth_artifact\(\s*&nominator::NewStakeParams\s*\{",
            source,
        )
        if len(builder_calls) != 1:
            fail(f"{name} reaches the verified controller birth builder {len(builder_calls)} times, expected 1")
        if "nominator::new_stake(&" in source or "nominator::new_stake_with_witness(&" in source:
            fail(f"{name} bypasses the verified controller birth artifact builder")

    runner = collapsed(pool_callers["election daemon"][0])
    if runner.count("controller_birth_state_init_boc.as_deref().ok_or_else") != 1:
        fail("election daemon no longer refuses a missing controller birth artifact")
    wallet = collapsed(pool_callers["config-wallet pool command"][0])
    path_read = wallet.find("let artifact_path = configured_birth_artifact_path(binding, &self.binding)?;")
    message = wallet.find("let msg = wallet.message(")
    if path_read < 0 or message < 0 or path_read >= message:
        fail("config-wallet birth artifact refusal no longer precedes the fee-bearing wallet message")

    policy_provider = collapsed(
        root / "tosctl/src/node-control/elections/src/providers/default.rs"
    )
    for marker in ("chain_provider.get_config_param(47).await?", "ConfigParamEnum::ConfigParamAny(47, cell) => Ok(cell)"):
        if policy_provider.count(marker) != 1:
            fail(f"shared live controller policy reader no longer uses the raw ConfigParam 47 cell: {marker}")

    direct_path = collapsed(
        root / "tosctl/src/node-control/commands/src/commands/nodectl/vote_cmd.rs"
    )
    refusal = "a wallet cannot stake directly to the PQ elector"
    if direct_path.count(refusal) != 1 or "nominator::new_stake(" in direct_path:
        fail("interactive bid does not refuse direct-to-elector PQ staking")
    if "0x654C5074" in direct_path or ".sign(" in direct_path or "Bid signed" in direct_path:
        fail("interactive bid still exposes classical stake signing")

    birth_import = collapsed(
        root / "tosctl/src/node-control/commands/src/commands/nodectl/config_bind_cmd.rs"
    )
    for marker in (
        "ImportBirth(BindImportBirthCmd)",
        "configured_pool_controller(&config, pool_name)?",
        "Transaction::construct_from_cell(root)?",
        "transaction.end_status == AccountStatus::AccStateActive",
        "!description.aborted",
        "transaction.account_id() == id",
        "message.dst_ref() == Some(controller)",
        "verified_controller_birth_witness(state, &expected_id, &code_hash)?",
        "OpenOptions::new().write(true).create_new(true).open(output)?",
        "binding.controller_birth_state_init_boc = Some(output.display().to_string())",
    ):
        if birth_import.count(marker) != 1:
            fail(f"controller birth import does not pin supplied transaction structure and binding: {marker}")
    import_command = birth_import.split("impl BindImportBirthCmd", 1)[-1].split("fn import_birth_artifact", 1)[0]
    import_position = import_command.find("import_birth_artifact(binding, &transaction, &controller, output)?")
    save_position = import_command.find("save_config(&config, path)?")
    if import_position < 0 or save_position < 0 or import_position >= save_position:
        fail("controller birth binding can be saved before its artifact is imported")

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
        "TOSCTL_PQ_STAKE_BUILDER_OK: two pool callers use node authorization and the verified birth-artifact builder with live policy reads; the direct bid refuses; deployment transaction import pins controller identity and create-new artifact binding; the multi-pool harness uses the production builder"
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
