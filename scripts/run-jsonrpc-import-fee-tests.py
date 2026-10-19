#!/usr/bin/env python3
"""Run the import-fee regressions and refuse a missing or empty selection."""

import re
import subprocess
import sys

EXPECTED = {
    "Test_JsonRpcImportFee_storage_and_emulation_use_the_same_execution_time",
    "Test_JsonRpcImportFee_the_config_carries_the_genesis_forwarding_prices",
    "Test_JsonRpcImportFee_deploying_an_undeployed_wallet_prices_its_state_init",
    "Test_JsonRpcImportFee_an_active_wallet_send_without_state_init_is_priced_without_one",
    "Test_JsonRpcImportFee_a_state_init_sent_to_an_active_wallet_is_still_priced",
    "Test_JsonRpcImportFee_unfreezing_a_frozen_wallet_prices_its_state_init",
    "Test_JsonRpcImportFee_a_state_init_raises_the_import_fee",
    "Test_JsonRpcImportFee_requests_the_executor_rejects_are_refused",
    "Test_JsonRpcImportFee_a_state_init_without_code_is_refused_for_its_own_address",
    "Test_JsonRpcImportFee_unfreezing_into_another_state_follows_the_global_version",
    "Test_JsonRpcImportFee_a_suspended_address_is_not_deployed",
    "Test_JsonRpcImportFee_suspension_expires_at_execution_time_not_shard_proof_time",
    "Test_JsonRpcImportFee_the_estimate_runs_the_code_the_executor_runs",
    "Test_JsonRpcImportFee_a_special_account_imports_for_free",
    "Test_JsonRpcImportFee_a_workchain_with_a_custom_compute_phase_is_refused",
    "Test_JsonRpcImportFee_a_message_that_is_not_an_inbound_external_is_refused",
    "Test_JsonRpcImportFee_the_message_depth_limit_matches_the_executor",
    "Test_JsonRpcImportFee_the_message_cell_limit_matches_the_executor",
    "Test_JsonRpcImportFee_the_message_bit_limit_matches_the_executor",
}


def main():
    try:
        result = subprocess.run(
            [sys.argv[1], "--filter", "+JsonRpcImportFee"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=90,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"Import-fee regression runner failed: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(result.stdout)
    output = result.stdout.decode("utf-8", errors="replace")
    observed = re.findall(r"Running test (Test_JsonRpcImportFee_\w+)\.\.\.", output)
    if (
        result.returncode != 0
        or set(observed) != EXPECTED
        or len(observed) != len(EXPECTED)
        or f"{len(EXPECTED)} test(s) passed" not in output
    ):
        print(
            f"Import-fee regressions incomplete: expected {len(EXPECTED)} passing cases; "
            f"observed {len(observed)}, missing {sorted(EXPECTED - set(observed))}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
