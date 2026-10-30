"""Targeted red controls against compiled mutants, never against a mock model."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SMARTCONT = ROOT / "crypto/smartcont"
# Mutable sources: the environment variable each suite reads its source path from, and the
# files the source includes by relative path, copied next to the mutant unchanged.
SOURCES = {
    "vault": (SMARTCONT / "treasury-vault-code.fc", "TREASURY_SOURCE", ()),
    "multisig": (
        SMARTCONT / "pq-multisig-code.fc",
        "PQ_MULTISIG_SOURCE",
        ("pq-quorum-signatures.fc", "pq-bytes.fc", "pq.fc"),
    ),
}
SUITES = {
    "test_native.py": "TreasuryTests",
    "test_wallets.py": "WalletTests",
    "test_pq_wallets.py": "PqWalletTests",
    "test_pq_cold.py": "PqColdTests",
}
RESULT_VARIABLES = (
    "TREASURY_RESULTS",
    "TREASURY_WALLET_RESULTS",
    "TREASURY_PQ_WALLET_RESULTS",
    "TREASURY_PQ_COLD_RESULTS",
)


def control(name, old, new, test, suite="test_native.py", source="vault"):
    return dict(name=name, old=old, new=new, test=test, suite=suite, source=source)


MUTATIONS = (
    control(
        "control_funding",
        "throw_unless(tv::funding, msg_value >= tv::control_value);",
        ";; removed control-message funding guard",
        "test_funding_and_storage_reserve",
    ),
    control(
        "guardian",
        "throw_unless(tv::sender, equal_slice_bits(sender, v_guardian));",
        ";; removed guardian guard",
        "test_required_guardian",
    ),
    control(
        "single_limit",
        "throw_unless(tv::single_limit, amount <= per);",
        ";; removed per-payment ceiling",
        "test_per_payment_limit",
    ),
    control(
        "window_limit",
        "throw_unless(tv::window_limit, spent <= window);",
        ";; removed window ceiling",
        "test_split_payments_hit_window_limit",
    ),
    control(
        "total_limit",
        "throw_unless(tv::total_limit, cumulative <= total);",
        ";; removed cumulative ceiling",
        "test_window_refresh_does_not_refresh_total",
    ),
    control(
        "timelock",
        "throw_unless(tv::timelock, now() >= ready);",
        ";; removed management delay",
        "test_management_timelock",
    ),
    control(
        "nonce",
        "throw_unless(tv::nonce, s~load_uint(64) == nonce);",
        "s~load_uint(64);",
        "test_request_nonce",
    ),
    control(
        "principal_reserve",
        "raw_reserve(remaining, 0);",
        ";; removed principal reserve",
        "test_action_failure_rolls_back_accounting",
    ),
    control(
        "action_atomicity",
        "send_raw_message(outgoing, 1);",
        "send_raw_message(outgoing, 3);",
        "test_action_failure_rolls_back_accounting",
    ),
    control(
        "cold_authority",
        "throw_unless(tv::authority, equal_slice_bits(cold, v_cold));",
        ";; removed cold authority immutability",
        "test_cold_authority_is_immutable",
    ),
    control(
        "veto_self_guardian",
        "throw_unless(tv::sender, equal_slice_bits(guardian, v_guardian));",
        ";; removed guardian self-replacement veto guard",
        "test_replaced_guardian_cannot_veto_its_replacement",
    ),
    control(
        "veto_self_pauser",
        "throw_unless(tv::sender, equal_slice_bits(pauser, v_pauser));",
        ";; removed pauser self-replacement veto guard",
        "test_replaced_pauser_cannot_veto_its_replacement",
    ),
    control(
        "token_attachment_required",
        "throw_unless(tv::funding, attachment > 0);",
        ";; removed Token attachment requirement",
        "test_raw_payload_attachment_and_amount_guards",
    ),
    control(
        "native_attachment_forbidden",
        "throw_unless(tv::funding, attachment == 0);",
        ";; removed native attachment prohibition",
        "test_raw_payload_attachment_and_amount_guards",
    ),
    control(
        "attachment_funding",
        "throw_unless(tv::funding, msg_value >= tv_checked_add(attachment, tv::control_value));",
        ";; removed guardian attachment funding guard",
        "test_token_attachment_must_be_funded_by_the_guardian",
    ),
    control(
        "window_limit_token",
        "throw_unless(tv::window_limit, spent <= window);",
        ";; removed window ceiling",
        "test_token_window_and_total_limits",
    ),
    control(
        "guardian_pq_wallet",
        "throw_unless(tv::sender, equal_slice_bits(sender, v_guardian));",
        ";; removed guardian guard",
        "test_pq_business_wallet_cannot_approve_its_own_proposal",
        "test_pq_wallets.py",
    ),
    control(
        "guardian_wallet",
        "throw_unless(tv::sender, equal_slice_bits(sender, v_guardian));",
        ";; removed guardian guard",
        "test_business_wallet_cannot_approve_its_own_proposal",
        "test_wallets.py",
    ),
    control(
        "multisig_quorum",
        "pq_quorum::require_quorum(config, hash, signatures);",
        ";; removed quorum requirement",
        "test_threshold_and_membership_are_enforced_before_verification",
        "test_pq_cold.py",
        "multisig",
    ),
    control(
        "multisig_seqno",
        "save_data(verifiers, count, quorum, seqno + 1);",
        "save_data(verifiers, count, quorum, seqno);",
        "test_request_binding_and_replay",
        "test_pq_cold.py",
        "multisig",
    ),
    control(
        "multisig_expiry",
        "pq_quorum::require_not_expired(valid_until);",
        ";; removed expiry check",
        "test_request_binding_and_replay",
        "test_pq_cold.py",
        "multisig",
    ),
    control(
        "multisig_deployment_check",
        "[_, int checked, _] = pq_quorum::config(verifiers, quorum);",
        "int checked = count;",
        "test_deployment_check_rejects_a_bad_initial_configuration",
        "test_pq_cold.py",
        "multisig",
    ),
    control(
        "multisig_single_send_quote",
        "const int fee::gas_per_signature = 12000;",
        "const int fee::gas_per_signature = 4000;",
        "test_each_quorum_funds_one_governance_send_at_exact_quote",
        "test_pq_cold.py",
        "multisig",
    ),
    control(
        "multisig_configuration_quote",
        "const int fee::gas_per_signature = 12000;",
        "const int fee::gas_per_signature = 4000;",
        "test_each_quorum_funds_all_configuration_changes_at_exact_quote",
        "test_pq_cold.py",
        "multisig",
    ),
    control(
        "multisig_fee_limit",
        "throw_unless(error::fee_range, (limit >= 0) & (limit <= fee::max_coins));",
        ";; removed checked fee limit guard",
        "test_checked_fee_arithmetic_boundaries",
        "test_pq_cold.py",
        "multisig",
    ),
    control(
        "multisig_fee_value",
        "throw_unless(error::fee_range, (value >= 0) & (value <= limit));",
        ";; removed checked fee value guard",
        "test_checked_fee_arithmetic_boundaries",
        "test_pq_cold.py",
        "multisig",
    ),
    control(
        "multisig_fee_add_result",
        "return checked_fee_value(a + b, limit);",
        "return a + b;",
        "test_checked_fee_arithmetic_boundaries",
        "test_pq_cold.py",
        "multisig",
    ),
    control(
        "multisig_fee_mul_result",
        "return checked_fee_value(a * b, limit);",
        "return a * b;",
        "test_checked_fee_arithmetic_boundaries",
        "test_pq_cold.py",
        "multisig",
    ),
    control(
        "multisig_quote_admission",
        "msg_value >= required_value(quorum, actions, kind == kind::configure)",
        "true",
        "test_each_quorum_funds_one_governance_send_at_exact_quote",
        "test_pq_cold.py",
        "multisig",
    ),
)


def main():
    originals = {name: path.read_text() for name, (path, _, _) in SOURCES.items()}
    receipts = []
    for m in MUTATIONS:
        original = originals[m["source"]]
        if original.count(m["old"]) != 1:
            raise RuntimeError(
                f"{m['name']}: expected one mutation anchor, found {original.count(m['old'])}"
            )
        _, variable, includes = SOURCES[m["source"]]
        script = Path(__file__).with_name(m["suite"])
        with tempfile.TemporaryDirectory(prefix=f"treasury-{m['name']}-") as temp:
            mutant = Path(temp) / "mutant.fc"
            mutant.write_text(original.replace(m["old"], m["new"], 1))
            for name in includes:
                shutil.copyfile(SMARTCONT / name, Path(temp) / name)
            env = dict(os.environ)
            env[variable] = str(mutant)
            for key in RESULT_VARIABLES:
                env.pop(key, None)
            result = subprocess.run(
                [sys.executable, str(script), f"{SUITES[m['suite']]}.{m['test']}"],
                env=env,
                text=True,
                capture_output=True,
                timeout=300,
            )
            output = result.stdout + result.stderr
            # A compiler error, missing library or test discovery error is NOT
            # a successful mutation control. The exact regression must assert.
            if result.returncode == 0 or f"FAIL: {m['test']}" not in output:
                raise RuntimeError(f"{m['name']}: missing targeted red result\n{output[-8000:]}")
            receipts.append(
                dict(
                    name=m["name"],
                    source=m["source"],
                    suite=m["suite"],
                    test=m["test"],
                    exit_code=result.returncode,
                    source_sha256=hashlib.sha256(mutant.read_bytes()).hexdigest(),
                    targeted_failure=True,
                )
            )
            print(f"RED CONTROL {m['name']}: {m['test']}", flush=True)
    report = dict(
        baseline_source_sha256={
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, (path, _, _) in SOURCES.items()
        },
        controls=receipts,
    )
    target = os.environ.get("TREASURY_MUTATION_RESULTS")
    if target:
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        Path(target).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
