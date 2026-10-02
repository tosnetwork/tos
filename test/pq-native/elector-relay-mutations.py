#!/usr/bin/env python3
"""Native fault controls for the bounded pool/controller/elector relay.

Each variant starts from identical source, builds the actual native artifact,
runs exactly one sandbox control, and must fail at its named assertion. Raw
logs stay in a retained directory inside .git. This never contacts a node.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
C = "crypto/smartcont/validator-controller-v1.fc"
P = "crypto/smartcont/nominator-pool/pool.fc"
E = "crypto/smartcont/elector-code.fc"
S = "crypto/smartcont/single-nominator-pool/single-nominator-code.fc"
F = "crypto/smartcont/create-elector-upgrade-proposal.fif"
PREFIX = "security_audit::relay::"
POOL = "pool_receipts_bind_actual_controller_query_hash_and_exact_forwarded_amount"
CONTROLLER = "controller_results_bind_elector_query_commitment_amount_and_wait_phase"
BOUNCE = "bounces_and_acknowledgments_cannot_change_the_wrong_or_unpaid_request"
SLOT = "one_pending_slot_and_monotonic_query_prevent_replay_and_storage_growth"
RECOVER = "recovery_tombstones_protect_later_credits_and_outstanding_receipts_block_upgrade"
MUTATIONS = [
    ("pool-source", P, [("if ((op == sr::result) & (sender_wc == -1) & (sender_addr == controller_address))", "if (op == sr::result)")], POOL, "unbound source receipt"),
    *[(f"pool-{name}", P, [(condition, "true", 2, 1)] if name == "query" else [(condition, "true")], POOL, f"unbound {name} receipt") for name, condition in [
        ("query", "(query_id == expected_query)"), ("hash", "(hash == expected_hash)"), ("forwarded", "(forwarded == expected_forwarded)")]],
    ("pool-accepted", P, [("throw_unless(sr::error, accepted == (success ? sr::sub(forwarded, sr::confirmation) : 0));", "throw_unless(sr::error, true);")], POOL, "unbound accepted receipt"),
    ("controller-source", C, [("if ((wc != -1) | (address != elector) | (phase != 0)) { return (); }", "if ((wc != -1) | (phase != 0)) { return (); }", 2, 1)], CONTROLLER, "controller unbound source"),
    ("controller-query", C, [("if (pending.null?() | (query != sequence)) { return (); }", "if (pending.null?()) { return (); }", 3, 1)], CONTROLLER, "controller unbound query"),
    *[(f"controller-{name}", C, [("throw_unless(sr::error, (hash == expected) & (received == forwarded));", replacement)], CONTROLLER, f"controller unbound {name}") for name, replacement in [
        ("hash", "throw_unless(sr::error, received == forwarded);"),
        ("received", "throw_unless(sr::error, hash == expected);")]],
    ("controller-accepted", C, [("throw_unless(sr::error, accepted == ((op == sr::ok) ? sr::sub(forwarded, sr::confirmation) : 0));", "throw_unless(sr::error, true);")], CONTROLLER, "controller unbound accepted"),
    ("bounce-prefix", C, [("ifnot (sr::bounce_matches(body, prefix)) { return (); }", "if (false) { return (); }")], BOUNCE, "unbound bounce prefix"),
    ("premature-ack", C, [("& (phase == 2)", "& true")], BOUNCE, "premature ack retains claim"),
    ("ack-owner", C, [("(address == owner)", "true")], BOUNCE, "unbound ack retains PAID"),
    ("single-flight", C, [("& pending.null?()", "& true")], SLOT, "assertion failed: tx.read_description()"),
    ("query-replay", C, [("(query > sequence)", "(query >= sequence)")], SLOT, "accepted query cannot replay"),
    ("root-pending-spend", C, [("throw_unless(ctl::error::bad_action, pending.null?());", "throw_unless(ctl::error::bad_action, true);")], "authority_and_elector_changes_keep_the_original_in_flight_creditor", "root send must not spend pending"),
    ("root-callback-namespace", C, [("throw_if(ctl::error::bad_action, sr::reserved_op(op));", "throw_if(ctl::error::bad_action, false);")], "root_cannot_forge_reserved_callbacks_even_without_a_pending_request", "root callback namespace"),
    ("owner-capital", C, [("raw_reserve(capital, 0);\n    ;; Non-bounce payment", "raw_reserve(0, 0);\n    ;; Non-bounce payment")], "the_three_real_contracts_close_the_stake_receipt_and_return_unused_budget", "third-party fees cannot fund root"),
    ("ignored-ready-action", C, [("raw_reserve(capital, 0);\n    ;; Non-bounce payment", "raw_reserve(capital, 2);\n    ;; Non-bounce payment"), ("sr::message(sr::address(owner), 0, receipt, false), 128", "sr::message(sr::address(owner), 0, receipt, false), 130")], "a_real_controller_payment_action_failure_keeps_ready_debt_for_public_retry", "failed payment action must retain READY"),
    ("bouncing-refund", C, [("sr::message(sr::address(owner), 0, receipt, false), 128", "sr::message(sr::address(owner), 0, receipt, true), 128")], "a_paid_receipt_can_be_retried_after_recipient_abort_without_repaying_principal", "assertion failed: !payment.int_header()"),
    ("public-retry-disabled", C, [("throw_unless(sr::error, phase > 0);", "throw_unless(sr::error, false);")], "a_real_controller_payment_action_failure_keeps_ready_debt_for_public_retry", "compute must actually succeed"),
    ("ignored-recovery-action", E, [("sr::message(sender, amount, reply, false), 64", "sr::message(sender, amount, reply, false), 66")], "recovery_payment_action_failure_preserves_credit_and_the_same_query_can_retry", "failed recover action cannot delete credit"),
    ("recovery-principal-repeated", E, [("sr::message(sender, 0, reply, false), 64", "sr::message(sender, amount, reply, false), 64")], RECOVER, "paid recovery repeats only caller fees"),
    ("recovery-replay", E, [("if (query == previous_query)", "if ((query == previous_query) & outstanding)"), ("(query > previous_query)", "(query >= previous_query)")], RECOVER, "acknowledged old recovery cannot consume a later credit"),
    ("recovery-upgrade-liability", E, [("& (outstanding == 0);", "& true;")], RECOVER, "only outstanding recovery blocks upgrade"),
    ("recovery-metadata-lost", E, [("active_id, active_hash, recovery_metadata());", "active_id, active_hash, null());")], "paid_recovery_metadata_survives_real_selection_configuration_rotation_and_unfreeze", "outstanding receipt book after unfreeze"),
    ("single-pool-commitment", S, [("(hash == expected_hash)", "true")], "the_single_pool_checks_the_same_bound_receipt_and_retries_a_paid_refund", "single pool unbound receipt"),
    ("bounce-source", C, [("if ((wc != -1) | (address != elector) | (phase != 0)) { return (); }", "if ((wc != -1) | (phase != 0)) { return (); }", 2, 2)], BOUNCE, "unbound bounce source"),
    ("signature-before-state", C, [("throw_unless(ctl::error::bad_signature, pq_check_mldsa44(\n    pq::stake_preimage(at, factor, controller, owner, algorithm, key_id, adnl),\n    pq::election_context(), signature_chain, key_chain));", "throw_unless(ctl::error::bad_signature, true);")], "malformed_or_underfunded_real_requests_refund_without_occupying_the_controller", "actual controller must refuse"),
    ("paid-retry-spends-capital", C, [("raw_reserve(sr::sub(pair_first(get_balance()), msg_value), 0);", "raw_reserve(0, 0);", 2, 1), ("sr::message(sr::address(owner), 0, receipt, false), 64", "sr::message(sr::address(owner), 0, receipt, false), 128")], "a_paid_receipt_can_be_retried_after_recipient_abort_without_repaying_principal", "PAID receipt retry must never contain the old principal"),
    ("pool-recovery-reack-disabled", P, [("if ((op == 0xf96f7332) & recovery_duplicate)", "if (false)")], "a_served_pool_recovers_its_real_credit_and_lost_ack_never_reallocates_rewards", "duplicate recovery must re-acknowledge"),
    ("installation-tool-marker", F, [("<b param-value <s s, 1 1 u, b> =: param-value", "<b param-value <s s, b> =: param-value")], "the_official_upgrade_proposal_carries_the_native_installation_hook", "official installation hook must be present"),
    ("nominator-reward-lost", P, [("nominators_reward = reward - validator_reward;", "nominators_reward = 0;")], "a_real_nominator_gets_its_principal_and_reward_after_the_complete_served_cycle", "pool business principal plus partitioned reward equals gross credit"),
    ("owner-tombstone-deleted", E, [("receipts~udict_set_builder(256, owner, begin_cell().store_uint(query, 64).store_coins(0).store_uint(0, 1));", "receipts~udict_delete?(256, owner);")], "recovery_receipt_storage_is_one_tombstone_per_owner_and_repeated_rounds_do_not_grow_it", "one replay tombstone per actual distinct creditor"),
    ("mature-recovery-elector-rebound", P, [("int pinned_elector = ls~load_uint(256);", "ls~load_uint(256); int pinned_elector = sr::elector();")], "a_served_pool_recovers_its_real_credit_and_lost_ack_never_reallocates_rewards", "mature recovery must use original stake elector"),
]


def digest(path):
    return {"path": str(path.relative_to(ROOT)), "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--only", action="append")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("positive jobs required")
    destination = args.out.resolve()
    destination.relative_to(ROOT / ".git")
    destination.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ, TOS_ROOT=str(ROOT), TMPDIR=str(ROOT / ".git/elector-security-audit-artifacts"),
                       CARGO_TARGET_DIR=str(ROOT / ".git/elector-security-audit-artifacts/cargo-target"))
    build = ["cmake", "--build", "build", "--target", "gen_fif", f"-j{args.jobs}"]
    test = ["cargo", "test", "--manifest-path", "tosctl/src/Cargo.toml", "-p", "contracts", "--locked",
            "--test", "elector_sandbox", f"-j{args.jobs}"]
    originals = {p: (ROOT / p).read_text() for p in {C, P, E, S, F}}
    index = {"sources": [digest(ROOT / p) for p in sorted(originals)],
             "tests": digest(ROOT / "tosctl/src/node-control/contracts/tests/elector_security_audit/relay.rs"), "runs": []}
    index["dependencies"] = [digest(ROOT / p) for p in [
        "crypto/smartcont/stake-relay.fc", "crypto/smartcont/stdlib.fc",
        "crypto/smartcont/pq.fc", "crypto/smartcont/pq-validator.fc", "crypto/smartcont/pq-bytes.fc",
        "crypto/smartcont/nominator-pool/stdlib.fc",
        "tosctl/src/node-control/contracts/tests/elector_sandbox.rs",
        "tosctl/src/node-control/contracts/tests/elector_security_audit/mod.rs",
        "tosctl/src/sandbox/src/blockchain.rs",
    ]]

    def run(command, label):
        log = destination / (label + ".log")
        with log.open("w") as output:
            result = subprocess.run(command, cwd=ROOT, env=environment, stdout=output, stderr=subprocess.STDOUT)
        return {"command": command, "exit": result.returncode, **digest(log)}

    failures = []
    try:
        baseline = run(test + [PREFIX, "--", "--nocapture"], "baseline")
        index["baseline"] = baseline
        if baseline["exit"]:
            raise RuntimeError("baseline must pass")
        for name, path, substitutions, target, assertion in MUTATIONS:
            if args.only and name not in args.only:
                continue
            changed = originals[path]
            for substitution in substitutions:
                before, after = substitution[:2]
                occurrences, maximum = substitution[2:] if len(substitution) == 4 else (1, 1)
                if changed.count(before) != occurrences:
                    raise RuntimeError(f"{name}: missing/ambiguous source anchor")
                changed = changed.replace(before, after, maximum)
            source = ROOT / path
            source.write_text(changed)
            compiled = run(build, name + "-compile")
            result = run(test + [PREFIX + target, "--", "--exact", "--nocapture"], name) if compiled["exit"] == 0 else None
            intended = bool(result and result["exit"] == 101 and "running 1 test" in (destination / (name + ".log")).read_text()
                            and assertion in (destination / (name + ".log")).read_text())
            index["runs"].append({"name": name, "source": digest(source), "compile": compiled, "test": result,
                                  "intended_assertion": assertion, "intended_failure": intended})
            print(f"{name}: intended={intended}", flush=True)
            if not intended:
                failures.append(name)
            source.write_text(originals[path])
            # Rebuild restored elector before testing a different contract's mutation.
            if path == E:
                restored_build = run(build, name + "-restore-compile")
                if restored_build["exit"]:
                    raise RuntimeError("restore build failed")
    finally:
        for path, source in originals.items():
            (ROOT / path).write_text(source)
        index["restored_build"] = run(build, "restored-compile")
        index["restored"] = run(test + [PREFIX, "--", "--nocapture"], "restored")
        index["restored_sources"] = [digest(ROOT / p) for p in sorted(originals)]
        index["unintended"] = failures
        (destination / "index.json").write_text(json.dumps(index, indent=2) + "\n")
    if failures or index["restored"]["exit"] or index["restored_build"]["exit"]:
        raise SystemExit(f"unclosed controls: {failures}")


if __name__ == "__main__":
    main()
