import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser(
    description="Require runtime assertion failures after removing note safety checks"
)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--target-dir", type=Path)
args = parser.parse_args()
repo = Path(__file__).resolve().parents[3]
root = args.output.resolve()
root.mkdir(parents=True, exist_ok=True)
env = {
    **os.environ,
    "CARGO_BUILD_JOBS": "2",
    "CARGO_TARGET_DIR": str(
        args.target_dir.resolve() if args.target_dir else root / "native-target"
    ),
}
base = [
    "cargo",
    "+1.97.1",
    "test",
    "--locked",
    "--manifest-path",
    "tools/shielded-pool-mobile/Cargo.toml",
]
results = []
for name, path, before, after, suite, test in [
    (
        "spent-reconciliation",
        repo / "tools/shielded-pool-mobile/src/lib.rs",
        "recovered.reconcile_spent(instance, published).map_err(|_| Error::Crypto)?;",
        "// mutation control: omit spent reconciliation",
        "core",
        "decrypts_real_payload_and_reconciles_spent_nullifiers",
    ),
    (
        "note-body-binding",
        repo / "tools/shielded-pool-wallet/src/import.rs",
        "if note_body != slot.note_body {",
        "if false && note_body != slot.note_body {",
        "core",
        "authenticated_note_body_mismatch_is_not_balance",
    ),
    (
        "pool-depth-bound",
        repo / "tools/shielded-pool-mobile/src/pool.rs",
        ".set_max_cell_depth(MAX_BOC_DEPTH)",
        "",
        "pool",
        "deep_frontier_is_rejected_before_layout_decode",
    ),
    (
        "pool-cell-bound",
        repo / "tools/shielded-pool-mobile/src/pool.rs",
        "if cells > MAX_BOC_CELLS as u64 {",
        "if false && cells > MAX_BOC_CELLS as u64 {",
        "pool",
        "cell_limit_rejects_a_valid_shallow_boc",
    ),
    (
        "pool-total-size-bound",
        repo / "tools/shielded-pool-mobile/src/pool.rs",
        "if declared_total > bytes.len() as u64 {",
        "if false && declared_total > bytes.len() as u64 {",
        "pool",
        "total_cell_bytes_cannot_wrap_on_a_32_bit_target",
    ),
    (
        "history-hash",
        repo / "tools/shielded-pool-mobile/src/history.rs",
        "root.repr_hash().as_array() != &expected_hash",
        "false",
        "history",
        "wrong_hash_lt_account_state_and_time_are_each_rejected",
    ),
    (
        "history-lt",
        repo / "tools/shielded-pool-mobile/src/history.rs",
        "transaction.logical_time() != expected_lt",
        "false",
        "history",
        "wrong_hash_lt_account_state_and_time_are_each_rejected",
    ),
    (
        "history-account",
        repo / "tools/shielded-pool-mobile/src/history.rs",
        "transaction.account_id() != &chain_block::SliceData::from_raw(account_id.to_vec(), 256)",
        "false",
        "history",
        "wrong_hash_lt_account_state_and_time_are_each_rejected",
    ),
    (
        "history-state",
        repo / "tools/shielded-pool-mobile/src/history.rs",
        "update.new_hash.as_array() != &post_state_hash",
        "false",
        "history",
        "wrong_hash_lt_account_state_and_time_are_each_rejected",
    ),
    (
        "history-time",
        repo / "tools/shielded-pool-mobile/src/history.rs",
        "transaction.now() > maximum_time",
        "false",
        "history",
        "wrong_hash_lt_account_state_and_time_are_each_rejected",
    ),
    (
        "history-previous-link",
        repo / "tools/shielded-pool-mobile/src/history.rs",
        "previous_lt >= expected_lt || (previous_lt == 0) != (previous_hash.as_array() == &[0; 32])",
        "false",
        "history",
        "inconsistent_and_non_descending_previous_links_are_rejected",
    ),
    (
        "replay-checkpoint",
        repo / "tools/shielded-pool-mobile/src/replay.rs",
        "ledger.checkpoint() != self.expected",
        "false",
        "replay",
        "all_six_checkpoint_mismatches_reject_the_entire_result",
    ),
    (
        "replay-head-hash",
        repo / "tools/shielded-pool-mobile/src/replay.rs",
        "last.hash == self.head.last_hash",
        "true",
        "replay",
        "truncated_history_or_wrong_proven_head_cannot_finish",
    ),
    (
        "replay-head-lt",
        repo / "tools/shielded-pool-mobile/src/replay.rs",
        "last.lt == self.head.last_lt",
        "true",
        "replay",
        "truncated_history_or_wrong_proven_head_cannot_finish",
    ),
    (
        "replay-head-state",
        repo / "tools/shielded-pool-mobile/src/replay.rs",
        "last.new_state == self.head.account_root",
        "true",
        "replay",
        "truncated_history_or_wrong_proven_head_cannot_finish",
    ),
    (
        "replay-first-link",
        repo / "tools/shielded-pool-mobile/src/replay.rs",
        "tx.prev_trans_lt() != 0 || tx.prev_trans_hash().as_array() != &[0; 32]",
        "false",
        "replay",
        "skipped_reordered_foreign_or_failed_pushes_poison_the_replay",
    ),
    (
        "replay-link-hash",
        repo / "tools/shielded-pool-mobile/src/replay.rs",
        "tx.prev_trans_hash().as_array() != &last.hash",
        "false",
        "replay",
        "each_forward_link_binding_is_checked_independently",
    ),
    (
        "replay-link-lt",
        repo / "tools/shielded-pool-mobile/src/replay.rs",
        "tx.prev_trans_lt() != last.lt",
        "false",
        "replay",
        "each_forward_link_binding_is_checked_independently",
    ),
    (
        "replay-link-state",
        repo / "tools/shielded-pool-mobile/src/replay.rs",
        "update.old_hash.as_array() != &last.new_state",
        "false",
        "replay",
        "each_forward_link_binding_is_checked_independently",
    ),
    (
        "replay-link-time",
        repo / "tools/shielded-pool-mobile/src/replay.rs",
        "tx.now() < last.time",
        "false",
        "replay",
        "each_forward_link_binding_is_checked_independently",
    ),
    (
        "replay-link-order",
        repo / "tools/shielded-pool-mobile/src/replay.rs",
        "tx.logical_time() <= last.lt",
        "false",
        "replay",
        "each_forward_link_binding_is_checked_independently",
    ),
    (
        "replay-zero-lt",
        repo / "tools/shielded-pool-mobile/src/replay.rs",
        "tx.logical_time() == 0",
        "false",
        "replay",
        "each_forward_link_binding_is_checked_independently",
    ),
    (
        "replay-account",
        repo / "tools/shielded-pool-mobile/src/replay.rs",
        "tx.account_id() != &chain_block::SliceData::from_raw(self.head.account_id.to_vec(), 256)",
        "false",
        "replay",
        "each_forward_link_binding_is_checked_independently",
    ),
    (
        "replay-proof-time",
        repo / "tools/shielded-pool-mobile/src/replay.rs",
        "tx.now() > self.head.shard_time",
        "false",
        "replay",
        "each_forward_link_binding_is_checked_independently",
    ),
    (
        "replay-proof-lt",
        repo / "tools/shielded-pool-mobile/src/replay.rs",
        "tx.logical_time() > self.head.last_lt",
        "false",
        "replay",
        "each_forward_link_binding_is_checked_independently",
    ),
    (
        "replay-transaction-budget",
        repo / "tools/shielded-pool-mobile/src/replay.rs",
        "count > MAX_HISTORY_TRANSACTIONS",
        "false",
        "replay",
        "transaction_budget_stops_valid_small_links_and_discards_state",
    ),
    (
        "replay-byte-budget",
        repo / "tools/shielded-pool-mobile/src/replay.rs",
        "bytes > MAX_HISTORY_BYTES",
        "false",
        "replay",
        "aggregate_byte_budget_stops_valid_large_links",
    ),
    (
        "replay-poison",
        repo / "tools/shielded-pool-mobile/src/replay.rs",
        "if result.is_ok() {",
        "if true {",
        "replay",
        "skipped_reordered_foreign_or_failed_pushes_poison_the_replay",
    ),
    (
        "session-hash",
        repo / "tools/shielded-pool-mobile/src/replay_ffi.rs",
        "root.repr_hash().as_array() != &hash(expected)?",
        "false",
        "session",
        "rejected_creation_and_premature_finish_return_no_ledger",
    ),
    (
        "session-poison",
        repo / "tools/shielded-pool-mobile/src/replay_ffi.rs",
        "std::mem::replace(&mut owner.state, State::Failed)",
        "std::mem::replace(&mut owner.state, State::Ready(Box::new(Ledger::genesis())))",
        "lib",
        "replay_ffi::tests::contained_mutator_panic_leaves_the_owner_failed",
    ),
    (
        "session-published-set",
        repo / "tools/shielded-pool-mobile/src/replay_ffi.rs",
        "recover_notes(&instance, &outputs, ledger.published_nullifiers())?",
        "recover_notes(&instance, &outputs, &std::collections::BTreeSet::new())?",
        "lib",
        "replay_ffi::tests::completed_scan_uses_the_full_published_nullifier_set",
    ),
    (
        "session-final-gate",
        repo / "tools/shielded-pool-mobile/src/replay_ffi.rs",
        "State::Ready(Box::new(replay.finish()?))",
        "State::Ready(Box::new(Ledger::genesis()))",
        "session",
        "rejected_creation_and_premature_finish_return_no_ledger",
    ),
]:
    original = path.read_bytes()
    assert original.decode().count(before) == 1, (name, path, before)
    try:
        path.write_text(original.decode().replace(before, after))
        log = root / f"native-mutation-{name}.log"
        with log.open("wb") as f:
            r = subprocess.run(
                base
                + (["--lib"] if suite == "lib" else ["--test", suite])
                + [test, "--", "--exact"],
                cwd=repo,
                env=env,
                stdout=f,
                stderr=subprocess.STDOUT,
            )
        text = log.read_text()
        assert r.returncode != 0 and "test result: FAILED" in text and "assertion" in text, (
            name,
            r.returncode,
            text[-2000:],
        )
        results.append(
            dict(
                control=name,
                exit=r.returncode,
                expected="assertion failure",
                log=log.name,
                sha256=hashlib.sha256(log.read_bytes()).hexdigest(),
            )
        )
    finally:
        path.write_bytes(original)
with (root / "native-core-restored.log").open("wb") as f:
    r = subprocess.run(base, cwd=repo, env=env, stdout=f, stderr=subprocess.STDOUT)
assert r.returncode == 0
results.append(dict(control="restored-full-suite", exit=r.returncode))
(root / "native-sensitivity.json").write_text(json.dumps(results, indent=2) + "\n")

print(json.dumps(results, indent=2))
