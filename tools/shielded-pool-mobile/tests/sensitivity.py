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
        "recovered.reconcile_spent(&instance, &published).map_err(|_| Error::Crypto)?;",
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
]:
    original = path.read_bytes()
    assert original.decode().count(before) == 1
    try:
        path.write_text(original.decode().replace(before, after))
        log = root / f"native-mutation-{name}.log"
        with log.open("wb") as f:
            r = subprocess.run(
                base + ["--test", suite, test, "--", "--exact"],
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
