"""Require real SDK journal tests to fail after independent persistence guard deletions."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tosctl/src/node-control/contracts/src/lms_fee_journal.rs"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source = SOURCE.read_text()
    mutations = [
        (
            "lock",
            "file.try_lock_exclusive()?;",
            "",
            "durable_reservations_exclude_writers_and_restarts_wait",
        ),
        (
            "append",
            "self.file.write_all(&record)?;",
            "",
            "durable_reservations_exclude_writers_and_restarts_wait",
        ),
        ("poison", "self.poisoned = true;", "", "failed_write_poison_survives_repaired_handle"),
        (
            "restore",
            "if let Some(barrier) = self.barrier {",
            "if let Some(barrier) = None::<RestoreBarrier> {",
            "rollback_snapshot_cannot_resume_current_slot",
        ),
    ]
    cache = SOURCE.with_name("lms_fee_cache.rs")
    originals = {SOURCE: source, cache: cache.read_text()}
    mutations = [
        (SOURCE, name, old, new, "lms_fee_journal::tests::" + witness)
        for name, old, new, witness in mutations
    ]
    for name, old, new, witness in [
        (
            "cache_session",
            "Arc::ptr_eq(&reservation.session, &self.session)",
            "true",
            "cache_cannot_be_written_using_a_receipt_from_another_session",
        ),
        (
            "cache_exclusive",
            "libc::O_EXCL",
            "0",
            "partial_existing_cache_is_never_overwritten_and_poisons_writer",
        ),
        (
            "cache_reservation",
            'anyhow::ensure!(found, "signature has no journal reservation");',
            "",
            "damaged_cache_and_rolled_back_reservation_are_refused",
        ),
        (
            "cache_leaf",
            "word(&signature[4..8])? == leaf",
            "true",
            "wrong_leaf_output_is_not_cached_and_reservation_stays_burned",
        ),
        (
            "cache_integrity",
            "Sha256::digest(&cached[..CACHE_SIZE - 32])[..] == cached[CACHE_SIZE - 32..]",
            "true",
            "damaged_cache_and_rolled_back_reservation_are_refused",
        ),
    ]:
        mutations.append((cache, name, old, new, "lms_fee_journal::cache::tests::" + witness))
    reserve_then_sign = (
        "let reservation = self.reserve(proven_time, chain_next_leaf, expected_leaf, intent_hash)?;\n"
        "        let signature = signer(reservation.leaf(), reservation.intent_hash())?;"
    )
    sign_then_reserve = (
        "let signature = signer(expected_leaf, &intent_hash)?;\n"
        "        let reservation = self.reserve(proven_time, chain_next_leaf, expected_leaf, intent_hash)?;"
    )
    mutations += [
        (
            cache,
            "signing_order",
            reserve_then_sign,
            sign_then_reserve,
            "lms_fee_journal::cache::tests::signing_callback_runs_after_reservation_and_retry_never_calls_it",
        ),
        (
            cache,
            "backend_verification",
            "verify(expected_leaf, &intent_hash, &signature)?",
            "true",
            "lms_fee_journal::cache::tests::failed_signer_or_verification_never_releases_or_reuses_leaf",
        ),
    ]
    results = {}

    def run(name):
        result = subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "--locked",
                "-p",
                "contracts",
                "--lib",
                "lms_fee_",
                "--",
                "--nocapture",
                # The process-handoff test can inherit sibling tests' flock
                # descriptors until exec. Keep immediate close/reopen probes
                # separate; the handoff test still checks competing processes.
                "--test-threads=1",
            ],
            capture_output=True,
            text=True,
        )
        log = result.stdout + result.stderr
        (args.output / f"{name}.log").write_text(log)
        return result.returncode, log

    try:
        code, log = run("production")
        assert code == 0, log[-2000:]
        for path, name, old, new, witness in mutations:
            for restored_path, original in originals.items():
                restored_path.write_text(original)
            candidate = originals[path]
            assert candidate.count(old) == 1
            path.write_text(candidate.replace(old, new))
            code, log = run(name)
            assert code != 0 and f"{witness} ... FAILED" in log
            assert "panicked at" in log and "assertion" in log
            results[name] = {"exit": code, "semantic_witness": witness}
    finally:
        for path, original in originals.items():
            path.write_text(original)
        code, log = run("restored")
        assert code == 0, log[-2000:]
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Eleven journal/cache/signing controls fail semantic tests; restored SDK tests pass")


if __name__ == "__main__":
    main()
