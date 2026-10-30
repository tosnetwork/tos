#!/usr/bin/env python3
"""Red-before controls for verifying an imported wallet index.

Each mutation removes one rule from the verification of a quarantined index
against the node's chain: the checkpoint's identity, the refusal of rows newer
than the checkpoint, the walk's stop at a block the node does not hold, its
link check and its check of each handle against the block's own bytes, the
check of the anchor against the node's first block, the per-row masterchain
reference, the refusal of a row stored
under another logical time, the refusal of in-window history left out
entirely, and the marking of accounts the head state cannot vouch for. The
named tests must fail with the mutation and pass again once the source is
restored. The source is restored in `finally` and its hash is checked.
"""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "services/index-verify.cpp"
TARGET = "test-wallet-index-source"

MUTATIONS = [
    (
        "foreign-checkpoint-accepted",
        "  if (top.value().id != checkpoint) {",
        "  if (false) {",
        ["WalletIndexVerify_the_checkpoint_must_be_this_nodes_block"],
    ),
    (
        "row-newer-than-checkpoint-accepted",
        "    if (lt >= upper) {",
        "    if (false) {",
        ["WalletIndexVerify_the_checkpoint_must_be_this_nodes_block"],
    ),
    (
        "walk-skips-a-gap",
        "      // already referenced cannot be checked and is dropped.\n      break;",
        "      // already referenced cannot be checked and is dropped.\n      continue;",
        ["WalletIndexVerify_the_window_walk_stops_at_a_gap_and_reports_the_horizon"],
    ),
    (
        "walk-without-links",
        "    if (!above.prev || above.prev.value() != block.value().id) {",
        "    if (false) {",
        ["WalletIndexVerify_a_lookup_error_or_an_unlinked_block_stops_the_walk_without_a_record"],
    ),
    (
        "handle-prev-trusted-over-the-bytes",
        "(block.prev && block.handle_prev && block.prev.value() == block.handle_prev.value());",
        "(true);",
        ["WalletIndexVerify_a_lookup_error_or_an_unlinked_block_stops_the_walk_without_a_record"],
    ),
    (
        "anchor-not-checked",
        "    if (first_block.value().id != anchor) {",
        "    if (false) {",
        ["WalletIndexVerify_the_anchor_is_checked_against_this_nodes_first_block"],
    ),
    (
        "every-row-at-the-checkpoint",
        "    TRY_STATUS(db.put_event_age(account, lt, table.seqno(lo)));",
        "    TRY_STATUS(db.put_event_age(account, lt, table.seqno(last)));",
        [
            "WalletIndexVerify_rows_get_the_block_that_first_referenced_them_per_shard",
            "WalletIndexVerify_rows_are_keyed_across_a_split_in_the_window",
        ],
    ),
    (
        "row-under-another-lt-accepted",
        "    if (link.is_ok() && link.ok().lt != lt) {",
        "    if (false) {",
        ["WalletIndexVerify_rows_that_contradict_the_head_state_refuse_the_import"],
    ),
    (
        "missing-history-accepted",
        "    if (has_rows) {",
        "    if (true) {",
        ["WalletIndexVerify_rows_that_contradict_the_head_state_refuse_the_import"],
    ),
    (
        "unprovable-accounts-unmarked",
        "        TRY_STATUS(db.put_unverified_account(group.account, static_cast<uint8_t>(reason)));",
        "        (void)reason;",
        [
            "WalletIndexVerify_an_honest_import_is_partial_with_the_unprovable_accounts_marked",
            "WalletIndexVerify_a_recreated_account_missing_its_first_life_is_never_complete",
            "WalletIndexSource_an_untrusted_snapshot_is_prepared_replayed_and_verified_at_the_head",
        ],
    ),
]


def build(build_dir: Path, jobs: int, log: Path) -> None:
    with log.open("ab") as out:
        subprocess.run(
            ["cmake", "--build", str(build_dir), "--target", TARGET, "-j", str(jobs)],
            check=True,
            stdout=out,
            stderr=subprocess.STDOUT,
        )


def run(build_dir: Path, test: str) -> tuple[int, str]:
    result = subprocess.run(
        [str(build_dir / TARGET), "--filter", test],
        text=True,
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return result.returncode, result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    build_dir = args.build_dir.resolve()
    log = build_dir / "wallet-index-verify-controls.log"
    log.write_bytes(b"")
    original = SOURCE.read_bytes()
    original_sha = hashlib.sha256(original).hexdigest()
    text = original.decode()
    for name, before, _, _ in MUTATIONS:
        if text.count(before) != 1:
            raise RuntimeError(f"mutation {name}: anchor is not unique")
    tests = sorted({test for _, _, _, names in MUTATIONS for test in names})
    results = []
    failed = False
    build(build_dir, args.jobs, log)
    for test in tests:
        status, output = run(build_dir, test)
        if status != 0:
            print(f"baseline test {test} does not pass:\n{output}", file=sys.stderr)
            return 1
    try:
        for name, before, after, names in MUTATIONS:
            SOURCE.write_text(text.replace(before, after, 1))
            build(build_dir, args.jobs, log)
            for test in names:
                status, output = run(build_dir, test)
                red = status != 0
                results.append({"mutation": name, "test": test, "exit_status": status, "red": red})
                if not red:
                    failed = True
                    print(f"mutation {name} left {test} passing:\n{output}", file=sys.stderr)
            SOURCE.write_bytes(original)
    finally:
        SOURCE.write_bytes(original)
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != original_sha:
        raise RuntimeError("verification source was not restored")
    build(build_dir, args.jobs, log)
    for test in tests:
        status, output = run(build_dir, test)
        results.append(
            {"mutation": "restored", "test": test, "exit_status": status, "red": status != 0}
        )
        if status != 0:
            failed = True
            print(f"restored source fails {test}:\n{output}", file=sys.stderr)
    print(json.dumps({"source_sha256": original_sha, "results": results}, indent=2))
    if failed:
        return 1
    print("WALLET_INDEX_VERIFY_CONTROLS_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
