#!/usr/bin/env python3
"""Red-before controls for verifying an imported wallet index.

Each mutation removes one rule from the verification of a quarantined index
against the node's chain: the checkpoint's identity, the refusal of rows newer
than the checkpoint, the walk's stop at a block the node does not hold, its
link check and its check of each handle against the block's own bytes, the
check of the anchor against the node's first block, the per-row masterchain
reference, the refusal of a row stored
under another logical time, the refusal of in-window history left out
entirely, and the marking of accounts the head state cannot vouch for; and
for the build of a fresh index from the window's blocks: the per-account
retention and trim, the drop of rows the base referenced, the binding to the
head and its replacement, the refusal of a used index, the Quarantined
state before any row, the interval bound and each row's charge by its
transaction's cells, the link to the interval below, the applied, held head,
and block 1 read only from the state the head's block names. The
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
HEADER = ROOT / "services/index-verify.h"
WRITER = ROOT / "validator-engine/wallet-index-writer.cpp"
TARGET = "test-wallet-index-source"

MUTATIONS = [
    (
        "build-keeps-every-row-of-an-account",
        "      if (list.size() > tos_wallet_index::kMaxEventsPerAccount) {\n"
        "        list.resize(tos_wallet_index::kMaxEventsPerAccount);\n      }\n",
        "",
        ["WalletIndexVerify_a_build_keeps_the_newest_rows_of_an_account_per_interval"],
    ),
    (
        "build-without-trim",
        "      TRY_STATUS(db.trim_events(account, list.size()));\n",
        "",
        ["WalletIndexVerify_a_build_keeps_the_newest_rows_of_an_account_per_interval"],
    ),
    (
        "build-keeps-rows-the-base-referenced",
        "          if (lt <= bound) {\n            return td::Status::OK();\n          }\n"
        "          TRY_RESULT(row_bytes, build_row_bytes(cell));",
        "          TRY_RESULT(row_bytes, build_row_bytes(cell));",
        ["WalletIndexVerify_a_fresh_index_is_built_from_the_windows_blocks"],
    ),
    (
        "build-ignores-a-lost-binding",
        "      bound = roots == record.roots;",
        "      bound = true;",
        ["WalletIndexVerify_a_build_on_a_lost_binding_is_replaced_before_anything_is_cleared"],
    ),
    (
        "build-replacement-keeps-the-built-rows",
        "      TRY_STATUS(db.clear_built_index());\n",
        "",
        ["WalletIndexVerify_a_build_on_a_lost_binding_is_replaced_before_anything_is_cleared"],
    ),
    (
        "build-over-a-used-index",
        '    if (!fresh) {\n      return terminal("an index that holds data',
        '    if (false) {\n      return terminal("an index that holds data',
        ["WalletIndexVerify_a_build_stops_at_a_bound_a_gap_or_an_unlinked_block"],
    ),
    (
        "build-record-without-quarantine",
        "    TRY_STATUS(db.put_verification_state(VerificationState::Quarantined));\n"
        "    TRY_STATUS(db.put_build_record(record));",
        "    TRY_STATUS(db.put_build_record(record));",
        ["WalletIndexVerify_an_interrupted_build_resumes_to_the_same_index"],
    ),
    (
        "build-row-charged-a-fixed-size",
        "          TRY_RESULT(row_bytes, build_row_bytes(cell));\n          interval_bytes += row_bytes;",
        "          interval_bytes += 4096;",
        ["WalletIndexVerify_a_build_charges_each_row_its_transactions_cells"],
    ),
    (
        "block-1-from-an-unbound-state",
        "  if (state.is_null() || td::Bits256{state->get_hash().bits()} != new_state_hash) {",
        "  if (state.is_null()) {",
        [
            "WalletIndexVerify_block_1_comes_from_the_state_the_heads_block_names",
            "WalletIndexVerify_a_retained_ancestor_comes_from_the_requested_entry_in_the_bound_head_state",
        ],
    ),
    (
        "build-interval-unbounded",
        "          interval_bytes += row_bytes;\n          if (interval_bytes > limits.interval_bytes) {",
        "          interval_bytes += row_bytes;\n          if (false) {",
        ["WalletIndexVerify_a_build_stops_at_a_bound_a_gap_or_an_unlinked_block"],
    ),
    (
        "build-without-the-link-below",
        "                   (record.expected && block.value().prev && "
        "block.value().prev.value() == record.expected.value()));\n    if (!linked",
        "                   (record.expected && block.value().prev));\n    if (!linked",
        ["WalletIndexVerify_a_build_stops_at_a_bound_a_gap_or_an_unlinked_block"],
    ),
    (
        "build-head-unapplied-or-foreign",
        "  if (!top || top.value().id != tip || !top.value().applied) {\n"
        "    return terminal(\"the source's tip is not",
        "  if (!top) {\n    return terminal(\"the source's tip is not",
        ["WalletIndexVerify_a_build_starts_only_at_an_applied_held_head"],
    ),
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
        [
            # One check, shared by the preparation's walk, the block pass's
            # walk and the build.
            (
                SOURCE,
                "(block.prev && block.handle_prev && block.prev.value() == block.handle_prev.value());",
                "(true);",
                1,
            ),
        ],
        None,
        ["WalletIndexVerify_a_lookup_error_or_an_unlinked_block_stops_the_walk_without_a_record"],
    ),
    (
        "anchor-not-checked",
        "    if (first_block.value().id != anchor) {",
        "    if (false) {",
        ["WalletIndexVerify_the_anchor_is_checked_against_this_nodes_first_block"],
    ),
    (
        "block-pass-accepts-a-wholly-omitted-account",
        "    if (imported != collected) {",
        "    if (!imported.empty() && imported != collected) {",
        ["WalletIndexVerify_the_block_pass_refuses_what_the_snapshot_left_out_or_changed"],
    ),
    (
        "block-pass-compares-only-a-common-prefix",
        "    if (imported != collected) {",
        "    if (!std::equal(imported.begin(), imported.begin() + std::min(imported.size(), collected.size()),\n"
        "                    collected.begin())) {",
        ["WalletIndexVerify_the_block_pass_refuses_what_the_snapshot_left_out_or_changed"],
    ),
    (
        "block-pass-without-identity-checks",
        [
            (
                "      if (!record.expected || block.value().id != record.expected.value() || "
                "!linked_inside(block.value()) ||",
                "      if (!record.expected || !linked_inside(block.value()) ||",
            ),
            (
                "      if (!linked || !block.value().applied || (seqno == head.seqno() && "
                "block.value().id != head)) {",
                "      if (!block.value().applied) {",
            ),
        ],
        None,
        ["WalletIndexVerify_the_block_pass_stops_at_a_gap_or_a_foreign_block"],
    ),
    (
        "block-pass-skips-a-missing-shard-block",
        [
            (
                HEADER,
                "    if (!root) {\n      return terminal_gap(block->id().to_str());\n    }",
                "    if (!root) {\n      continue;\n    }",
            ),
        ],
        None,
        ["WalletIndexSource_the_block_pass_stops_at_a_shard_block_the_node_does_not_hold"],
    ),
    (
        "block-pass-holds-no-interval-memory-bound",
        "\n        if (interval_bytes > limits.interval_bytes) {",
        "\n        if (false) {",
        ["WalletIndexVerify_an_interval_over_the_memory_bound_stops_the_pass"],
    ),
    (
        "partial-index-replays",
        [
            (
                HEADER,
                "      return pass_done ? ServiceAction::HoldForOwnership : ServiceAction::BlockPass;",
                "      return pass_done ? ServiceAction::Replay : ServiceAction::BlockPass;",
            ),
        ],
        None,
        ["WalletIndexVerify_a_partial_index_holds_replay_at_the_head"],
    ),
    (
        "ownership-derivation-skips-accounts-with-code",
        [
            (
                WRITER,
                "      case AccountAtHead::WithCode:\n        TRY_STATUS(derive_account(db, heads, index, key, step));",
                "      case AccountAtHead::WithCode:\n        // skipped",
            ),
        ],
        None,
        ["WalletIndexVerify_ownership_is_derived_at_the_head_across_shards"],
    ),
    (
        "undecodable-account-skipped",
        [
            (
                WRITER,
                "        TRY_STATUS(park_at_head(db, TokenKind::Fungible, key, heads.head(index).end_lt));\n"
                "        TRY_STATUS(park_at_head(db, TokenKind::Nft, key, heads.head(index).end_lt));\n"
                "        step.parked += 2;",
                "        // skipped",
            ),
        ],
        None,
        ["WalletIndexVerify_an_undecodable_account_is_parked_at_its_shard_state"],
    ),
    (
        "recorded-accounts-not-reconciled",
        [(WRITER, "    if (at_head == AccountAtHead::WithCode) {", "    if (true) {")],
        None,
        ["WalletIndexVerify_recorded_ownership_of_accounts_gone_from_the_head_is_removed"],
    ),
    (
        "full-despite-parked-candidates",
        "  if (stats.entries != 0 || pending != 0 || stats.parked != 0) {",
        "  if (stats.entries != 0 || pending != 0) {",
        ["WalletIndexVerify_the_index_is_full_only_when_no_ownership_work_is_owed"],
    ),
    (
        "fetcher-answers-another-state",
        "        done(tos_wallet_index::Wc0NewestState{state.block_id, state.end_lt, state.root});",
        "        done(tos_wallet_index::Wc0NewestState{state.block_id, state.end_lt + 1, state.root});",
        ["WalletIndexVerify_the_pinned_fetcher_answers_with_the_head_states"],
    ),
    (
        "pin-keeps-the-cached-state",
        "  tos_wallet_index::release_wc0_index_state();\n  tos_wallet_index::set_wc0_index_state_fetcher(make_head_state_fetcher(std::move(states)));",
        "  tos_wallet_index::set_wc0_index_state_fetcher(make_head_state_fetcher(std::move(states)));",
        ["WalletIndexVerify_pinning_to_the_head_drops_an_older_cached_state"],
    ),
    (
        "ownership-drain-holds-accounts-without-code",
        [
            (
                WRITER,
                "    if (g_ownership_work) {\n      state->treat_no_code_as_inactive();\n    }",
                "",
            )
        ],
        None,
        ["WalletIndexVerify_the_ownership_drain_decides_a_parked_account_without_code"],
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


def edits(before, after) -> list[tuple[Path, str, str, int]]:
    """A mutation's (file, anchor, replacement, occurrences) edits.

    `before` is one anchor in SOURCE replaced by `after`, or a list of
    (anchor, replacement) pairs in SOURCE, (file, anchor, replacement)
    triples, or (file, anchor, replacement, occurrences) for a rule written
    in more than one place, where every copy must be mutated.
    """
    if not isinstance(before, list):
        return [(SOURCE, before, after, 1)]
    out = []
    for edit in before:
        if len(edit) == 2:
            out.append((SOURCE, edit[0], edit[1], 1))
        elif len(edit) == 3:
            out.append((*edit, 1))
        else:
            out.append(tuple(edit))
    return out


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
    originals = {path: path.read_bytes() for path in (SOURCE, HEADER, WRITER)}
    original_sha = {
        str(path.relative_to(ROOT)): hashlib.sha256(data).hexdigest()
        for path, data in originals.items()
    }
    for name, before, after, _ in MUTATIONS:
        for path, anchor, _, occurrences in edits(before, after):
            if originals[path].decode().count(anchor) != occurrences:
                raise RuntimeError(
                    f"mutation {name}: anchor does not occur {occurrences} time(s) in {path.name}"
                )
    tests = sorted({test for _, _, _, names in MUTATIONS for test in names})
    results = []
    failed = False
    build(build_dir, args.jobs, log)
    for test in tests:
        status, output = run(build_dir, test)
        if status != 0:
            print(f"baseline test {test} does not pass:\n{output}", file=sys.stderr)
            return 1

    def restore() -> None:
        for path, data in originals.items():
            path.write_bytes(data)

    try:
        for name, before, after, names in MUTATIONS:
            mutated = {path: data.decode() for path, data in originals.items()}
            for path, anchor, replacement, occurrences in edits(before, after):
                mutated[path] = mutated[path].replace(anchor, replacement, occurrences)
            for path, text in mutated.items():
                path.write_text(text)
            build(build_dir, args.jobs, log)
            for test in names:
                status, output = run(build_dir, test)
                red = status != 0
                results.append({"mutation": name, "test": test, "exit_status": status, "red": red})
                if not red:
                    failed = True
                    print(f"mutation {name} left {test} passing:\n{output}", file=sys.stderr)
            restore()
    finally:
        restore()
    for path, data in originals.items():
        if path.read_bytes() != data:
            raise RuntimeError(f"{path.name} was not restored")
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
