#!/usr/bin/env python3
"""Red-before controls for the wallet index's served window.

Each mutation removes one rule: the history filter's bound or its per-account
cutoff, the RPC's fail-closed answer and its filter on single events, the
base record written with every base move (by replay with an advancing nonzero
base, by the verification of an import and by a build), the retried backfill of a
missing record, the record's shard cover check, the refusal of a nonzero base without its record, and the
canonical dump's bound, its normalization of token and NFT verdict lts, its
head check and its refusal to widen the window. The named tests must fail
with the mutation and pass again once the source is restored. Sources are
restored in `finally` and their hashes are checked.
"""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_HEADER = ROOT / "validator-engine/wallet-index.h"
DB_SOURCE = ROOT / "validator-engine/wallet-index.cpp"
RPC = ROOT / "validator-engine/json-rpc-server-wc0index.cpp"
REPLAY = ROOT / "services/index-replay-loop.h"
VERIFY = ROOT / "services/index-verify.cpp"
DUMP = ROOT / "services/index-dump.cpp"
FILES = (DB_HEADER, DB_SOURCE, RPC, REPLAY, VERIFY, DUMP)

TRANSPORT = (
    "test-json-rpc-transport",
    "JsonRpcTransport_wallet_index_history_reads_serve_only_the_window",
)
CANONICAL = ("test-wallet-index", "WalletIndex_TheCanonicalViewIsTheServedWindow")
RECORD = ("test-wallet-index", "WalletIndex_WindowBaseRecordIsCheckedAndMovesWithTheBase")
REPLAYED = (
    "test-wallet-index-source",
    "WalletIndexSource_replay_moves_the_window_base_with_its_blocks_record",
)
PREPARED = (
    "test-wallet-index-source",
    "WalletIndexSource_an_untrusted_snapshot_is_prepared_replayed_and_verified_at_the_head",
)
BUILT = (
    "test-wallet-index-source",
    "WalletIndexVerify_a_fresh_index_is_built_from_the_windows_blocks",
)
BACKFILLED = (
    "test-wallet-index-source",
    "WalletIndexVerify_a_missing_base_record_is_backfilled_after_the_source_recovers",
)
DUMP_CLI = ("dump-cli", None)

# (name, file, anchor, replacement, tests that must turn red)
MUTATIONS = [
    (
        "filter-without-the-bound",
        DB_HEADER,
        "    return lt > bound && lt >= cutoff;",
        "    return lt >= cutoff;",
        [TRANSPORT, CANONICAL],
    ),
    (
        "filter-without-the-cutoff",
        DB_HEADER,
        "    return lt > bound && lt >= cutoff;",
        "    return lt > bound;",
        [TRANSPORT, CANONICAL],
    ),
    (
        "rpc-history-fails-open",
        RPC,
        "    if (served.is_error()) {\n"
        "      promise.set_value(make_json_rpc_error(-32603, served.error().message().str(), req_id));\n"
        "      return;\n"
        "    }\n"
        "    filter = served.move_as_ok();",
        "    if (served.is_ok()) {\n      filter = served.move_as_ok();\n    }",
        [TRANSPORT],
    ),
    (
        "rpc-single-event-unfiltered",
        RPC,
        " || !filter.ok().serves(id.lt)) {",
        ") {",
        [TRANSPORT],
    ),
    (
        "replay-moves-the-base-without-its-record",
        REPLAY,
        "commit_replay_checkpoint(committed, base, base_record)",
        "commit_replay_checkpoint(committed, base, {})",
        [REPLAYED],
    ),
    (
        "prepare-moves-the-base-without-its-record",
        VERIFY,
        "  TRY_STATUS(db.put_window_base(base, base_record));",
        "  TRY_STATUS(db.put_window_base(base, {}));",
        [PREPARED],
    ),
    (
        "build-publishes-the-base-without-its-record",
        VERIFY,
        "  TRY_STATUS(db.put_window_base(record.base, base_record));",
        "  TRY_STATUS(db.put_window_base(record.base, {}));",
        [BUILT],
    ),
    (
        "backfill-gives-up-after-a-failure",
        VERIFY,
        "  delay_ = delay_ == 0 ? kFirstDelaySeconds",
        "  owed_ = false;\n  delay_ = delay_ == 0 ? kFirstDelaySeconds",
        [BACKFILLED],
    ),
    (
        "record-cover-unchecked",
        DB_SOURCE,
        "    if (ranges[i].first != next ||",
        "    if (false ||",
        [RECORD],
    ),
    (
        "a-base-without-its-record-is-served",
        DB_SOURCE,
        "  if (record.is_error() || !record.ok() || record.ok().value().block.seqno() != window.base) {\n"
        "    return td::Status::Error(\n"
        "        \"account history unavailable: the index's window base is not authenticated by its "
        "block's record\");\n"
        "  }\n"
        "  window.record = record.move_as_ok();",
        "  if (record.is_ok()) {\n    window.record = record.move_as_ok();\n  }",
        [TRANSPORT, RECORD, DUMP_CLI],
    ),
    (
        "canonical-ignores-the-bound",
        DB_SOURCE,
        "      if (lt <= bound || served >= kMaxEventsPerAccount) {",
        "      if (served >= kMaxEventsPerAccount) {",
        [CANONICAL],
    ),
    (
        "canonical-token-keeps-its-verdict-lt",
        DB_SOURCE,
        '" " << wallet.to_hex());',
        '" " << wallet.to_hex() << " " << cell->get_hash().to_hex());',
        [CANONICAL],
    ),
    (
        "canonical-nft-keeps-its-verdict-lt",
        DB_SOURCE,
        '(has_collection ? collection.to_hex() : std::string("-")));',
        '(has_collection ? collection.to_hex() : std::string("-")) << " " << cell->get_hash().to_hex());',
        [CANONICAL],
    ),
    (
        "dump-head-unchecked",
        DUMP,
        "  if (committed.seqno() != head) {",
        "  if (false) {",
        [DUMP_CLI],
    ),
    (
        "dump-window-widened",
        DUMP,
        "    if (other.ok().base < window.base || other.ok().base > head) {",
        "    if (other.ok().base > head) {",
        [DUMP_CLI],
    ),
]

TARGETS = [
    "test-json-rpc-transport",
    "test-wallet-index",
    "test-wallet-index-source",
    "tos-wallet-index-dump",
    "tos-wallet-index-snapshot",
]


def build(build_dir: Path, jobs: int, log: Path) -> None:
    with log.open("ab") as out:
        subprocess.run(
            ["cmake", "--build", str(build_dir), "--target", *TARGETS, "-j", str(jobs)],
            check=True,
            stdout=out,
            stderr=subprocess.STDOUT,
        )


def run(build_dir: Path, test: tuple[str, str | None]) -> tuple[int, str]:
    binary, name = test
    if binary == "dump-cli":
        command = [
            sys.executable,
            str(ROOT / "scripts/test_wallet_index_dump_cli.py"),
            "--dump-binary",
            str(build_dir / "services/tos-wallet-index-dump"),
            "--snapshot-binary",
            str(build_dir / "services/tos-wallet-index-snapshot"),
        ]
    else:
        command = [str(build_dir / binary), "--filter", str(name)]
    result = subprocess.run(
        command, text=True, errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    return result.returncode, result.stdout


def label(test: tuple[str, str | None]) -> str:
    return test[0] if test[1] is None else f"{test[0]}:{test[1]}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    build_dir = args.build_dir.resolve()
    log = build_dir / "wallet-index-window-controls.log"
    log.write_bytes(b"")
    originals = {path: path.read_bytes() for path in FILES}
    original_sha = {
        str(path.relative_to(ROOT)): hashlib.sha256(data).hexdigest()
        for path, data in originals.items()
    }
    for name, path, anchor, _, _ in MUTATIONS:
        if originals[path].decode().count(anchor) != 1:
            raise RuntimeError(f"mutation {name}: anchor does not occur once in {path.name}")
    tests = sorted({test for *_, names in MUTATIONS for test in names}, key=label)
    build(build_dir, args.jobs, log)
    for test in tests:
        status, output = run(build_dir, test)
        if status != 0:
            print(f"baseline test {label(test)} does not pass:\n{output}", file=sys.stderr)
            return 1

    def restore() -> None:
        for path, data in originals.items():
            path.write_bytes(data)

    results = []
    failed = False
    try:
        for name, path, anchor, replacement, names in MUTATIONS:
            path.write_text(originals[path].decode().replace(anchor, replacement, 1))
            build(build_dir, args.jobs, log)
            for test in names:
                status, output = run(build_dir, test)
                red = status != 0
                results.append(
                    {"mutation": name, "test": label(test), "exit_status": status, "red": red}
                )
                if not red:
                    failed = True
                    print(f"mutation {name} left {label(test)} passing:\n{output}", file=sys.stderr)
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
            {"mutation": "restored", "test": label(test), "exit_status": status, "red": status != 0}
        )
        if status != 0:
            failed = True
            print(f"restored source fails {label(test)}:\n{output}", file=sys.stderr)
    print(json.dumps({"source_sha256": original_sha, "results": results}, indent=2))
    if failed:
        return 1
    print("WALLET_INDEX_WINDOW_CONTROLS_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
