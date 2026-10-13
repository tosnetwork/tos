#!/usr/bin/env python3
"""Fail if the production code stops calling the sync-stall alert logic.

test-sync-stall-alerts drives the logic the validator manager and the
block-data waiter run (validator/sync-stall-alerts.h). This guard pins the
other half: that the manager's alarm still runs the tick, that the tick still
publishes the block times and logs the report, that the waiter still feeds
every failed attempt and every delivery to its tracker and logs the
warnings, that it tells the tracker whether the bytes came from the network
or from the local candidate store, that the manager answers a block request
from its cache only with bytes matching the file hash (evicting anything
else), and that the exporter still publishes the families. Removing any of
these leaves the unit tests green, so it is checked here.

With --self-test, each pinned call is removed from an in-memory copy of the
sources and the guard must then fail.
"""

import re
import sys
from pathlib import Path

SOURCES = {
    "manager": "validator/manager.cpp",
    "waiter": "validator/downloaders/wait-block-data.cpp",
    "exporter": "metrics/prometheus-exporter.cpp",
}

# (source, function signature prefix, required fragments in its body)
REQUIRED = [
    ("manager", "void ValidatorManagerImpl::alarm()", ["check_masterchain_lag();"]),
    (
        "manager",
        "void ValidatorManagerImpl::check_masterchain_lag()",
        [
            "observe_masterchain_lag(",
            "health_block_unix_seconds(last_masterchain_block_handle_)",
            "health_block_unix_seconds(shard_client_handle_)",
            "g.masterchain_block_unix_seconds",
            "g.shard_client_unix_seconds",
            "LOG(WARNING) << masterchain_lag_message(report);",
            "LOG(INFO) << masterchain_lag_message(report);",
        ],
    ),
    (
        "manager",
        "void ValidatorManagerImpl::send_get_block_request(",
        [
            "block::compute_file_hash(cached->as_slice()) == id.file_hash",
            "cached_block_data_.erase(id);",
        ],
    ),
    (
        "waiter",
        "void WaitBlockData::start()",
        [
            "ReceivedBlock{id, R.move_as_ok()}, BlockDataSource::LocalCandidate",
            'R.move_as_error_prefix("net error: "), BlockDataSource::Network',
            "&WaitBlockData::loaded_data, R.move_as_ok(), BlockDataSource::Network",
        ],
    ),
    (
        "waiter",
        "void WaitBlockData::failed_to_get_block_data(",
        [
            "net_failures_.on_failure(source, reason.code() == ErrorCode::notready",
            "health::node_state.block_data_net_failures",
            "if (report.stall_warning) {",
            'LOG(WARNING) << "still cannot get block "',
            "if (report.failure_warning) {",
            'LOG(WARNING) << "failed to get block "',
        ],
    ),
    (
        "waiter",
        "void WaitBlockData::loaded_data(",
        [
            'block_data_source_name(source) << ": "), source);',
            "net_failures_.on_delivered();",
        ],
    ),
    (
        "exporter",
        "void PrometheusExporter::collection_completed(",
        ["health::chain_progress_families(prefix_, wall)"],
    ),
]


def function_body(text, signature):
    start = text.find(signature)
    if start < 0:
        return None
    if text.find(signature, start + 1) >= 0:
        return None
    open_brace = text.find("{", start)
    if open_brace < 0:
        return None
    depth = 0
    for i in range(open_brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace : i + 1]
    return None


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def collapsed(text):
    return re.sub(r"\s+", " ", text)


def problems(texts):
    found = []
    for source, signature, fragments in REQUIRED:
        body = function_body(strip_comments(texts[source]), signature)
        if body is None:
            found.append(f"{SOURCES[source]}: {signature} not found exactly once")
            continue
        body = collapsed(body)
        for fragment in fragments:
            if collapsed(fragment) not in body:
                found.append(f"{SOURCES[source]}: {signature} no longer contains {fragment!r}")
    return found


def main():
    args = sys.argv[1:]
    self_test = "--self-test" in args
    args = [a for a in args if a != "--self-test"]
    root = Path(args[0] if args else Path(__file__).parents[1]).resolve()
    texts = {key: (root / path).read_text() for key, path in SOURCES.items()}
    current = problems(texts)
    if current:
        for problem in current:
            print(f"SYNC_STALL_WIRING_FAILURE: {problem}")
        return 1
    if not self_test:
        print(f"sync-stall wiring: {sum(len(r[2]) for r in REQUIRED)} calls in place")
        return 0
    survivors = []
    mutants = 0
    for source, signature, fragments in REQUIRED:
        for fragment in fragments:
            mutants += 1
            mutated = dict(texts)
            text = mutated[source]
            start = text.find(signature)
            # The fragment may be split over lines in the source: match its
            # tokens across any whitespace.
            pattern = r"\s+".join(re.escape(token) for token in fragment.split())
            match = re.compile(pattern).search(text, start)
            if match is None:
                survivors.append(f"{SOURCES[source]}: {fragment!r} could not be located to remove")
                continue
            mutated[source] = text[: match.start()] + "/* removed */" + text[match.end() :]
            if not problems(mutated):
                survivors.append(f"{SOURCES[source]}: removing {fragment!r} was not detected")
    for survivor in survivors:
        print(f"SYNC_STALL_WIRING_SELF_TEST_FAILURE: {survivor}")
    if survivors:
        return 1
    print(f"sync-stall wiring self-test: {mutants} removals, all detected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
