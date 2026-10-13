#!/usr/bin/env python3
"""Fail if the production code stops calling the sync-stall alert logic.

test-sync-stall-alerts drives the logic the validator manager and the
block-data waiter run (validator/sync-stall-alerts.h). This guard pins the
other half: that the manager's alarm still runs the tick, that the tick still
publishes the block times and logs the report, that the waiter still feeds
every failed attempt and every delivery to its tracker and logs the
warnings, that it tells the tracker whether the bytes came from the network
or from the local candidate store, that the manager answers a block request
from its cache only with bytes that pass the full block check (evicting
anything else), that the exporter still publishes the families, and that the
full node's refusal-answer budget still feeds the exported counters. Removing any
of these leaves the unit tests green, so it is checked here.

It also checks that a pull request touching any of these files, or the logic
and tests behind them, still triggers the node-health-monitor workflow that
builds and runs those tests: a path missing from its trigger skips them without
a word.

With --self-test, each pinned call is removed from an in-memory copy of the
sources, and every trigger pattern covering each required file is removed from
an in-memory copy of the workflow; the guard must then fail, naming that call
or that file.
"""

import re
import sys
from pathlib import Path

SOURCES = {
    "manager": "validator/manager.cpp",
    "cache": "validator/candidate-data-cache.h",
    "waiter": "validator/downloaders/wait-block-data.cpp",
    "exporter": "metrics/prometheus-exporter.cpp",
    "families": "metrics/chain-progress-metrics.h",
    "budget": "validator/full-node-shard-admission.h",
    "fullnode": "validator/full-node.hpp",
}

WORKFLOW = ".github/workflows/node-health-monitor.yml"
# Files whose change must trigger the workflow: every pinned source, and the
# logic, declarations and tests the workflow's jobs exercise through them.
TRIGGERED = sorted(
    set(SOURCES.values())
    | {
        "validator/sync-stall-alerts.h",
        "validator/downloaders/wait-block-data.hpp",
        "validator/manager.hpp",
        "metrics/node-state-snapshot.h",
        "test/test-sync-stall-alerts.cpp",
        "test/test-health-native-snapshot.cpp",
        "test/test-full-node-shard-admission.cpp",
        "tools/node-health-monitor/tests/native-snapshot-http.py",
        "scripts/check-sync-stall-wiring.py",
    }
)

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
            "create_block(id, data.clone());",
            "return false;",
            "cached_block_data_.get_if_valid(id, valid, false)",
        ],
    ),
    ("cache", "const td::BufferSlice *get_if_valid(", ["if (!valid(*data)) {", "erase(key);"]),
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
    (
        "families",
        "inline std::vector<metrics::MetricFamily> chain_progress_families(",
        [
            '"_full_node_refusal_answers_total"',
            "gauges.refusal_answers.answered.load(",
            '"_full_node_refusal_answers_suppressed_total"',
            "gauges.refusal_answers.suppressed.load(",
        ],
    ),
    (
        "budget",
        "bool try_take(",
        [
            "sink_->suppressed.fetch_add(1, std::memory_order_relaxed);",
            "sink_->answered.fetch_add(1, std::memory_order_relaxed);",
        ],
    ),
    ("fullnode", "class FullNodeImpl : public FullNode", ["&health::node_state.refusal_answers"]),
]


class UnsupportedTrigger(ValueError):
    pass


def pull_request_paths(workflow):
    """The workflow's on.pull_request.paths patterns, in order.

    Only the block shape this workflow uses is read; any other shape, an
    exclusion pattern or a paths-ignore list is refused rather than guessed.
    """
    lines = workflow.splitlines()
    try:
        on = lines.index("on:")
    except ValueError as exc:
        raise UnsupportedTrigger("no top-level 'on:' block") from exc
    block = []
    for line in lines[on + 1 :]:
        if line and not line.startswith(" "):
            break
        block.append(line)
    try:
        pr = block.index("  pull_request:")
    except ValueError as exc:
        raise UnsupportedTrigger("no 'pull_request:' trigger with keys") from exc
    keys = []
    patterns = None
    for line in block[pr + 1 :]:
        if line.startswith("  ") and not line.startswith("    "):
            break
        if line.startswith("    ") and not line.startswith("     "):
            keys.append(line.strip())
            if line.strip() == "paths:":
                patterns = []
            continue
        if patterns is None or keys[-1] != "paths:":
            raise UnsupportedTrigger(f"unsupported pull_request entry {line!r}")
        m = re.fullmatch(r"      - '([^'\n]+)'", line)
        if m is None:
            raise UnsupportedTrigger(f"unsupported paths entry {line!r}")
        patterns.append(m.group(1))
    if keys != ["paths:"]:
        raise UnsupportedTrigger(f"unsupported pull_request keys {keys}")
    if not patterns:
        raise UnsupportedTrigger("pull_request has an empty paths list")
    for pattern in patterns:
        if pattern.startswith("!") or re.search(r"[?\[\]{}+]", pattern):
            raise UnsupportedTrigger(f"unsupported pattern syntax {pattern!r}")
    return patterns


def glob_regex(pattern):
    """GitHub path filter semantics for * and **: * stays within one path
    segment, ** crosses segments, and **/ also matches no directory."""
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out))


def covering(patterns, path):
    return [p for p in patterns if glob_regex(p).fullmatch(path)]


def trigger_problems(workflow):
    try:
        patterns = pull_request_paths(workflow)
    except UnsupportedTrigger as exc:
        return [f"{WORKFLOW}: unsupported trigger: {exc}"]
    return [
        f"{WORKFLOW}: pull_request paths do not cover {path}"
        for path in TRIGGERED
        if not covering(patterns, path)
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
    workflow = (root / WORKFLOW).read_text()
    current = problems(texts) + trigger_problems(workflow)
    if current:
        for problem in current:
            print(f"SYNC_STALL_WIRING_FAILURE: {problem}")
        return 1
    if not self_test:
        print(
            f"sync-stall wiring: {sum(len(r[2]) for r in REQUIRED)} calls in place, "
            f"{len(TRIGGERED)} files trigger the workflow"
        )
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
    survivors += trigger_self_test(workflow)
    for survivor in survivors:
        print(f"SYNC_STALL_WIRING_SELF_TEST_FAILURE: {survivor}")
    if survivors:
        return 1
    print(
        f"sync-stall wiring self-test: {mutants} call removals and {len(TRIGGERED)} trigger "
        "removals, all detected"
    )
    return 0


def trigger_self_test(workflow):
    """Removing each required file's trigger patterns must fail on that file
    alone; the glob semantics must hold; unsupported shapes must be refused."""
    survivors = []
    patterns = pull_request_paths(workflow)
    for path in TRIGGERED:
        drop = {f"      - '{p}'\n" for p in covering(patterns, path)}
        kept = [line for line in workflow.splitlines(keepends=True) if line not in drop]
        found = trigger_problems("".join(kept))
        if found != [f"{WORKFLOW}: pull_request paths do not cover {path}"]:
            survivors.append(f"removing the trigger for {path} gave {found}")
    semantics = [
        ("metrics/*", "metrics/a.h", True),
        ("metrics/*", "metrics/sub/a.h", False),
        ("metrics/**", "metrics/sub/a.h", True),
        ("test/test-health-*.cpp", "test/test-health-x.cpp", True),
        ("test/test-health-*.cpp", "test/sub/test-health-x.cpp", False),
        ("**/a.h", "a.h", True),
        ("**/a.h", "x/y/a.h", True),
        ("validator/manager.cpp", "validator/manager.hpp", False),
        ("validator/manager.cpp", "validator/manager_cpp", False),
    ]
    for pattern, path, expected in semantics:
        if bool(glob_regex(pattern).fullmatch(path)) != expected:
            survivors.append(f"glob {pattern!r} on {path!r} is not {expected}")
    for bad in (
        workflow.replace("      - 'metrics/**'\n", "      - '!metrics/**'\n"),
        workflow.replace("    paths:\n", "    paths-ignore:\n"),
        workflow.replace("      - 'metrics/**'\n", "      - metrics/**\n"),
        workflow.replace("      - 'metrics/**'\n", "      - 'metrics/[ab]*'\n"),
    ):
        if bad == workflow:
            survivors.append("a refusal control did not change the workflow")
            continue
        found = trigger_problems(bad)
        if len(found) != 1 or "unsupported trigger" not in found[0]:
            survivors.append(f"an unsupported trigger shape was not refused: {found}")
    return survivors


if __name__ == "__main__":
    sys.exit(main())
