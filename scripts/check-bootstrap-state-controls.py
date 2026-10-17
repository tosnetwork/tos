#!/usr/bin/env python3
"""Prove bootstrap readiness tests observe the guards they protect.

Run only after other builds have stopped. Each local source mutation is compiled
and must fail its targeted runtime assertion. Original sources and green binaries
are restored in finally; full logs stay in the requested output directory.
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--mutation", help="Run one named control, with baseline and restoration")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    build = args.build_dir.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    transport = "bootstrap_readiness_routes_the_exact_id_and_does_not_cache_availability"
    native = "validator/bootstrap-state.cpp"
    # name, source, original, replacement, target, test, expected failure text
    mutations = [
        (
            "missing-account-part",
            native,
            "for (const auto &part : parts.ok()) {",
            "for (const auto &part : std::vector<SplitStatePart>{}) {",
            "test-bootstrap-state",
            "SplitHeaderRequiresOnlyNonemptyParts",
            "!missing_part.ready",
        ),
        (
            "truncated-file",
            native,
            "if (first.size() != 1 || last.size() != 1) {",
            "if (first.size() != 1) {",
            "test-bootstrap-state",
            "CachedSizeDoesNotProveReadableFile",
            "!run_readiness(archive).ready",
        ),
        (
            "missing-proof",
            native,
            "if (root.is_error()) {",
            "if (false && root.is_error()) {",
            "test-bootstrap-state",
            "RequiresArchivedShardProof",
            "!missing.ready",
        ),
        (
            "stalled-deadline",
            native,
            "td::actor::await_with_timeout(\n"
            "          scan_bootstrap_state(std::move(description), archive_ttl, now, std::move(reader), deadline), deadline)",
            "scan_bootstrap_state(std::move(description), archive_ttl, now, std::move(reader), deadline)",
            "test-bootstrap-state",
            "DeadlineRespondsWhileReadIsStalledAndKeepsAdmissionLease",
            "Deadlock detected",
        ),
        (
            "manifest-budget",
            native,
            "if (description->shard_blocks.size() >= kMaxStateFiles) {",
            "if (false) {",
            "test-bootstrap-state",
            "ResourceBudgetsRefuseBeforeUnboundedReads",
            "manifest->reads",
        ),
        (
            "split-header-budget",
            native,
            "if (size.ok() > kMaxSplitHeaderBytes) {",
            "if (false) {",
            "test-bootstrap-state",
            "ResourceBudgetsRefuseBeforeUnboundedReads",
            "too_large.reason",
        ),
        (
            "concurrent-admission",
            "validator/manager.cpp",
            "if (bootstrap_queries_->load() >= 2) {",
            "if (false) {",
            "test-json-rpc-transport",
            transport,
            "client.read_response(5000, status, body)",
        ),
        (
            "stale-cached-readiness",
            "validator-engine/json-rpc-server.cpp",
            '{"getBootstrapState", R,',
            '{"getBootstrapState", R | C,',
            "test-json-rpc-transport",
            transport,
            "unavailable.find",
        ),
    ]
    if args.mutation:
        mutations = [item for item in mutations if item[0] == args.mutation]
        if not mutations:
            parser.error("unknown mutation: " + args.mutation)
    originals = {item[1]: (root / item[1]).read_bytes() for item in mutations}
    for name, source, anchor, *_ in mutations:
        if originals[source].count(anchor.encode()) != 1:
            raise RuntimeError(name + ": expected exactly one mutation anchor")
    targets = sorted({item[4] for item in mutations})
    results = {}

    def run(name, command, timeout=None):
        print(name, flush=True)
        with (output / (name + ".log")).open("wb") as log:
            result = subprocess.run(
                command, cwd=root, stdout=log, stderr=subprocess.STDOUT, timeout=timeout
            )
        results[name] = result.returncode
        return result.returncode

    def build_target(name, target):
        if run(
            name + "-build",
            ["cmake", "--build", str(build), "--target", target, "-j", str(args.jobs)],
        ):
            raise RuntimeError(name + ": build failed; this is not a passing control")

    def test_target(name, target, test=None):
        command = [str(build / target)]
        if test:
            command += ["--filter", test]
        return run(name, command, timeout=60)

    def green(name):
        for target in targets:
            label = name + "-" + target
            build_target(label, target)
            if test_target(
                label, target, transport if target == "test-json-rpc-transport" else None
            ):
                raise RuntimeError(label + ": expected green")

    def restore_sources():
        for path, data in originals.items():
            if (root / path).read_bytes() != data:
                (root / path).write_bytes(data)

    green("baseline")
    try:
        for name, source, anchor, replacement, target, test, assertion in mutations:
            restore_sources()
            (root / source).write_bytes(
                originals[source].replace(anchor.encode(), replacement.encode())
            )
            build_target(name, target)
            if test_target(name, target, test) == 0:
                raise RuntimeError(name + ": removing the guard unexpectedly passed")
            failure = (output / (name + ".log")).read_text(errors="replace")
            if test not in failure or assertion not in failure:
                raise RuntimeError(name + ": did not reach the expected runtime assertion")
    finally:
        restore_sources()
        try:
            green("restored")
        finally:
            evidence = {
                "scope": "archive completeness, actual deadline, manager admission and uncached HTTP readiness",
                "source_sha256": {
                    path: hashlib.sha256(data).hexdigest() for path, data in originals.items()
                },
                "returncodes": results,
                "logs": {
                    path.name: {
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        "bytes": path.stat().st_size,
                    }
                    for path in sorted(output.glob("*.log"))
                },
            }
            (output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
