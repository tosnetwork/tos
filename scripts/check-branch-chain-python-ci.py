#!/usr/bin/env python3
"""Pin branch CI coverage for the Python suite and a real PQ chain boot."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REQUIRED_NATIVE_TARGETS = {
    "gen_fif",
    "create-state",
    "toslibjson",
    "generate-random-id",
    "tos-pq-consensus-key",
    "dht-server",
    "validator-engine-console",
    "validator-engine",
    "test-pq-lite-forward-proof",
    "test-pending-finality-cache",
    "test-c04-real-state-proof",
    "test-n5-manager-db-fixture",
    "test-consensus",
    "test-notarize-after-transient-resolve",
}

RESTART_ORIGIN_TESTS = (
    "test-consensus-simplex2-pq-empty-chain-restart",
    "test-consensus-simplex2-pq-restart-transient-anchor",
    "test-consensus-simplex2-pq-restart-transient-anchor-zerostate-control",
    "test-consensus-simplex2-pq-restart-transient-origin",
    "test-consensus-simplex2-pq-restart-permanent-origin",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"BRANCH_CHAIN_PYTHON_CI_FAILURE: {message}")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    workflow = root / ".github/workflows/branch-chain-python.yml"
    text = workflow.read_text(encoding="utf-8")
    require(re.search(r"(?m)^on:\s*$", text) is not None, "workflow has no trigger map")
    require(re.search(r"(?m)^  push:\s*$", text) is not None, "workflow does not run on pushes")
    require(
        re.search(r"(?m)^  pull_request:\s*$", text) is not None,
        "workflow does not run on pull requests",
    )
    require(
        "branches:" not in text.split("permissions:", 1)[0],
        "workflow restricts branch triggers",
    )
    # This workflow's only purpose is to run on every push and pull request.
    # Refuse conditions anywhere in the file: a job- or step-level `if:` is
    # how the existing real-chain job became a green-looking skipped check.
    require("if:" not in text, "workflow makes a job or step conditional")
    require("uv sync --no-dev" in text, "workflow does not install repository Python dependencies")
    require(
        "test/tostester/generate_tl.py" in text,
        "workflow does not generate the ignored Python TL API",
    )
    require(re.search(r"(?m)^\s*run: uv run pytest\s*$", text) is not None, "full pytest is absent")
    require(
        "uv run python test/integration/test_basic.py" in text,
        "four-validator PQ chain regression is absent",
    )
    require(
        "ctest --test-dir build --output-on-failure -R '^test-pq-lite-forward-proof$'" in text,
        "PQ key-block proof context behavior gate is absent",
    )
    manager_ctest = "ctest --test-dir build --output-on-failure -R '^test-pending-finality-cache$'"
    require(
        re.search(rf"(?m)^\s*run: {re.escape(manager_ctest)}\s*$", text) is not None,
        "pending PQ finality manager actor behavior gate is absent",
    )
    real_state_ctest = "ctest --test-dir build --output-on-failure -R '^test-c04-real-state-proof$'"
    require(
        re.search(rf"(?m)^\s*run: {re.escape(real_state_ctest)}\s*$", text) is not None,
        "real PQ predecessor and BlockProof component gate is absent",
    )
    for test_name, boundary in (
        ("test-n5-manager-db-fixture", "FinalCert journal cold read"),
        ("test-n5-accept-block", "PQ AcceptBlock cold read"),
        ("test-n5-joined-finalcert", "same-FinalCert actor and cold persistence path"),
        ("test-n5-cut1-finalcert-recovery", "FinalCert write-after bootstrap recovery"),
        ("test-n5-cut2-signatures-recovery", "#13 signature write-after bootstrap recovery"),
        ("test-n5-cut3-proof-recovery", "BlockProof write-after bootstrap recovery"),
    ):
        command = f"ctest --test-dir build --output-on-failure -R '^{test_name}$'"
        require(
            re.search(rf"(?m)^\s*run: {re.escape(command)}\s*$", text) is not None,
            f"N5 {boundary} behavior gate is absent: {test_name}",
        )
    cmake = (root / "CMakeLists.txt").read_text(encoding="utf-8")
    require(
        re.search(
            r"(?s)add_test\(NAME test-n5-accept-block COMMAND test-c04-real-state-proof "
            r"--n5-accept\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}/test/pq-native/data/c04-pq-genesis\.boc\)",
            cmake,
        ) is not None,
        "N5 AcceptBlock CTest is absent or no longer invokes the production-fixture mode",
    )
    require(
        re.search(
            r"tos_test\(test-n5-manager-db-fixture\s+"
            r"\$\{CMAKE_CURRENT_SOURCE_DIR\}/test/pq-native/data/c04-pq-genesis\.boc\)",
            cmake,
        ) is not None,
        "N5 FinalCert journal CTest is absent",
    )
    require(
        re.search(
            r"(?s)add_test\(NAME test-n5-joined-finalcert COMMAND test-c04-real-state-proof "
            r"--n5-joined\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}/test/pq-native/data/c04-pq-genesis\.boc\)",
            cmake,
        ) is not None,
        "N5 same-FinalCert actor CTest is absent or no longer invokes its joined mode",
    )
    require(
        re.search(
            r"(?s)add_test\(NAME test-n5-cut1-finalcert-recovery COMMAND test-c04-real-state-proof "
            r"--n5-cut1\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}/test/pq-native/data/c04-pq-genesis\.boc\)",
            cmake,
        ) is not None,
        "N5 write-after recovery CTest is absent or no longer invokes its cut1 mode",
    )
    require(
        re.search(
            r"(?s)add_test\(NAME test-n5-cut2-signatures-recovery COMMAND test-c04-real-state-proof "
            r"--n5-cut2\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}/test/pq-native/data/c04-pq-genesis\.boc\)",
            cmake,
        ) is not None,
        "N5 #13 write-after recovery CTest is absent or no longer invokes its cut2 mode",
    )
    require(
        re.search(
            r"(?s)add_test\(NAME test-n5-cut3-proof-recovery COMMAND test-c04-real-state-proof "
            r"--n5-cut3\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}/test/pq-native/data/c04-pq-genesis\.boc\)",
            cmake,
        ) is not None,
        "N5 BlockProof write-after recovery CTest is absent or no longer invokes its cut3 mode",
    )
    c05_ctest = "ctest --test-dir build --output-on-failure -R '^c05-notarize-'"
    require(
        re.search(rf"(?m)^\s*run: {re.escape(c05_ctest)}\s*$", text) is not None,
        "Simplex parent-state retry voting behavior gate is absent",
    )
    consensus_tests = (root / "test/validator/consensus/CMakeLists.txt").read_text(encoding="utf-8")
    for test_name, fault_count in (
        ("c05-notarize-simultaneous-recovery", 3),
        ("c05-notarize-simultaneous-overbudget", 24),
    ):
        require(
            re.search(rf"(?m)^\s*NAME {re.escape(test_name)}\s*$", consensus_tests) is not None
            and re.search(
                rf'(?m)^set_tests_properties\({re.escape(test_name)} PROPERTIES\s*\n'
                rf'\s*ENVIRONMENT "TOS_TEST_C05_SIMULTANEOUS_FAULTS={fault_count}"\)\s*$',
                consensus_tests,
            ) is not None,
            f"C05 four-node behavior CTest is absent or has wrong fault budget: {test_name}",
        )
    for test_name in RESTART_ORIGIN_TESTS:
        command = f"ctest --test-dir build --output-on-failure -R '^{test_name}$'"
        require(
            re.search(rf"(?m)^\s*{re.escape(command)}\s*$", text) is not None,
            f"Simplex restart-origin behavior gate is absent: {test_name}",
        )
    rust_job = re.search(
        r"(?ms)^  rust-workspace-tests-compile:\s*\n(?P<body>.*?)(?=^  [\w-]+:\s*$|\Z)",
        text,
    )
    require(rust_job is not None, "all-crate Rust test compilation job is absent")
    require(
        re.search(
            r"(?m)^\s*run: cargo check --manifest-path tosctl/src/Cargo.toml --workspace --tests --locked\s*$",
            rust_job.group("body"),
        )
        is not None,
        "all-crate Rust test compilation is absent or scoped to an allowlist",
    )
    zero_stats = text.find("ccache --zero-stats")
    native_build = text.find("cmake --build build --parallel 4 --target")
    show_stats = text.find("ccache --show-stats")
    require(
        -1 < zero_stats < native_build < show_stats,
        "native cache statistics do not bracket the fixture build",
    )
    cache_key = "${{ runner.os }}-${{ runner.arch }}-branch-pq-chain-${{ github.sha }}"
    restore_prefix = "${{ runner.os }}-${{ runner.arch }}-branch-pq-chain-"
    require(f"key: {cache_key}" in text, "native cache key is not commit-specific")
    require(
        f"restore-keys: {restore_prefix}" in text,
        "native cache cannot restore the newest prior branch entry",
    )
    require("continue-on-error" not in text, "workflow permits a guarded step to fail")

    target_command = re.search(
        r"cmake --build build --parallel 4 --target\s+\\?\s*(?P<targets>(?:\s*[\w-]+\s*\\?\s*)+)",
        text,
    )
    require(target_command is not None, "minimal native target command is missing")
    observed_targets = set(target_command.group("targets").replace("\\", "").split())
    require(
        REQUIRED_NATIVE_TARGETS <= observed_targets,
        f"native fixture targets are missing: {sorted(REQUIRED_NATIVE_TARGETS - observed_targets)}",
    )
    print(
        "BRANCH_CHAIN_PYTHON_CI_OK: every push and pull request runs full pytest, "
        "boots the four-validator PQ chain, checks PQ key-block proof context, "
        "the pending-finality manager actor and real PQ predecessor/BlockProof component, "
        "N5 FinalCert-journal, AcceptBlock, same-FinalCert, and three write-after recovery CTests, "
        "the C05 parent-state retry CTest selector "
        "and its two named four-node fault controls, "
        "and five named restart-origin controls, "
        "and compiles every Rust test target"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
