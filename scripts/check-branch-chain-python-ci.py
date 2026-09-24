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
    "test-consensus",
    "test-notarize-after-transient-resolve",
}

RESTART_ORIGIN_TESTS = (
    "test-consensus-simplex2-pq-empty-chain-restart",
    "test-consensus-simplex2-pq-restart-transient-anchor",
    "test-consensus-simplex2-pq-restart-transient-anchor-zerostate-control",
    "test-consensus-simplex2-pq-restart-transient-origin",
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
    c05_ctest = "ctest --test-dir build --output-on-failure -R '^c05-notarize-'"
    require(
        re.search(rf"(?m)^\s*run: {re.escape(c05_ctest)}\s*$", text) is not None,
        "Simplex parent-state retry voting behavior gate is absent",
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
        "the pending-finality manager actor and the C05 parent-state retry CTest selector, "
        "and four restart-origin controls, "
        "and compiles every Rust test target"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
