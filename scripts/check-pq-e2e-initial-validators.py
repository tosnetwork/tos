#!/usr/bin/env python3
"""Keep retained chain E2E entry points on one deterministic PQ validator helper."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

HELPER_MODULE = "tostester.pq_initial_validator"
HELPER_NAME = "make_deterministic_pq_initial_validator"
LOW_LEVEL_METHODS = frozenset({
    "make_initial_validator",
    "make_initial_pq_validator",
    "make_noninitial_pq_validator",
})
EXPECTED_CALLS = {
    "test/integration/test_simplex2_release.py": 1,
    "scripts/localnet-jsonrpc.py": 1,
    "scripts/agent-wallet-account-e2e.py": 1,
    "scripts/agent-query-api-e2e.py": 1,
    "scripts/agent-chain-index-e2e.py": 1,
    "scripts/agent-task-escrow-e2e.py": 1,
    "scripts/proof-attestation-e2e.py": 1,
    "scripts/capability-registry-e2e.py": 1,
    "scripts/agent-economy-composed-e2e.py": 1,
    "scripts/validator-election-stage-a.py": 2,
    "scripts/dispute-e2e.py": 1,
    "scripts/service-actor-e2e.py": 1,
    "scripts/wc0-token-index-e2e.py": 1,
    "scripts/dns-e2e.py": 2,
    "scripts/nominator-pool-lifecycle-e2e.py": 1,
}


def fail(message: str) -> None:
    raise RuntimeError(f"PQ_E2E_INITIAL_VALIDATOR_FAILURE: {message}")


def imported_helper(tree: ast.AST) -> bool:
    return any(
        isinstance(node, ast.ImportFrom)
        and node.module == HELPER_MODULE
        and any(alias.name == HELPER_NAME and alias.asname is None for alias in node.names)
        for node in ast.walk(tree)
    )


def helper_calls_in(node: ast.AST) -> int:
    return sum(
        isinstance(child, ast.Call)
        and isinstance(child.func, ast.Name)
        and child.func.id == HELPER_NAME
        for child in ast.walk(node)
    )


def forbidden_bypasses(tree: ast.AST) -> list[tuple[str, int]]:
    """Find low-level method references, including bound aliases and literal getattr."""
    bypasses: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in LOW_LEVEL_METHODS:
            bypasses.append((node.attr, node.lineno))
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
            and node.args[1].value in LOW_LEVEL_METHODS
        ):
            bypasses.append((f"getattr(..., {node.args[1].value!r})", node.lineno))
    return bypasses


def n6_cluster_imports(tree: ast.AST) -> list[int]:
    """The N6 soak helper provisions keys directly and is not a retained E2E route."""
    lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(
            alias.name == "tostester.n6_cluster" for alias in node.names
        ):
            lines.append(node.lineno)
        if isinstance(node, ast.ImportFrom) and (
            node.module == "tostester.n6_cluster"
            or (node.module == "tostester"
                and any(alias.name == "n6_cluster" for alias in node.names))
        ):
            lines.append(node.lineno)
    return lines


def check_detector_controls() -> None:
    """A clean scan is credible only while each known bypass remains detectable."""
    controls = {
        "getattr initial": ("getattr(node, 'make_initial_pq_validator')(id, seed)", "getattr"),
        "bound method": ("provision = node.make_initial_validator\nprovision()", "make_initial_validator"),
        "direct spare": ("node.make_noninitial_pq_validator(id, seed)", "make_noninitial_pq_validator"),
    }
    for name, (source, marker) in controls.items():
        if not any(marker in method for method, _ in forbidden_bypasses(ast.parse(source))):
            fail(f"detector control missed {name}")
    if forbidden_bypasses(ast.parse("getattr(os, 'O_CLOEXEC', 0)")):
        fail("detector control marked an unrelated getattr as validator provisioning")
    for source in (
        "import tostester.n6_cluster",
        "from tostester import n6_cluster",
        "from tostester.n6_cluster import run_cluster",
    ):
        if len(n6_cluster_imports(ast.parse(source))) != 1:
            fail("detector control missed a direct N6 soak helper import")


def check_election_branches(tree: ast.AST) -> None:
    """Both launch fixture and legacy network paths must use the shared helper."""
    execute = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "execute"
    ]
    if len(execute) != 1:
        fail("scripts/validator-election-stage-a.py: execute method is absent or ambiguous")
    branches = [
        node for node in ast.walk(execute[0])
        if isinstance(node, ast.If)
        and ast.unparse(node.test) == "self.fixture_only or self.pq_election"
        and node.orelse
        and any(helper_calls_in(child) for child in node.body + node.orelse)
    ]
    if len(branches) != 1:
        fail("scripts/validator-election-stage-a.py: PQ/legacy validator provisioning split is absent")
    branch = branches[0]
    pq_calls = sum(helper_calls_in(child) for child in branch.body)
    legacy_calls = sum(helper_calls_in(child) for child in branch.orelse)
    if pq_calls != 1 or legacy_calls != 1:
        fail(
            "scripts/validator-election-stage-a.py: each PQ/legacy provisioning branch "
            f"must call the shared helper once: pq={pq_calls} legacy={legacy_calls}"
        )


def main() -> int:
    check_detector_controls()
    root = (
        Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else Path(__file__).resolve().parents[1]
    )
    failures: list[str] = []
    for relative, expected_count in EXPECTED_CALLS.items():
        path = root / relative
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if not imported_helper(tree):
            failures.append(f"{relative}: does not import {HELPER_MODULE}.{HELPER_NAME}")
        helper_calls = 0
        forbidden = forbidden_bypasses(tree)
        failures.extend(
            f"{relative}:{line}: imports the N6 soak helper with direct validator provisioning"
            for line in n6_cluster_imports(tree)
        )
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id == HELPER_NAME:
                helper_calls += 1
        if helper_calls != expected_count:
            failures.append(
                f"{relative}: has {helper_calls} shared helper calls, expected {expected_count}"
            )
        if relative == "scripts/validator-election-stage-a.py":
            check_election_branches(tree)
        failures.extend(
            f"{relative}:{line}: bypasses the shared helper via {name}" for name, line in forbidden
        )
    if failures:
        fail("; ".join(failures))
    print(
        "PQ_E2E_INITIAL_VALIDATOR_OK: "
        f"{len(EXPECTED_CALLS)} retained entry points use "
        f"{sum(EXPECTED_CALLS.values())} shared deterministic PQ validator calls; "
        "the election rehearsal has one call in each PQ and legacy provisioning branch; "
        "no low-level validator method attribute reference, literal getattr of those methods, "
        "or direct N6 soak-helper import appears"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, SyntaxError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
