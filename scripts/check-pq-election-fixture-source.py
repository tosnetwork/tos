#!/usr/bin/env python3
"""Pin the launch-fixture wiring; the live fixture-check tests its behavior."""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise RuntimeError(f"PQ_ELECTION_FIXTURE_SOURCE_FAILURE: {message}")


def method(tree: ast.Module, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    matches = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]
    if len(matches) != 1:
        fail(f"{name} exists {len(matches)} times, expected one")
    return matches[0]


def call_lines(body: ast.AST, name: str) -> list[int]:
    return [
        node.lineno for node in ast.walk(body)
        if isinstance(node, ast.Call)
        and (
            isinstance(node.func, ast.Name) and node.func.id == name
            or isinstance(node.func, ast.Attribute) and node.func.attr == name
        )
    ]


def one_call(body: ast.AST, name: str) -> int:
    lines = call_lines(body, name)
    if len(lines) != 1:
        fail(f"{name} appears at {lines}, expected one call")
    return lines[0]


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else Path(__file__).resolve().parents[1]
    script = root / "scripts/validator-election-stage-a.py"
    tree = ast.parse(script.read_text(), filename=str(script))
    execute = method(tree, "execute")
    fixture_branches = [
        node for node in ast.walk(execute) if isinstance(node, ast.If)
        and isinstance(node.test, ast.Attribute)
        and isinstance(node.test.value, ast.Name)
        and node.test.value.id == "self" and node.test.attr == "fixture_only"
        and any(call_lines(child, "assert_controller_identity") for child in node.body)
    ]
    if len(fixture_branches) != 1:
        fail("fixture provisioning branch with controller identity assertion is absent")
    fixture_body = ast.Module(body=fixture_branches[0].body, type_ignores=[])
    provision = one_call(fixture_body, "make_deterministic_pq_initial_validator")
    identity = one_call(fixture_body, "assert_controller_identity")
    provisioning_calls = [
        node for node in ast.walk(fixture_body)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "make_deterministic_pq_initial_validator"
    ]
    identity_keywords = [
        keyword for keyword in provisioning_calls[0].keywords
        if keyword.arg == "validator_id"
    ]
    if len(identity_keywords) != 1 or ast.unparse(identity_keywords[0].value) != "controller.address.hash_part":
        fail("fixture node validator_id is not derived from the controller address")
    # `run` also appears in the subprocess and experiment setup. Require the
    # immediately visible node boot to follow the binding, not a text regex for
    # a particular indentation or spelling of the node collection.
    node_boots = [
        node.lineno for node in ast.walk(execute)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "node"
        and node.func.attr == "run"
    ]
    if not node_boots or not provision < identity < min(node_boots):
        fail("controller address equality is not asserted after provisioning and before node boot")
    client = one_call(execute, "toslib_client")
    policy = one_call(execute, "verify_live_controller_policy")
    wallets = one_call(execute, "setup_wallets")
    deploy = one_call(execute, "deploy_pq_fixture_accounts")
    if not client < policy < wallets < deploy:
        fail("live controller policy read-back does not precede fixture account deployment")

    profile = method(tree, "configure_network_profile")
    fields = [
        target.attr for node in ast.walk(profile) if isinstance(node, ast.Assign)
        for target in node.targets if isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name) and target.value.id == "config"
    ]
    for required in ("validator_controller_code_hash", "global_version"):
        if required not in fields:
            fail(f"fixture profile does not set {required}")

    fift = (root / "crypto/fift/lib/Config.fif").read_text()
    helper = re.search(
        r"\{(?P<body>[^{}]*)\}\s*:\s*config\.validator_controller_code!",
        fift,
    )
    body = "" if helper is None else re.sub(r"//[^\n]*", "", helper.group("body"))
    if not re.search(r"\b47\s+config!(?:\s|$)", body):
        fail("named Genesis helper no longer installs ConfigParam 47 with config!")
    genesis = (root / "test/tostester/src/tostester/zerostate.py").read_text()
    if "{controller_policy_param}" not in genesis or "config.validator_controller_code!" not in genesis:
        fail("zerostate no longer invokes the Config.fif policy helper")
    print(
        "PQ_ELECTION_FIXTURE_SOURCE_OK: controller identity is asserted before boot; "
        "the live Param 47 read-back call precedes deployment; "
        "the Genesis helper contains 47 config!"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, SyntaxError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
