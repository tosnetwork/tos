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
        and ast.unparse(node.test) == "self.fixture_only or self.pq_election"
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
    binding_preflight = one_call(execute, "require_pq_stake_authorization_binding")
    if not binding_preflight < one_call(execute, "prepare_artifact_snapshot") < min(node_boots):
        fail("generated Python TL binding is not checked before snapshot and PQ node boot")
    snapshot = method(tree, "prepare_artifact_snapshot")
    snapshot_text = ast.unparse(snapshot)
    if (
        "pq_stake_authorization_python_tl" not in snapshot_text
        or "test/tostester/src/tosapi/tos_api.py" not in snapshot_text
        or "tl/generate/scheme/tos_api.tl" not in snapshot_text
        or "shutil.copy2(REPO / schema_relative, schema_target)" not in snapshot_text
        or "'schema': self.file_provenance(schema_target)" not in snapshot_text
    ):
        fail("artifact snapshot no longer retains and hashes the PQ authorization TL schema and generated binding")
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
    console = (root / "toslib/toslib/EngineConsoleClient.cpp").read_text()
    if "case tos::tos_api::engine_validator_createPqStakeAuthorization::ID:" not in console:
        fail("Python engine-console transport no longer admits the PQ stake authorization query")

    order = method(tree, "authorized_pq_pool_order")
    candidate = method(tree, "submit_pq_candidate")
    if len(call_lines(candidate, "authorized_pq_pool_order")) != 1:
        fail("PQ candidate no longer uses the shared authorization and production pool-order path")
    if len(call_lines(order, "Engine_validator_createPqStakeAuthorizationRequest")) != 1:
        fail("shared PQ pool order no longer asks the node for a stake authorization")
    if len(call_lines(order, "build_production_pool_stake_order")) != 1:
        fail("shared PQ pool order no longer uses the production Rust builder")
    fixture = root / "test/tostester/src/tostester/pq_election_fixture.py"
    builder = method(ast.parse(fixture.read_text(), filename=str(fixture)),
                     "build_production_pool_stake_order")
    builder_calls = [
        node for node in ast.walk(order)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "build_production_pool_stake_order"
    ]
    passed = {keyword.arg for keyword in builder_calls[0].keywords}
    accepted = {argument.arg for argument in builder.args.kwonlyargs}
    if len(builder_calls[0].args) != 1 or passed != accepted:
        fail(
            "shared PQ pool order and production bridge keyword interface differ: "
            f"missing={sorted(accepted - passed)} unexpected={sorted(passed - accepted)}"
        )
    bridge = (root / "tosctl/src/node-control/contracts/examples/pq_pool_stake_order.rs").read_text()
    if not re.search(r"\blet body\s*=\s*new_stake_with_witness\s*\(", bridge):
        fail("live PQ pool-order bridge no longer calls nominator::new_stake_with_witness")
    if "Some(&witness)" not in bridge:
        fail("live PQ pool-order bridge no longer carries the controller birth witness")
    if any(call_lines(path, "election_body") or call_lines(path, "sign") for path in (order, candidate)):
        fail("shared PQ stake path constructs a classical preimage or signs locally")
    order_text = ast.unparse(order)
    candidate_text = ast.unparse(candidate)
    for expression, property_name in (
        ("stake_owner=pool.address.hash_part", "pool-owned authorization"),
        ("signature=auth.signature", "node-produced PQ signature"),
    ):
        if expression not in order_text:
            fail(f"shared PQ pool order lost {property_name}: expected {expression}")
    for expression, property_name in (
        ("dest=pool.address", "pool rather than elector destination"),
        ("stake_accepted=True", "accepted stake outcome field"),
    ):
        if expression not in candidate_text:
            fail(f"PQ candidate lost {property_name}: expected {expression}")
    if not any(
        isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Name) and node.left.id == "opcode"
        and len(node.ops) == 1 and isinstance(node.ops[0], ast.NotEq)
        and len(node.comparators) == 1
        and isinstance(node.comparators[0], ast.Constant)
        and node.comparators[0].value == 0xF374484C
        for node in ast.walk(candidate)
    ):
        fail("PQ candidate no longer refuses a reply other than STAKE_ACCEPTED")
    negative = method(tree, "assert_unwitnessed_wallet_stake_refused")
    negative_text = ast.unparse(negative)
    if "reason != 8" not in negative_text or not call_lines(negative, "elector_reply"):
        fail("negative wallet no longer pins elector admission reason 8")
    if not any(
        isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Name) and node.left.id == "opcode"
        and len(node.ops) == 1 and isinstance(node.ops[0], ast.NotEq)
        and len(node.comparators) == 1
        and isinstance(node.comparators[0], ast.Constant)
        and node.comparators[0].value == 0xEE6F454C
        for node in ast.walk(negative)
    ):
        fail("negative wallet no longer requires an elector return-stake opcode")
    if not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute) and node.func.attr == "store_uint"
        and len(node.args) >= 1 and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == 0x50517374
        for node in ast.walk(negative)
    ):
        fail("negative wallet no longer uses the elector PQst opcode")
    election = method(tree, "run_pq_first_election")
    negative_line = one_call(election, "assert_unwitnessed_wallet_stake_refused")
    positive_line = one_call(election, "submit_pq_candidate")
    if negative_line >= positive_line:
        fail("negative wallet no-witness control no longer precedes positive stakes")
    election_text = ast.unparse(election)
    if "participant_ids != expected_ids" not in election_text:
        fail("PQ election no longer requires exactly the four controller participants")
    if "value.utime_since == self.first_election_id" not in election_text:
        fail("PQ election no longer requires live ConfigParam 34 activation")
    if "actual_ids != expected_ids_hex" not in election_text or "self.first_config34.total != VALIDATOR_COUNT" not in election_text:
        fail("PQ election no longer requires exactly four controller IDs in live ConfigParam 34")
    config_reader = method(tree, "get_config34")
    if "validator_id:x([0-9A-Fa-f]{64})" not in ast.unparse(config_reader):
        fail("live ConfigParam 34 reader no longer extracts PQ validator IDs")
    print(
        "PQ_ELECTION_FIXTURE_SOURCE_OK: controller identity is asserted before boot; "
        "the live Param 47 read-back call precedes deployment; "
        "the Genesis helper contains 47 config!; "
        "Python engine-console transport admits the PQ authorization query; "
        "generated TL response fields are checked before snapshot/node boot and hashed in the snapshot; "
        "PQ candidates call the shared node-authorized, keyword-compatible Rust nominator::new_stake_with_witness pool-order path; "
        "STAKE_ACCEPTED, exact controller participants, and activated ConfigParam 34 with exact PQ IDs are required; "
        "reason-8 negative control precedes positive stakes"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, SyntaxError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
