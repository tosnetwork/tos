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
    cli_text = ast.unparse(method(tree, "parse_args"))
    main_text = ast.unparse(method(tree, "async_main"))
    if "pq-launch-gate" not in cli_text or "pq_full=args.mode == 'pq-launch-gate'" not in main_text:
        fail("the opt-in full PQ launch-gate CLI no longer reaches the full rehearsal")
    genesis_profile = method(tree, "configure_network_profile")
    if "if self.pq_full:\n" not in ast.unparse(genesis_profile) or "PQ_FULL_GENESIS_FAUCET_FUNDING" not in ast.unparse(genesis_profile):
        fail("full PQ mode no longer sets its three-round faucet budget in Genesis")
    capacity_line = one_call(execute, "require_pq_full_faucet_capacity")
    if not capacity_line < one_call(execute, "run_pq_first_election"):
        fail("full PQ faucet capacity is no longer checked before the first election")
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
        ("signature = auth.signature", "node-produced PQ signature source"),
        ("signature=signature", "node-produced PQ signature in the pool body"),
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
    positive_lines = sorted(call_lines(election, "submit_pq_candidate"))
    if len(positive_lines) != 2:
        fail(f"PQ first election has {len(positive_lines)} positive stake call sites, expected three-then-four")
    restart_line = one_call(election, "restart_node")
    pool_negative_line = one_call(election, "assert_pq_first_round_negative_cases")
    duplicate_line = one_call(election, "assert_duplicate_pq_key_refused")
    activation_events = [
        node.lineno for node in ast.walk(election)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute) and node.func.attr == "event"
        and node.args and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "pq_first_election_activated"
    ]
    if len(activation_events) != 1:
        fail("PQ first election has no single activation event after live ConfigParam 34 check")
    activated_line = activation_events[0]
    liveness_line = one_call(election, "verify_three_of_four_liveness")
    recovery_line = one_call(election, "assert_pq_early_recovery_no_credit")
    if not (
        negative_line < pool_negative_line < positive_lines[0]
        < restart_line < positive_lines[1] < duplicate_line
        < activated_line < liveness_line < recovery_line
    ):
        fail("PQ first election no longer orders negative, three stakes, restart, fourth stake")
    three_loops = [
        node for node in ast.walk(election)
        if isinstance(node, ast.For)
        and ast.unparse(node.iter) == "range(VALIDATOR_COUNT - 1)"
        and call_lines(ast.Module(body=node.body, type_ignores=[]), "submit_pq_candidate")
    ]
    if len(three_loops) != 1:
        fail("PQ first election no longer submits exactly three candidates before restarting the fourth")
    election_text = ast.unparse(election)
    if "participant_ids != expected_ids" not in election_text:
        fail("PQ election no longer requires exactly the four controller participants")
    if "value.utime_since == self.first_election_id" not in election_text:
        fail("PQ election no longer requires live ConfigParam 34 activation")
    if "actual_ids != expected_ids_hex" not in election_text or "self.first_config34.total != VALIDATOR_COUNT" not in election_text:
        fail("PQ election no longer requires exactly four controller IDs in live ConfigParam 34")
    if "three_ids != expected_three" not in election_text or "three_stake < VALIDATOR_COUNT * EFFECTIVE_STAKE" not in election_text:
        fail("PQ first election no longer checks the three-candidate state below the four-validator threshold")
    for call, property_name in (
        ("assert_pq_first_round_negative_cases", "three exact elector negative controls"),
        ("restart_node", "fourth-node restart before its stake"),
        ("assert_duplicate_pq_key_refused", "duplicate held-key negative control"),
        ("verify_three_of_four_liveness", "three-of-four liveness"),
        ("assert_pq_early_recovery_no_credit", "pool-owned early-recovery refusal"),
    ):
        if not call_lines(election, call):
            fail(f"PQ first election lost {property_name}")
    if "actual_adnl != expected_adnl" not in election_text or "self.first_config34.main != VALIDATOR_COUNT" not in election_text:
        fail("PQ election no longer requires four matching ADNL identities and four main validators")
    if len(call_lines(election, "require_pq_config34_associations")) != 1:
        fail("PQ election no longer checks controller-to-ADNL pairs from the same ConfigParam 34 records")
    association = method(tree, "require_pq_config34_associations")
    if "actual != expected" not in ast.unparse(association):
        fail("PQ ConfigParam 34 association check no longer compares paired identities and ADNL IDs")
    pq_negatives = method(tree, "assert_pq_first_round_negative_cases")
    negative_text = ast.unparse(pq_negatives)
    for expected in ("'under-minimum', election_id, 1001 * NANO, False, 5",
                     "'wrong-election', election_id + 1, PQ_STAKE_MESSAGE_VALUE, False, 3",
                     "'invalid-signature', election_id, PQ_STAKE_MESSAGE_VALUE, True, 1"):
        if expected not in negative_text:
            fail(f"PQ first-round elector negative is absent: {expected}")
    if "after != before" not in negative_text:
        fail("PQ first-round negatives no longer require unchanged participation")
    duplicate = method(tree, "assert_duplicate_pq_key_refused")
    duplicate_text = ast.unparse(duplicate)
    if "reason != 4" not in duplicate_text or "after != before" not in duplicate_text:
        fail("PQ duplicate held-key negative no longer pins reason 4 and unchanged stake")
    recovery = method(tree, "assert_pq_early_recovery_no_credit")
    recovery_text = ast.unparse(recovery)
    if "compute_returned_stake" not in recovery_text or "after_credit != 0" not in recovery_text:
        fail("PQ early recovery no longer checks the pool-owned elector credit")
    restart_stake_calls = [
        node for node in ast.walk(election)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "submit_pq_candidate"
        and any(
            keyword.arg == "retry_restart_transients"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )
    ]
    if len(restart_stake_calls) != 1 or restart_stake_calls[0].lineno != positive_lines[1]:
        fail("fourth PQ stake no longer uses the bounded post-restart authorization retry")
    readiness = method(tree, "request_pq_authorization")
    readiness_text = ast.unparse(readiness)
    for marker in (
        "asyncio.timeout(remaining)",
        "error.code != 0", "error.message != 'Connection closed'",
        "error.code != 651", "this node cannot authorise a stake: not started",
        "deadline - loop.time()", "await self.nodes[index].engine_console.request(request)",
    ):
        if marker not in readiness_text:
            fail(f"post-restart authorization retry lost {marker!r}")
    if "retry_restart_transients=retry_restart_transients" not in ast.unparse(method(tree, "authorized_pq_pool_order")):
        fail("PQ pool order no longer threads the scoped post-restart retry to node authorization")
    config_reader = method(tree, "get_config34")
    if "validator_id:x([0-9A-Fa-f]{64})" not in ast.unparse(config_reader):
        fail("live ConfigParam 34 reader no longer extracts PQ validator IDs")
    if len(call_lines(config_reader, "parse_pq_validator_adnl_pairs")) != 1:
        fail("live ConfigParam 34 reader no longer parses identity/ADNL from each PQ record")
    execute = method(tree, "execute")
    if len(call_lines(execute, "run_pq_followup_elections")) != 1:
        fail("full PQ rehearsal is no longer invoked after its first election")
    if one_call(execute, "run_pq_first_election") >= one_call(execute, "run_pq_followup_elections"):
        fail("full PQ rehearsal no longer follows first-election acceptance")
    if not any(
        isinstance(node, ast.If)
        and ast.unparse(node.test) == "self.pq_full"
        and len(call_lines(ast.Module(body=node.body, type_ignores=[]), "run_pq_followup_elections")) == 1
        for node in ast.walk(execute)
    ):
        fail("the multi-round PQ rehearsal is no longer opt-in behind pq_full")
    followup = method(tree, "run_pq_followup_elections")
    followup_text = ast.unparse(followup)
    for marker in (
        "round_number=2", "round_number=3",
        "await self.fund_pq_pool_for_round(faucet, index, 2)",
        "await self.fund_pq_pool_for_round(faucet, index, 3)",
        "self.first_credits = await self.recover_pq_round(1)",
        "self.second_credits = await self.recover_pq_round(2)",
        "await self.assert_duplicate_pq_recovery_no_credit()",
        "await self.verify_two_of_four_safe_halt()",
        "pq_full_launch_gate_passed",
    ):
        if marker not in followup_text:
            fail(f"full PQ rehearsal lost {marker!r}")
    for name, marker in (
        ("recover_pq_round", "compute_returned_stake"),
        ("recover_pq_round", "pool_id = '0x' + pool.address.hash_part.hex()"),
        ("recover_pq_round", str(0xF96F7324)),
        ("assert_duplicate_pq_recovery_no_credit", str(0xFFFFFFFE)),
        ("wait_pq_config_activation", "require_pq_config34_associations"),
    ):
        if marker not in ast.unparse(method(tree, name)):
            fail(f"full PQ rehearsal {name} lost {marker!r}")
    print(
        "PQ_ELECTION_FIXTURE_SOURCE_OK: controller identity is asserted before boot; "
        "the live Param 47 read-back call precedes deployment; "
        "the Genesis helper contains 47 config!; "
        "Python engine-console transport admits the PQ authorization query; "
        "generated TL response fields are checked before snapshot/node boot and hashed in the snapshot; "
        "PQ candidates call the shared node-authorized, keyword-compatible Rust nominator::new_stake_with_witness pool-order path; "
        "the three exact pool-route refusals precede three accepted stakes, a restarted fourth stake with bounded pre-send authorization retry, and a duplicate-key refusal; "
        "STAKE_ACCEPTED, exact controller participants, and activated ConfigParam 34 with paired controller/ADNL identities are required; "
        "three-of-four liveness and pool-owned early recovery checks follow activation; "
        "an opt-in full PQ route budgets its faucet in Genesis before the first election and retains "
        "second/rollover activation, pool-owned recovery, duplicate refusal and two-of-four halt"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, SyntaxError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
