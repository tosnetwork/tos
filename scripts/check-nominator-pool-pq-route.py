#!/usr/bin/env python3
"""Pin the multi-nominator lifecycle route's PQ authority and pool wiring."""

from __future__ import annotations

import ast
import sys
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"NOMINATOR_POOL_PQ_ROUTE_FAILURE: {message}")


def method(tree: ast.Module, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    matches = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]
    require(len(matches) == 1, f"{name} has {len(matches)} definitions, expected one")
    return matches[0]


def calls(node: ast.AST, name: str) -> list[ast.Call]:
    return [
        child for child in ast.walk(node)
        if isinstance(child, ast.Call)
        and (
            isinstance(child.func, ast.Name) and child.func.id == name
            or isinstance(child.func, ast.Attribute) and child.func.attr == name
        )
    ]


def one_call(node: ast.AST, name: str) -> ast.Call:
    found = calls(node, name)
    require(len(found) == 1, f"{name} has {len(found)} calls, expected one")
    return found[0]


def keyword(call: ast.Call, name: str) -> str | None:
    values = [ast.unparse(item.value) for item in call.keywords if item.arg == name]
    return values[0] if len(values) == 1 else None


def validate(source: str) -> None:
    tree = ast.parse(source)
    for legacy in ("validator-elect-req.fif", "validator-elect-signed.fif", "validator-elect-req>B"):
        require(legacy not in source, f"multi-nominator lifecycle still calls classical {legacy}")
    prepare = method(tree, "prepare_pq_election_fixture")
    bring_up = method(tree, "bring_up_network")
    deploy = method(tree, "deploy_pool")
    order = method(tree, "authorized_pool_order")
    support = method(tree, "stake_support_pool")
    primary = method(tree, "stake_through_pool")
    upkeep = method(tree, "keep_elections_alive")
    selection = method(tree, "record_pool_validator_selection")
    execute = method(tree, "execute")

    require(bool(calls(prepare, "require_pq_stake_authorization_binding")),
            "PQ authorization TL binding is not preflighted")
    require("for index in range(5)" in ast.unparse(prepare),
            "fixture no longer prepares five controller identities")
    require("network.config.validator_controller_code_hash = self.controller_code.hash" in ast.unparse(bring_up),
            "Genesis no longer admits the compiled controller code")
    provision = one_call(bring_up, "make_deterministic_pq_initial_validator")
    spare = one_call(bring_up, "make_deterministic_pq_spare_validator")
    require(keyword(provision, "validator_id") == "controller.address.hash_part",
            "PQ validator_id is not bound to the controller address")
    require(keyword(spare, "validator_id") == "controller.address.hash_part",
            "spare PQ validator_id is not bound to its controller address")
    branches = [
        node for node in ast.walk(bring_up)
        if isinstance(node, ast.If) and ast.unparse(node.test) == "validator_index < 4"
    ]
    require(
        len(branches) == 1
        and provision in calls(ast.Module(body=branches[0].body, type_ignores=[]),
                               "make_deterministic_pq_initial_validator")
        and spare in calls(ast.Module(body=branches[0].orelse, type_ignores=[]),
                           "make_deterministic_pq_spare_validator"),
        "Genesis topology is not exactly four initial PQ validators plus one noninitial spare",
    )
    node_boots = [
        call.lineno for call in calls(bring_up, "run")
        if isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "node"
    ]
    require(bool(node_boots) and one_call(bring_up, "assert_controller_identity").lineno < min(node_boots),
            "controller identity is not asserted before node boot")
    require(one_call(bring_up, "verify_live_controller_policy").lineno > one_call(bring_up, "toslib_client").lineno,
            "ConfigParam 47 is not read back after client creation")
    require("controller_account=self.controllers[0].address.hash_part" in ast.unparse(deploy),
            "multi-nominator pool is not bound to controller zero")
    require(bool(calls(deploy, "make_pool_fixture")),
            "supporting validators lack controller-backed pools")
    request = one_call(order, "Engine_validator_createPqStakeAuthorizationRequest")
    require(keyword(request, "stake_owner") == "pool_address.hash_part",
            "node signs for an owner other than the destination pool")
    require(bool(calls(order, "parse_result")), "node authorization response is not parsed")
    builder = one_call(order, "build_production_pool_stake_order")
    for field, expected in {
        "public_key": "auth.public_key",
        "signature": "auth.signature",
        "witness": "controller.birth_witness",
        "adnl_addr": "node.validator_key.id",
    }.items():
        require(keyword(builder, field) == expected,
                f"production pool builder {field} is not bound to node/controller data")
    require(bool(calls(support, "authorized_pool_order")) and bool(calls(primary, "authorized_pool_order")),
            "a pool stake route bypasses the shared node-authorized order")
    require(bool(calls(upkeep, "stake_support_pool")) and not calls(upkeep, "stake_directly"),
            "election upkeep bypasses controller-backed support pools")
    selection_text = ast.unparse(selection)
    require("self.config34_selection" in selection_text and "validator_adnl_pairs" in selection_text,
            "live ConfigParam 34 no longer checks controller/ADNL pairing")
    require(one_call(execute, "prepare_pq_election_fixture").lineno < one_call(execute, "bring_up_network").lineno,
            "controller policy is not prepared before Genesis")


def self_test(source: str) -> None:
    mutations = {
        "wrong stake owner": ("stake_owner=pool_address.hash_part", "stake_owner=controller.address.hash_part"),
        "missing witness": ("witness=controller.birth_witness", "witness=None"),
        "wrong key source": ("public_key=auth.public_key", "public_key=controller.consensus.public_key"),
        "no support stake": ("await self.stake_support_pool(index, election_id)", "await self.elector_participant_ids()"),
        "classical Fift call": ("return build_production_pool_stake_order(",
                                 "# validator-elect-req.fif\n        return build_production_pool_stake_order("),
        "five Genesis validators": ("validator_index < 4", "validator_index < 5"),
        "spare made initial": ("make_deterministic_pq_spare_validator(\n", "make_deterministic_pq_initial_validator(\n"),
    }
    for label, (before, after) in mutations.items():
        require(source.count(before) == 1, f"self-test {label} mutation target is not unique")
        try:
            validate(source.replace(before, after, 1))
        except RuntimeError:
            continue
        raise RuntimeError(f"NOMINATOR_POOL_PQ_ROUTE_FAILURE: self-test survived {label}")


def main() -> None:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else Path(__file__).resolve().parents[1]
    source = (root / "scripts/nominator-pool-lifecycle-e2e.py").read_text()
    validate(source)
    self_test(source)
    print("NOMINATOR_POOL_PQ_ROUTE_OK: four Genesis PQ validators plus one noninitial spare, ConfigParam 47, node authorization, witness, production pool builder and paired Config34 lookup are wired; no live stake is claimed")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, SyntaxError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
