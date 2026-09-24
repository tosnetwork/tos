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
    assignments = {
        target.id: ast.unparse(node.value)
        for node in tree.body if isinstance(node, ast.Assign)
        for target in node.targets if isinstance(target, ast.Name)
    }
    require(assignments.get("CONTROLLER_FORWARDING_ALLOWANCE") == "1 * NANO",
            "controller forwarding allowance is not one TOS")
    require(assignments.get("POOL_STAKE_VALUE") ==
            "NETWORK_MIN_STAKE + ELECTOR_CONFIRMATION_ALLOWANCE + CONTROLLER_FORWARDING_ALLOWANCE",
            "pool stake no longer includes both Elector and controller forwarding allowances")
    for legacy in ("validator-elect-req.fif", "validator-elect-signed.fif", "validator-elect-req>B"):
        require(legacy not in source, f"multi-nominator lifecycle still calls classical {legacy}")
    prepare = method(tree, "prepare_pq_election_fixture")
    bring_up = method(tree, "bring_up_network")
    deploy = method(tree, "deploy_pool")
    order = method(tree, "authorized_pool_order")
    support = method(tree, "stake_support_pool")
    primary = method(tree, "stake_through_pool")
    feedback = method(tree, "record_pool_stake_feedback")
    history = method(tree, "_transactions_since")
    window = method(tree, "stakeable_election_id")
    window_parser = method(tree, "stakeable_election_id_from_live_status")
    upkeep = method(tree, "keep_elections_alive")
    support_snapshot = method(tree, "support_chain_snapshot")
    support_eligibility = method(tree, "recoverable_support_election_ids")
    support_poll = method(tree, "support_keeper_poll_seconds")
    support_recovery = method(tree, "recover_support_pool")
    selection = method(tree, "record_pool_validator_selection")
    recover = method(tree, "recover")
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
        "stake_amount": "POOL_STAKE_VALUE",
    }.items():
        require(keyword(builder, field) == expected,
                f"production pool builder {field} is not bound to node/controller data")
    require(bool(calls(support, "authorized_pool_order")) and bool(calls(primary, "authorized_pool_order")),
            "a pool stake route bypasses the shared node-authorized order")
    require(keyword(builder, "query_id") == "time.time_ns() if query_id is None else query_id"
            and keyword(one_call(primary, "authorized_pool_order"), "query_id") == "query_id"
            and "return query_id" in ast.unparse(primary),
            "primary pool order no longer binds a recorded query ID to its body")
    feedback_text = ast.unparse(feedback)
    require(bool(calls(history, "raw_get_transactions")) and bool(calls(feedback, "_transactions_since"))
            and "previous_transaction_id" in ast.unparse(history)
            and "cursor = previous" in ast.unparse(history),
            "second-stake feedback no longer pages raw transactions to the pre-order cursor")
    require(all(calls(feedback, name) for name in (
        "elector_reply", "pool_controller_bounce", "controller_relay_result",
        "_pool_order_transaction_lt",
    )), "second-stake feedback no longer reads Elector reply, controller bounce and relay")
    require("INCONCLUSIVE" in ast.unparse(feedback)
            and "pool_order_transaction_lt" in ast.unparse(feedback)
            and "pool_window_complete" in ast.unparse(feedback),
            "an uncovered second-stake order can be reported as a conclusive reply")
    require("except TimeoutError:" in source
            and "await self.record_pool_stake_feedback(final_query_id, label='pool-stake-after-drain')"
            in ast.unparse(execute),
            "second-stake timeout no longer collects exact-query chain feedback")
    require("'participant_list_extended'" in ast.unparse(window)
            and "state.sync_utime" in ast.unparse(window)
            and bool(calls(window, "stakeable_election_id_from_live_status")),
            "final election window no longer comes from Elector status and chain time")
    parser_text = ast.unparse(window_parser)
    require("elect_close - chain_utime > minimum_window_seconds" in parser_text
            and "failed != 0" in parser_text and "finished != 0" in parser_text,
            "final election selector no longer rejects closed or finished windows")
    final_retries = [
        call for call in calls(execute, "retry")
        if keyword(call, "description") == repr("an election with an open pool-stake acceptance window")
    ]
    require(len(final_retries) == 1 and len(final_retries[0].args) == 1
            and ast.unparse(final_retries[0].args[0]) == "self.stakeable_election_id",
            "final pool stake can select a nonzero but closed active_election_id")
    rechecks = [
        node for node in ast.walk(execute)
        if isinstance(node, ast.If)
        and ast.unparse(node.test) == "await self.stakeable_election_id() != final_election"
        and any(isinstance(child, ast.Raise) for child in node.body)
    ]
    final_orders = [
        call for call in calls(execute, "stake_through_pool")
        if keyword(call, "label") == repr("pool-stake-after-drain")
    ]
    require(len(rechecks) == 1 and len(final_orders) == 1
            and final_retries[0].lineno < rechecks[0].lineno < final_orders[0].lineno,
            "final pool order is not preceded by a same-election live-window recheck")
    require(bool(calls(upkeep, "stake_support_pool")) and not calls(upkeep, "stake_directly"),
            "election upkeep bypasses controller-backed support pools")
    snapshot_text = ast.unparse(support_snapshot)
    require(all(token in snapshot_text for token in (
        "'getconfig 34'", "'past_elections_list'", "'participant_list_extended'",
        "'get_pool_data'", "'compute_returned_stake'", "elector_state.sync_utime",
        "self.support_retired_past[election_id] = dict(record)",
        "support_election_retention_state", "'election_retention'",
    )), "support snapshot lost a live set, true unfreeze, pool state, owner credit or window read")
    eligibility_text = ast.unparse(support_eligibility)
    require(all(token in eligibility_text for token in (
        "election_id == current_set_id", "current_set_hash == set_hash",
        "observed['vset_hash'] != set_hash", "election_id in live_past",
        "chain_utime < observed['unfreeze_at']",
        "credit >= len(eligible) * NETWORK_MIN_STAKE",
    )), "support credit reuse is no longer gated by retired Config34, actual unfreeze, deleted past record and owner credit")
    recovery_text = ast.unparse(support_recovery)
    require(all(token in recovery_text for token in (
        "pool_message(1197831204, query_id)", "_transactions_since", "elector_reply",
        "opcode != 4184830756", "detail != 0", "reply_boc is None",
        "self.support_recovered[index].update(election_ids)",
    )), "support recovery no longer requires a pool-owned order and exact Elector reply")
    upkeep_text = ast.unparse(upkeep)
    require(all(token in upkeep_text for token in (
        "self.support_chain_snapshot('keeper-poll')", "recoverable_support_election_ids",
        "self.recover_support_pool(index, eligible, snapshot)",
        "await self.stakeable_election_id() != election_id",
        "self.support_submitted[index].add(election_id)",
        "support_keeper_poll_seconds", "await asyncio.sleep(poll_seconds)",
    )), "support keeper no longer proves recovery and open window before reusing capital")
    poll_text = ast.unparse(support_poll)
    require(all(token in poll_text for token in (
        "elections - recovered[index]", "retired_past.get(election_id)",
        "record['unfreeze_at'] - chain_utime <= 60", "return 5", "return 20",
    )), "support keeper no longer polls promptly near a chain-observed unfreeze")
    require(one_call(upkeep, "recover_support_pool").lineno < one_call(upkeep, "stake_support_pool").lineno,
            "support keeper spends another principal before attempting mature pool credit recovery")
    selection_text = ast.unparse(selection)
    require("self.config34_selection" in selection_text and "validator_adnl_pairs" in selection_text,
            "live ConfigParam 34 no longer checks controller/ADNL pairing")
    require("SUPPORT_POOL_CAPITAL = 2 * POOL_STAKE_VALUE + 20 * NANO" in source,
            "supporting pool capital no longer reserves two stake principals")
    require("capital = SUPPORT_POOL_CAPITAL" in ast.unparse(deploy),
            "supporting pool funding bypasses the preflighted two-principal budget")
    budget = one_call(execute, "require_lifecycle_funding_budget")
    require(budget.lineno < one_call(execute, "prepare_pq_election_fixture").lineno,
            "fixture budget is not checked before Genesis preparation")
    execute_text = ast.unparse(execute)
    require("data.stake_at == election_id" in execute_text
            and "data.stake_amount_sent >= NETWORK_MIN_STAKE" in execute_text,
            "first pool stake acceptance is no longer bound to the target election and minimum")
    recover_text = ast.unparse(recover)
    require("predicate=lambda value: value == 0" in recover_text
            and "the Elector no longer holds a recoverable primary-pool credit" in recover_text,
            "recovery no longer confirms the Elector consumed the primary pool credit")
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
        "budget bypassed": ("**require_lifecycle_funding_budget(", "**dict("),
        "one support principal": ("SUPPORT_POOL_CAPITAL = 2 * POOL_STAKE_VALUE", "SUPPORT_POOL_CAPITAL = 1 * POOL_STAKE_VALUE"),
        "wrong election accepted": ("data.stake_at == election_id", "data.stake_at >= 0"),
        "credit not consumed": (
            "description=\"Elector consumed the primary pool's recovered credit\",\n            predicate=lambda value: value == 0",
            "description=\"Elector consumed the primary pool's recovered credit\",\n            predicate=lambda value: value >= 0",
        ),
        "controller allowance omitted":
            (" + CONTROLLER_FORWARDING_ALLOWANCE\n", "\n"),
        "controller allowance zeroed":
            ("CONTROLLER_FORWARDING_ALLOWANCE = 1 * NANO", "CONTROLLER_FORWARDING_ALLOWANCE = 0 * NANO"),
        "stake builder bypasses budgeted amount":
            ("stake_amount=POOL_STAKE_VALUE", "stake_amount=NETWORK_MIN_STAKE"),
        "unbound second stake query":
            ("self.pool_address, query_id=query_id", "self.pool_address, query_id=0"),
        "second stake feedback removed":
            ("await self.record_pool_stake_feedback(\n                    final_query_id", "await self.pool_data(\n                    final_query_id"),
        "Elector reply ignored":
            ("elector_reply(pool_transactions, query_id)", "None"),
        "controller bounce ignored":
            ("pool_controller_bounce(\n                pool_transactions", "ignored_bounce(\n                pool_transactions"),
        "controller relay ignored":
            ("controller_relay_result(\n                controller_transactions", "ignored_relay(\n                controller_transactions"),
        "history stops after one page":
            ("cursor = previous\n", "return transactions, pages, False, latest_cursor\n"),
        "closed election selected by nonzero ID":
            ("                self.stakeable_election_id,\n", "                self.active_election_id,\n"),
        "final election recheck removed":
            ("if await self.stakeable_election_id() != final_election:",
             "if False and await self.stakeable_election_id() != final_election:"),
        "support past record ignored": (
            "or election_id in live_past or chain_utime < observed[\"unfreeze_at\"]",
            "or False or chain_utime < observed[\"unfreeze_at\"]",
        ),
        "support owner credit ignored": (
            "credit >= len(eligible) * NETWORK_MIN_STAKE",
            "credit >= 0",
        ),
        "support active set reused": (
            "election_id == current_set_id or set_hash is None",
            "False or set_hash is None",
        ),
        "support true unfreeze ignored": (
            "or election_id in live_past or chain_utime < observed[\"unfreeze_at\"]",
            "or election_id in live_past or False",
        ),
        "support exact reply ignored": (
            "if opcode != 0xF96F7324 or detail != 0 or reply_boc is None:",
            "if reply_boc is None:",
        ),
        "support recovery bypassed": (
            "await self.recover_support_pool(index, eligible, snapshot)",
            "await self.balance(self.support_pools[index].address)",
        ),
        "pre-unfreeze fast poll removed": (
            "record[\"unfreeze_at\"] - chain_utime <= 60:",
            "record[\"unfreeze_at\"] - chain_utime <= 0:",
        ),
        "keeper ignores fast poll": (
            "await asyncio.sleep(poll_seconds)", "await asyncio.sleep(20)"
        ),
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
    print("NOMINATOR_POOL_PQ_ROUTE_OK: fixture identity and PQ pool-order wiring checked; support recovery is gated by live Config34, observed retired past-election unfreeze, deleted record, owner credit and exact Elector reply; final stake selection requires an open window and same-ID recheck; no live second stake is claimed")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, SyntaxError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
