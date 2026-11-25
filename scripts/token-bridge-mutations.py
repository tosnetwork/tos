#!/usr/bin/env python3
"""Mutation controls for the token bridge settlement protocol and its oracle multisig.

Each control removes or weakens one guard in a copy of the sources and runs
the test that names it. A control counts as red only when the test fails for
its named reason: the expected text must appear in the failure. Before the
mutations, every named test runs once against the unmutated copy and must
pass, so a red result cannot come from a broken test.

The working tree is never modified: the contracts, the shared vectors and the
EVM project are copied to a scratch root, which the sandbox reads through
TOS_ROOT and Hardhat runs from.

Usage: token-bridge-mutations.py [--only ID[,ID...]] [--results FILE]
                                 [--skip-evm | --tvm-only | --evm-only] [--show] [--no-controls]

Exit status 0 when every control is red for its reason (or is a recorded
survivor), 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BRIDGE = "crosschain/token-bridge"
COIN = "crosschain/coin-bridge"
C = f"{BRIDGE}/tvm/contracts"
SOL = f"{BRIDGE}/evm/contracts"


@dataclass
class Mutation:
    id: str
    what: str
    file: str
    old: str
    new: str
    test: str  # cargo test filter, or a Hardhat test title for EVM
    reason: str  # text the failure must contain
    evm: bool = False
    survivor: str = ""  # why this control cannot go red here, if it cannot
    target: str = "token_bridge_sandbox"  # the sandbox test binary
    # A filter naming the sibling tests that must all stay green under this
    # mutation: the control is red only when the named test is the one that
    # fails among them.
    exclusive: str = ""


M = Mutation

# The guards of the oracle multisig (multisig.fc, check_proposed_query). Each
# has one test in bridge_multisig_sandbox, a quorum query that violates only
# that guard, and removing the guard turns only that test red among the
# guard tests.
MULTISIG_GUARDS = [
    (
        "does not check the destination allowlist",
        "  throw_unless(46, allowed_bridge?(dest, allowed));\n",
        "",
        "guard_destination_",
        "expected exit code 46",
    ),
    (
        "does not check the bounce flag",
        "  throw_unless(47, (flags & 11) == 2);\n",
        "",
        "guard_non_bounceable_",
        "expected exit code 47",
    ),
    (
        "does not check the send mode",
        "  throw_unless(48, mode < 4);\n",
        "",
        "guard_send_mode_",
        "expected exit code 48",
    ),
    (
        "does not check the value bound",
        "  throw_unless(49, (value <= MAX_VOTE_VALUE) & (extra == 0));\n",
        "",
        "guard_value_",
        "expected exit code 49",
    ),
    (
        "does not check the StateInit refusal",
        "  throw_if(50, rest~load_uint(1));\n",
        "",
        "guard_state_init_",
        "expected exit code 50",
    ),
    (
        "checks only the bounce bit, not the message kind or the bounced bit",
        "  throw_unless(47, (flags & 11) == 2);\n",
        "  throw_unless(47, (flags & 2) == 2);\n",
        "guard_non_bounceable_",
        "expected exit code 47",
    ),
]


def multisig_controls(prefix: str, file: str) -> list[Mutation]:
    return [
        Mutation(
            f"{prefix}{i:02d}",
            f"the multisig {what}",
            file,
            old,
            new,
            test,
            reason,
            target="bridge_multisig_sandbox",
            exclusive="guard_",
        )
        for i, (what, old, new, test, reason) in enumerate(MULTISIG_GUARDS, 1)
    ]


MUTATIONS = [
    M(
        "M01",
        "the wallet ignores its floor and its set",
        f"{C}/token-wallet.fc",
        "} elseif (k >= max(w_credit_wm, w_credit_cf)) {",
        "} elseif (true) {",
        "t_m4_",
        "credit",
    ),
    M(
        "M02",
        "the minter counts a COUNTED s",
        f"{C}/token-minter.fc",
        "        if (status == MINT_CREDITING) {\n            m_in_flight -= amount;\n            m_supply += amount;\n"
        "            mint_put(s, MINT_COUNTED, bound_life, k, 0, hash, owner, amount, d);\n"
        "            (h_credits, _) = h_credits.udict_delete?(64, k);\n",
        "        if ((status == MINT_CREDITING) | (status == MINT_COUNTED)) {\n            m_in_flight -= amount;\n"
        "            m_supply += amount;\n            mint_put(s, MINT_COUNTED, bound_life, k, 0, hash, owner, amount, d);\n",
        "t_m4_",
        "I",
    ),
    M(
        "M03",
        "the bridge ignores its burn watermark",
        f"{C}/token-bridge.fc",
        "} elseif (m < max(c_burn_wm, c_burn_cf)) {",
        "} elseif (false) {",
        "t_b6_",
        "LOG_BURN emitted twice",
    ),
    M(
        "M04",
        "the bridge honours a second cancellation flag",
        f"{C}/token-bridge.fc",
        "        throw_unless(error::operation_mismatch, e~load_uint(256) == hash);\n        send_burn_result(m, outcome);",
        "        throw_unless(error::operation_mismatch, e~load_uint(256) == hash);\n"
        "        if (cancel) {\n            outcome = OUTCOME_CANCELLED;\n"
        "            c_burns~udict_set_builder(64, m, begin_cell().store_uint(outcome, 1).store_uint(hash, 256));\n        }\n"
        "        send_burn_result(m, outcome);",
        "t_b5_",
        "I",
    ),
    M(
        "M05",
        "a bounce triggers a refund",
        f"{C}/token-wallet.fc",
        "  if (op != op::internal_transfer) {\n    return ();\n  }\n  in_msg_body~load_query_id();",
        "  if (op == op::burn_admit) {\n    w_balance += 400;\n    save_data();\n    return ();\n  }\n"
        "  if (op != op::internal_transfer) {\n    return ();\n  }\n  in_msg_body~load_query_id();",
        "t_b7_",
        "I1:",
    ),
    M(
        "M06",
        "a settlement handler reads ConfigParam 79",
        f"{C}/token-minter.fc",
        "    cell d = body~load_ref();\n    body.end_parse();\n    if (~ bridge_ok?(sender, life, expected, false)) {",
        "    cell d = body~load_ref();\n    body.end_parse();\n    get_token_bridge_config();\n"
        "    if (~ bridge_ok?(sender, life, expected, false)) {",
        "t_m7_",
        "failed",
    ),
    M(
        "M07",
        "the wallet's descriptor hash comparison is removed",
        f"{C}/token-wallet.fc",
        "        throw_unless(error::operation_mismatch, entry.preload_uint(256) == hash);\n",
        "",
        "t_m6_",
        "panicked",
    ),
    M(
        "M08",
        "the minter's burn descriptor hash comparison is removed",
        f"{C}/token-minter.fc",
        "        throw_unless(error::operation_mismatch, stored_hash == hash);\n"
        "        if ((status == BURN_AWAITING_BRIDGE) & cancel & (~ stored_cancel)) {",
        "        if ((status == BURN_AWAITING_BRIDGE) & cancel & (~ stored_cancel)) {",
        "t_b8_",
        "panicked",
    ),
    M(
        "M09",
        "burn_reserve is not counted",
        f"{C}/token-minter.fc",
        "        m_burn_reserve += amount;\n        m_notices~udict_set_builder",
        "        m_notices~udict_set_builder",
        "t_x1_",
        "panicked",
    ),
    M(
        "M10",
        "an exception is dropped without the sender's floor",
        f"{C}/token-minter.fc",
        "if ((status == MINT_COUNTED) | (m_mint_wm < m_mint_cf)) {",
        "if (true) {",
        "t_x3_a_refusal",
        "panicked",
    ),
    M(
        "M11",
        "ADMIT_REFUSED is not stored",
        f"{C}/token-minter.fc",
        "        h_burns~udict_set_builder(64, b, burn_record(BURN_ADMIT_REFUSED, cancel, 0, amount, hash, d));\n"
        "        send_burn_answer(op::admit_refused",
        "        send_burn_answer(op::admit_refused",
        "t_y1_",
        "panicked",
    ),
    M(
        "M12",
        "the sender window ignores its acknowledged floor",
        f"{C}/token-bridge.fc",
        "    require_window(s, c_mint_ack, MINT_WINDOW);\n",
        "",
        "t_y4_",
        "panicked",
    ),
    M(
        "M13",
        "the wallet's life check is removed",
        f"{C}/token-wallet.fc",
        "    throw_unless(error::life_mismatch, wallet_life == w_born);\n"
        "    (_, _, int amount, _, _, _, slice minter, slice recipient) = parse_mint_descriptor(descriptor);",
        "    (_, _, int amount, _, _, _, slice minter, slice recipient) = parse_mint_descriptor(descriptor);",
        "t_x4_an_old_life",
        "panicked",
    ),
    M(
        "M14",
        "a newer hub life is treated as a recreated wallet",
        f"{C}/token-wallet.fc",
        "    if (minter_life > w_minter_life) {\n        w_minter_terminal = 1;\n        save_data();\n        return false;\n    }",
        "    if (minter_life > w_minter_life) {\n        w_minter_life = minter_life;\n        return true;\n    }",
        "t_y6_a_newer",
        "panicked",
    ),
    M(
        "M15",
        "cancel_lock accepts a PREPARING lock",
        f"{C}/token-bridge.fc",
        "        throw_unless(error::not_admissible, e.preload_uint(2) == SWAP_PAID);\n        e~skip_bits(2);\n        slice payer",
        "        throw_unless(error::not_admissible, e.preload_uint(2) <= SWAP_PREPARING);\n        e~skip_bits(2);\n        slice payer",
        "t_y5_",
        "panicked",
    ),
    M(
        "M16",
        "an advance takes a field from its body",
        f"{C}/token-bridge.fc",
        "        int s = body~load_uint(64);\n        body.end_parse();\n        int need = advance_need(kind, s);",
        "        int s = body~load_uint(64);\n        int need = advance_need(kind, s);",
        "t_m9_",
        "extra fields",
    ),
    M(
        "M17",
        "admission tests only W, not max(W, C)",
        f"{C}/token-minter.fc",
        "    if (s < max(m_mint_wm, m_mint_cf)) {\n        ;; counted, the channel's default",
        "    if (s < m_mint_wm) {\n        ;; counted, the channel's default",
        "t_z2_",
        "panicked",
        survivor="redundant by construction: no entry at or above W is ever deleted (folding removes an "
        "entry only after W passes it, compaction only below min(W, C)), so a number in [W, C) "
        "always finds its own entry before the admission bound is consulted",
    ),
    M(
        "M18",
        "a reported floor is accepted without validation",
        f"{C}/token-minter.fc",
        "    throw_unless(error::bad_floor, floor <= entered_high(m_mints, m_mint_wm));\n",
        "",
        "t_z2_",
        "panicked",
    ),
    M(
        "M19",
        "credits are bounded by the global window instead of the holder's k",
        f"{C}/token-minter.fc",
        "        if ((k > MAX_SEQ) | (k >= h_credit_ack + CREDIT_WINDOW)) {",
        "        if (k > MAX_SEQ) {",
        "t_z3_",
        "panicked",
    ),
    M(
        "M20",
        "RESERVED is not stranded on recreation",
        f"{C}/token-minter.fc",
        "    if ((status != MINT_RESERVED) & (status != MINT_CREDITING)) {",
        "    if (status != MINT_CREDITING) {",
        "t_z4_a_wallet_deleted",
        "panicked",
    ),
    M(
        "M21",
        "the generation check is removed",
        f"{C}/token-bridge.fc",
        "(b_gen_state == GEN_ACTIVE) & (generation == b_generation)",
        "b_gen_state == GEN_ACTIVE",
        "t_z1_",
        "panicked",
    ),
    M(
        "M22",
        "a sender advances its floor from C instead of S",
        f"{C}/token-minter.fc",
        "            .store_uint(channel::c1, 8)\n            .store_uint(mint_storage_floor(), 64));",
        "            .store_uint(channel::c1, 8)\n            .store_uint(m_mint_cf, 64));",
        "t_z2_",
        "panicked",
        survivor="equivalent at the current constants: a reply is always computed after a fold of up to "
        "FOLD_LIMIT numbers, and the unfolded backlog never exceeds MINT_WINDOW - FOLD_LIMIT = "
        "FOLD_LIMIT, so W has caught up with C and S = min(W, C) = C whenever a reply is sent",
    ),
    M(
        "M23",
        "a waiting mint is promoted past the holder's credit window",
        f"{C}/token-minter.fc",
        "if ((h_open == HOLDER_OPEN) & (k <= MAX_SEQ) & (k < h_credit_ack + CREDIT_WINDOW)) {",
        "if (h_open == HOLDER_OPEN) {",
        "t_z7_",
        "panicked",
    ),
    M(
        "M24",
        "LOG_LIABILITY_STRANDED is sent in mode 2",
        f"{C}/settlement.fc",
        "        .store_ref(data)\n        .end_cell(), 0);\n}\n\n;; A record for observers only",
        "        .store_ref(data)\n        .end_cell(), 2);\n}\n\n;; A record for observers only",
        "t_z4_stranding",
        "the action phase failed",
    ),
    M(
        "M25",
        "a record keeps only a hash",
        f"{C}/token-bridge.fc",
        ".store_uint(hash, 256).store_ref(d));\n}",
        ".store_uint(hash, 256).store_ref(begin_cell().end_cell()));\n}",
        "t_z6_a_mint",
        "panicked",
    ),
    M(
        "M26",
        "cancel_lock below the watermark is evaluated",
        f"{C}/token-bridge.fc",
        "    require_open_swap(n);\n    (slice e, int found) = b_swaps.udict_get?(64, n);\n    if (found) {\n"
        "        throw_unless(error::not_admissible, e.preload_uint(2) == SWAP_PAID);",
        "    throw_unless(error::sequence_exhausted, n <= MAX_SEQ);\n    (slice e, int found) = b_swaps.udict_get?(64, n);\n"
        "    if (found) {\n        throw_unless(error::not_admissible, e.preload_uint(2) == SWAP_PAID);",
        "t_z1_",
        "panicked",
    ),
    M(
        "M27",
        "atomic send: +2 on the cancellation refund",
        f"{C}/token-bridge.fc",
        "                .store_coins(refund)\n                .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)\n                .end_cell(), 1);",
        "                .store_coins(refund)\n                .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)\n                .end_cell(), 3);",
        "t_x7_",
        "I8 atomic send",
    ),
    M(
        "M28",
        "the vote's namespace check is removed",
        f"{C}/token-bridge.fc",
        "    throw_unless(error::wrong_namespace, (evm_chain_id == b_evm_chain) & (evm_bridge == b_evm_bridge) & (b_evm_chain == MY_CHAIN_ID));\n",
        "",
        "t_x8_votes",
        "panicked",
    ),
    M(
        "M29",
        "the zero-destination check is removed",
        f"{C}/token-wallet.fc",
        "  throw_if(error::zero_destination, destination_address == 0);\n",
        "",
        "t_x8_votes",
        "panicked",
    ),
    M(
        "M30",
        "the bridge's capacity check is removed",
        f"{C}/token-bridge.fc",
        "    require_cell_capacity(BRIDGE_WORST_CELLS, true);\n}",
        "}",
        "t_y8_a_lowered",
        "panicked",
    ),
    M(
        "M31",
        "an unpaid cancellation's funding check is removed",
        f"{C}/token-bridge.fc",
        "        throw_unless(error::underfunded, msg_value_of_in() >= get_cancel_cost());\n",
        "",
        "t_y5_",
        "panicked",
    ),
    M(
        "M32",
        "a vote returns all its value, leaving the log to the bridge",
        f"{C}/token-bridge.fc",
        "        if (b_vote_keep > 0) {",
        "        if (false) {",
        "t_y5_",
        "I7",
    ),
    M(
        "M33",
        "a stranded report rewrites a committed swap",
        f"{C}/token-bridge.fc",
        "            if (status == PENDING_PREPARING) {\n                b_swaps~udict_set_builder(64, n, begin_cell().store_uint(SWAP_CONSUMED, 2));\n            }",
        "            b_swaps~udict_set_builder(64, n, begin_cell().store_uint(SWAP_CONSUMED, 2));",
        "t_z4_a_wallet_deleted",
        "panicked",
    ),
    M(
        "M34",
        "a step's declared gas is below what it uses",
        f"{C}/settlement.fc",
        "const int WALLET_STEP_GAS = 40000;",
        "const int WALLET_STEP_GAS = 4000;",
        "t_m1_",
        "over its declared",
    ),
    M(
        "M35",
        "stranding exceeds FOLD_LIMIT per transaction",
        f"{C}/token-minter.fc",
        "    while (more & (steps < FOLD_LIMIT)) {\n        (int b, slice e, int found) = first ?",
        "    while (more & (steps < FOLD_LIMIT + 4)) {\n        (int b, slice e, int found) = first ?",
        "t_z4_stranding",
        "strand",
    ),
    M(
        "M36",
        "the minter's step gas misses the deepest holder path",
        f"{C}/settlement.fc",
        "const int MINTER_STEP_GAS = 300000;",
        "const int MINTER_STEP_GAS = 120000;",
        "deep::every_minter_step",
        "over its declared",
    ),
    M(
        "M37",
        "a minter batch's gas misses the deepest holder path",
        f"{C}/settlement.fc",
        "const int MINTER_BATCH_GAS = 400000;",
        "const int MINTER_BATCH_GAS = 180000;",
        "deep::every_minter_step",
        "over its declared",
    ),
    # Reported transfers and the balance report (token_bridge/reported.rs)
    M(
        "M38",
        "S sends a reported transfer for anyone",
        f"{C}/token-wallet.fc",
        "  throw_unless(error::unauthorized_transfer, equal_slices(w_owner, sender_address));\n"
        "  throw_unless(error::not_enough_funds, token_amount > 0);\n",
        "  throw_unless(error::not_enough_funds, token_amount > 0);\n",
        "t_r4_",
        "not the owner: S refuses with",
    ),
    M(
        "M39",
        "S sends a reported transfer of nothing",
        f"{C}/token-wallet.fc",
        "  throw_unless(error::not_enough_funds, token_amount > 0);\n"
        "  throw_unless(error::not_enough_funds, token_amount <= w_balance);\n",
        "  throw_unless(error::not_enough_funds, token_amount <= w_balance);\n",
        "t_r4_",
        "zero amount: S refuses with",
    ),
    M(
        "M40",
        "S sends more than its balance",
        f"{C}/token-wallet.fc",
        "  throw_unless(error::not_enough_funds, token_amount <= w_balance);\n"
        "  throw_unless(error::not_canonical_destination",
        "  throw_unless(error::not_canonical_destination",
        "t_r4_",
        "above the balance: S refuses with",
    ),
    M(
        "M41",
        "S accepts a destination that is not canonical on the basechain",
        f"{C}/token-wallet.fc",
        "  throw_unless(error::not_canonical_destination, canonical_basechain?(to_owner_address));\n",
        "",
        "t_r4_",
        "the masterchain: S refuses with",
    ),
    M(
        "M42",
        "S accepts a body without a forward payload",
        f"{C}/token-wallet.fc",
        "  throw_unless(error::malformed_forward_payload, slice_bits(in_msg_body) >= 1);\n"
        "  (_, int recorded)",
        "  (_, int recorded)",
        "t_r4_",
        "no forward payload: S refuses with",
    ),
    M(
        "M43",
        "S reuses a query id whose refusal is recorded",
        f"{C}/token-wallet.fc",
        "  throw_if(error::refusal_pending, recorded);\n",
        "",
        "t_r7_",
        "expected a refusal with 712",
    ),
    M(
        "M44",
        "S accepts a value equal to the need",
        f"{C}/token-wallet.fc",
        "throw_unless(error::not_enough_tos, msg_value > reported_need(",
        "throw_unless(error::not_enough_tos, msg_value >= reported_need(",
        "t_r4_",
        "exactly the need: S refuses with",
    ),
    M(
        "M45",
        "R's compute is priced from ConfigParam 79 alone",
        f"{C}/token-wallet.fc",
        "  return max(get_compute_fee(false, R_GAS_LIMIT), wallet_gas_consumption);",
        "  return wallet_gas_consumption;",
        "t_r5_",
        "network-priced compute term",
    ),
    # M46, M47 and M48 hold only through T-R5's need_from_terms, which
    # recomputes the need term by term: at the test's prices the storage reserve
    # and the margins leave R funded without any one of these terms.
    M(
        "M46",
        "the value check omits R's largest action fine",
        f"{C}/token-wallet.fc",
        "          + REPORT_MARGIN * get_forward_fee(false, 0, body_cells + 2)\n",
        "",
        "t_r5_",
        "the need is the sum of its terms",
    ),
    M(
        "M47",
        "the value check omits the forwarding of R's bounce",
        f"{C}/token-wallet.fc",
        "          + REPORT_MARGIN * get_forward_fee(false, 32 + 256, 1)\n",
        "",
        "t_r5_",
        "the need is the sum of its terms",
    ),
    M(
        "M48",
        "the value check omits the storage reserve",
        f"{C}/token-wallet.fc",
        "          + wallet_min_tos_for_storage;\n}",
        "          ;\n}",
        "t_r5_",
        "the need is the sum of its terms",
    ),
    M(
        "M49",
        "S sends to R without +16",
        f"{C}/token-wallet.fc",
        "  send_raw_message(msg, SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE + SEND_MODE_BOUNCE_ON_ACTION_FAIL);",
        "  send_raw_message(msg, SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE);",
        "t_r3_",
        "S's action failure bounces P's message",
    ),
    M(
        "M50",
        "R does not cap its gas",
        f"{C}/token-wallet.fc",
        "    set_gas_limit(R_GAS_LIMIT);\n",
        "",
        "t_r2_refused_at_r_out_of_its_capped_gas",
        "R runs out of its capped gas",
    ),
    M(
        "M51",
        "R credits a transfer from any sender",
        f"{C}/token-wallet.fc",
        "  throw_unless(error::unauthorized_incoming_transfer,\n"
        "          equal_slices(calculate_user_token_wallet_address(from_address, w_master, w_code), sender_address));\n"
        "  (_, _, _, _, _, _, int wallet_min_tos_for_storage",
        "  (_, _, _, _, _, _, int wallet_min_tos_for_storage",
        "t_r8_",
        "ended more often than it was sent",
    ),
    M(
        "M52",
        "R credits past MAX_SUPPLY",
        f"{C}/token-wallet.fc",
        "get_token_bridge_config();\n  int balance = w_balance + token_amount;\n"
        "  throw_unless(error::supply_bound, balance <= MAX_SUPPLY);\n",
        "get_token_bridge_config();\n  int balance = w_balance + token_amount;\n",
        "t_r2_refused_at_r_by_its_supply_bound",
        "refused for another reason",
    ),
    M(
        "M53",
        "R's notification of a reported transfer is sent without +16",
        f"{C}/token-wallet.fc",
        "    send_raw_message(msg.end_cell(), SEND_MODE_PAY_FEES_SEPARETELY + SEND_MODE_BOUNCE_ON_ACTION_FAIL);\n"
        "  }\n\n  ;; The report commits",
        "    send_raw_message(msg.end_cell(), SEND_MODE_PAY_FEES_SEPARETELY);\n"
        "  }\n\n  ;; The report commits",
        "t_r2_refused_at_r_by_an_action_failure",
        "I1:",
    ),
    M(
        "M54",
        "R's delivery report is sent without +16",
        f"{C}/token-wallet.fc",
        "  send_raw_message(report.end_cell(), SEND_MODE_PAY_FEES_SEPARETELY + SEND_MODE_BOUNCE_ON_ACTION_FAIL);",
        "  send_raw_message(report.end_cell(), SEND_MODE_PAY_FEES_SEPARETELY);",
        "t_r2_refused_at_r_by_an_action_failure",
        "I1:",
    ),
    M(
        "M55",
        "R credits without reporting the delivery",
        f"{C}/token-wallet.fc",
        "  send_raw_message(report.end_cell(), SEND_MODE_PAY_FEES_SEPARETELY + SEND_MODE_BOUNCE_ON_ACTION_FAIL);",
        "",
        "t_r1_",
        "without its report",
    ),
    M(
        "M56",
        "S records a refusal without restoring the tokens",
        f"{C}/token-wallet.fc",
        "  w_balance += token_amount;\n  ;; A second refusal",
        "  ;; A second refusal",
        "t_r2_refused_at_r_by_a_compute_failure",
        "restores its amount",
    ),
    M(
        "M57",
        "S restores a refused transfer without recording it",
        f"{C}/token-wallet.fc",
        "    w_refusals~udict_set_builder(64, query_id, begin_cell().store_coins(token_amount));\n"
        "    w_refusals_count += 1;\n",
        "",
        "t_r2_refused_at_r_by_a_compute_failure",
        "is recorded",
    ),
    M(
        "M58",
        "S handles a refusal on the bounce's own value",
        f"{C}/token-wallet.fc",
        "    set_gas_limit(S_BOUNCE_GAS);\n",
        "",
        "t_r2_a_short_bounce",
        "I1:",
    ),
    M(
        "M59",
        "S's refusal report can roll back the restore",
        f"{C}/token-wallet.fc",
        "  send_refused(op::transfer_refused, query_id, token_amount, SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE + SEND_MODE_IGNORE_ERRORS);",
        "  send_refused(op::transfer_refused, query_id, token_amount, SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE);",
        "t_r2_a_short_bounce",
        "I1:",
    ),
    M(
        "M60",
        "a re-report of an unknown query id is not ignored",
        f"{C}/token-wallet.fc",
        "  if (~ found) {\n    return ();\n  }\n  send_refused",
        "  send_refused",
        "t_r7_",
        "the transaction failed",
    ),
    M(
        "M61",
        "a re-report that cannot be sent is skipped instead of failing",
        f"{C}/token-wallet.fc",
        "  send_refused(op::transfer_rereported, query_id, entry~load_coins(), SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE);",
        "  send_refused(op::transfer_rereported, query_id, entry~load_coins(), SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE + SEND_MODE_IGNORE_ERRORS);",
        "t_r7_",
        "an unfunded re-report fails",
    ),
    M(
        "M62",
        "anyone clears a refusal",
        f"{C}/token-wallet.fc",
        "  throw_unless(error::unauthorized_transfer, equal_slices(w_owner, sender_address));\n"
        "  (w_refusals, int deleted) = w_refusals.udict_delete?(64, query_id);",
        "  (w_refusals, int deleted) = w_refusals.udict_delete?(64, query_id);",
        "t_r7_",
        "expected a refusal with 705",
    ),
    M(
        "M63",
        "anyone learns the balance",
        f"{C}/token-wallet.fc",
        "  throw_unless(error::unauthorized_transfer, equal_slices(w_owner, sender_address));\n"
        "  send_raw_message(begin_cell()\n          .store_msg_flags(NON_BOUNCEABLE)\n"
        "          .store_slice(w_owner)\n          .store_coins(0)\n          .store_msgbody_prefix_slice()\n"
        "          .store_body_header(op::take_balance",
        "  send_raw_message(begin_cell()\n          .store_msg_flags(NON_BOUNCEABLE)\n"
        "          .store_slice(w_owner)\n          .store_coins(0)\n          .store_msgbody_prefix_slice()\n"
        "          .store_body_header(op::take_balance",
        "t_r9_",
        "expected a refusal with 705",
    ),
    M(
        "M64",
        "R_GAS_LIMIT is below twice R's measured most",
        f"{C}/token-wallet.fc",
        "const int R_GAS_LIMIT = 41000;",
        "const int R_GAS_LIMIT = 40000;",
        "t_r11_",
        "more than half of its R_GAS_LIMIT",
    ),
    M(
        "M65",
        "S_BOUNCE_GAS is below twice the bounce's measured most",
        f"{C}/token-wallet.fc",
        "const int S_BOUNCE_GAS = 58000;",
        "const int S_BOUNCE_GAS = 54000;",
        "t_r11_",
        "more than half of its S_BOUNCE_GAS",
    ),
    M(
        "M66",
        "an ordinary transfer's notification is sent without +16",
        f"{C}/token-wallet.fc",
        "    send_raw_message(msg.end_cell(), SEND_MODE_PAY_FEES_SEPARETELY + SEND_MODE_BOUNCE_ON_ACTION_FAIL);\n"
        "  }\n\n  if ((response_address.preload_uint(2) != 0) & (msg_value > 0)) {\n"
        "    var msg = begin_cell()\n            .store_msg_flags(NON_BOUNCEABLE)\n"
        "            .store_slice(response_address)\n            .store_coins(msg_value)\n"
        "            .store_msgbody_prefix_slice()\n            .store_body_header(op::excesses, query_id);\n"
        "    send_raw_message(msg.end_cell(), SEND_MODE_IGNORE_ERRORS);\n  }\n\n  w_balance = balance;\n"
        "  save_data();\n}\n\n;; ---- reported",
        "    send_raw_message(msg.end_cell(), SEND_MODE_PAY_FEES_SEPARETELY);\n"
        "  }\n\n  if ((response_address.preload_uint(2) != 0) & (msg_value > 0)) {\n"
        "    var msg = begin_cell()\n            .store_msg_flags(NON_BOUNCEABLE)\n"
        "            .store_slice(response_address)\n            .store_coins(msg_value)\n"
        "            .store_msgbody_prefix_slice()\n            .store_body_header(op::excesses, query_id);\n"
        "    send_raw_message(msg.end_cell(), SEND_MODE_IGNORE_ERRORS);\n  }\n\n  w_balance = balance;\n"
        "  save_data();\n}\n\n;; ---- reported",
        "t_r13_",
        "I1:",
    ),
    # Like M46 to M48, M67 holds only through T-R5's need_from_terms: R's
    # margined budget absorbs S's compute at the test's prices.
    M(
        "M67",
        "the value check omits S's own compute",
        f"{C}/token-wallet.fc",
        "          + get_compute_fee(false, S_TRANSFER_GAS)\n",
        "",
        "t_r5_",
        "the need is the sum of its terms",
    ),
    M(
        "M68",
        "S admits a body over its cell cap",
        f"{C}/token-wallet.fc",
        "const int REPORTED_BODY_CELLS = 256;",
        "const int REPORTED_BODY_CELLS = 512;",
        "t_r14_",
        "more than half of its S_TRANSFER_GAS",
    ),
    M(
        "M69",
        "S_TRANSFER_GAS is below twice S's measured most",
        f"{C}/token-wallet.fc",
        "const int S_TRANSFER_GAS = 127000;",
        "const int S_TRANSFER_GAS = 120000;",
        "t_r11_",
        "more than half of its S_TRANSFER_GAS",
    ),
    M(
        "M70",
        "a second refusal under one query id replaces the first",
        f"{C}/token-wallet.fc",
        "    int recorded = total <= MAX_SUPPLY ? total : earlier;",
        "    int recorded = token_amount;",
        "t_r2_a_second_refusal",
        "is recorded",
    ),
    M(
        "M71",
        "R's budget is priced without the margin",
        f"{C}/token-wallet.fc",
        "const int REPORT_MARGIN = 10;",
        "const int REPORT_MARGIN = 1;",
        "t_r6_a_rise_within_the_margin_ends_every_transfer_without_a_reserve",
        "and delivers",
    ),
    M(
        "M72",
        "S admits a reported transfer at the refusal limit",
        f"{C}/token-wallet.fc",
        "  throw_unless(error::refusals_full, w_refusals_count < REFUSALS_LIMIT);\n",
        "",
        "t_r15_",
        "expected a refusal with 714",
    ),
    M(
        "M73",
        "S records a refusal past the limit",
        f"{C}/token-wallet.fc",
        "  } elseif (w_refusals_count < REFUSALS_LIMIT) {",
        "  } else {",
        "t_r15_",
        "no more than REFUSALS_LIMIT refusals are recorded",
    ),
    M(
        "M74",
        "clearing a refusal leaves it counted",
        f"{C}/token-wallet.fc",
        "  if (deleted) {\n    w_refusals_count -= 1;\n  }\n",
        "",
        "t_r15_",
        "I11:",
    ),
    M(
        "M75",
        "a re-report is sent as a new refusal",
        f"{C}/token-wallet.fc",
        "  send_refused(op::transfer_rereported,",
        "  send_refused(op::transfer_refused,",
        "t_r7_",
        "the refusal is reported again",
    ),
    M(
        "M76",
        "R raises its gas limit before checking that the message pays for it",
        f"{C}/token-wallet.fc",
        "    throw_unless(error::reported_underfunded, msg_value >= get_compute_fee(false, R_GAS_LIMIT));\n"
        "    set_gas_limit(R_GAS_LIMIT);\n",
        "    set_gas_limit(R_GAS_LIMIT);\n"
        "    throw_unless(error::reported_underfunded, msg_value >= get_compute_fee(false, R_GAS_LIMIT));\n",
        "t_r16_",
        "R's balance paid for a forged message",
    ),
    M(
        "M77",
        "R raises its gas limit for any message",
        f"{C}/token-wallet.fc",
        "    throw_unless(error::reported_underfunded, msg_value >= get_compute_fee(false, R_GAS_LIMIT));\n",
        "",
        "t_r16_",
        "R's balance paid for a forged message",
    ),
    # The oracle multisig: S01 to S06.
    *multisig_controls("S", f"{C}/multisig.fc"),
    # EVM
    M(
        "E01",
        "lock without an active generation",
        f"{SOL}/Bridge.sol",
        '        require(generation != 0, "No active generation");\n',
        "",
        "refuses every lock until a generation is active",
        "failing",
        evm=True,
    ),
    M(
        "E02",
        "lock nonce exhaustion is not checked",
        f"{SOL}/Bridge.sol",
        '        require(lockNonce <= MAX_LOCK_NONCE, "Lock nonces exhausted");\n',
        "",
        "allocates the last nonce and then refuses, never wrapping",
        "failing",
        evm=True,
    ),
    M(
        "E03",
        "a refund does not check the lock's status",
        f"{SOL}/Bridge.sol",
        '        require(record.status == LOCK_OPEN, "Lock is not refundable");\n',
        "",
        "refunds a cancelled lock once",
        "failing",
        evm=True,
    ),
    M(
        "E04",
        "the refund digest omits the amount",
        f"{SOL}/SignatureChecker.sol",
        "abi.encode(0x4EF0, address(this), block.chainid, n, lockGeneration, locker, token, amount)",
        "abi.encode(0x4EF0, address(this), block.chainid, n, lockGeneration, locker, token, uint256(0))",
        "refunds a cancelled lock once",
        "failing",
        evm=True,
    ),
    M(
        "E05",
        "a generation need not follow the current one",
        f"{SOL}/Bridge.sol",
        '        require(newGeneration == generation + 1, "Generation must follow the current one");\n',
        "",
        "starts each generation above every allocated lock",
        "failing",
        evm=True,
    ),
    M(
        "E06",
        "a stale generation nonce is accepted",
        f"{SOL}/Bridge.sol",
        '        require(nonce > lastGenerationNonce, "Stale generation nonce");\n',
        "",
        "starts each generation above every allocated lock",
        "failing",
        evm=True,
    ),
    M(
        "E07",
        "an uncapped token is refused without its own error message (an error-message pin: the per-lock cap still refuses it)",
        f"{SOL}/Bridge.sol",
        '        require(lockCaps[token].total != 0, "lock: token has no lock cap");\n',
        "",
        "refuses locks before any cap is set",
        "failing",
        evm=True,
    ),
    M(
        "E08",
        "the per-lock cap is not checked",
        f"{SOL}/Bridge.sol",
        '        require(received <= cap.perLock, "lock: over the per-lock cap");\n',
        "",
        "accepts a lock at the per-lock cap and refuses one unit more",
        "failing",
        evm=True,
    ),
    M(
        "E09",
        "the token cap is not checked",
        f"{SOL}/Bridge.sol",
        '        require(newBalance <= cap.total, "lock: over the token cap");\n',
        "",
        "accepts a balance at the token cap",
        "failing",
        evm=True,
    ),
    M(
        "E10",
        "the hourly cap is not checked",
        f"{SOL}/Bridge.sol",
        '        require(hourUsed <= cap.hourly, "lock: over the hourly cap");\n',
        "",
        "fills the hourly bucket exactly",
        "failing",
        evm=True,
    ),
    M(
        "E11",
        "the daily cap is not checked",
        f"{SOL}/Bridge.sol",
        '        require(dayUsed <= cap.daily, "lock: over the daily cap");\n',
        "",
        "fills the daily bucket across hours",
        "failing",
        evm=True,
    ),
    M(
        "E12",
        "an earlier hour's usage is charged to the current hour",
        f"{SOL}/Bridge.sol",
        "        hourUsed = usage.hour == hour ? usage.hourUsed : 0;\n",
        "        hourUsed = usage.hourUsed;\n",
        "fills the hourly bucket exactly",
        "failing",
        evm=True,
    ),
    M(
        "E13",
        "the caps count the requested amount, not the received one",
        f"{SOL}/Bridge.sol",
        "        _consumeLockCap(token, received, newBalance);\n",
        "        _consumeLockCap(token, amount, newBalance);\n",
        "caps a fee-on-transfer token by the received amount",
        "failing",
        evm=True,
    ),
    M(
        "E14",
        "a stale lock cap nonce is accepted",
        f"{SOL}/Bridge.sol",
        '        require(nonce > lastLockCapNonce[token], "Stale lock cap nonce");\n',
        "",
        "refuses a cap vote with too few",
        "failing",
        evm=True,
    ),
    M(
        "E15",
        "unordered or partly zero caps are accepted",
        f"{SOL}/Bridge.sol",
        '            require(perLock <= hourly && hourly <= daily, "Lock caps are not ordered");\n',
        "",
        "refuses partly zero, unordered",
        "failing",
        evm=True,
    ),
    M(
        "E16",
        "a cap over the supply bound is truncated instead of refused",
        f"{SOL}/Bridge.sol",
        '            require(total <= 2 ** 120 - 1 && daily <= 2 ** 120 - 1, "Lock cap over the supply bound");\n',
        "",
        "refuses partly zero, unordered",
        "failing",
        evm=True,
    ),
    M(
        "E17",
        "the lock cap digest omits the token",
        f"{SOL}/SignatureChecker.sol",
        "abi.encode(0xCA95, address(this), block.chainid, token, total, perLock, hourly, daily, nonce)",
        "abi.encode(0xCA95, address(this), block.chainid, total, perLock, hourly, daily, nonce)",
        "refuses a cap vote signed for another token",
        "expected a refusal: Wrong signature",
        evm=True,
    ),
    M(
        "E18",
        "an unlock reads the lock caps",
        f"{SOL}/Bridge.sol",
        "        IERC20(data.token).safeTransfer(data.receiver, data.amount);\n",
        '        require(lockCaps[data.token].total != 0, "payout reads the caps");\n        IERC20(data.token).safeTransfer(data.receiver, data.amount);\n',
        "pays out by unlock and refundLock after the caps are voted to zero",
        "payout reads the caps",
        evm=True,
    ),
    M(
        "E19",
        "a refund is held to the total cap",
        f"{SOL}/Bridge.sol",
        "        IERC20(record.token).safeTransfer(record.locker, record.amount);\n",
        '        require(IERC20(record.token).balanceOf(address(this)) <= lockCaps[record.token].total, "payout reads the caps");\n        IERC20(record.token).safeTransfer(record.locker, record.amount);\n',
        "pays out by unlock and refundLock after the total cap is voted below the balance",
        "payout reads the caps",
        evm=True,
    ),
    M(
        "E20",
        "partly zero caps are accepted",
        f"{SOL}/Bridge.sol",
        '            require(total != 0 && perLock != 0, "Lock cap is partly zero");\n',
        "",
        "refuses partly zero, unordered",
        "expected a refusal: Lock cap is partly zero",
        evm=True,
    ),
    M(
        "E21",
        "caps can be voted for the zero token",
        f"{SOL}/Bridge.sol",
        '        require(token != address(0), "Lock cap names no token");\n',
        "",
        "refuses partly zero, unordered",
        "expected a refusal: Lock cap names no token",
        evm=True,
    ),
]


def scratch_root() -> Path:
    root = Path(tempfile.mkdtemp(prefix="token-bridge-mutations-"))
    for sub in ("tvm", "tests"):
        shutil.copytree(ROOT / BRIDGE / sub, root / BRIDGE / sub)
    # bridge_multisig_sandbox compiles every bridge multisig, coin ones too.
    shutil.copytree(ROOT / COIN / "tvm", root / COIN / "tvm")
    evm = root / BRIDGE / "evm"
    shutil.copytree(
        ROOT / BRIDGE / "evm",
        evm,
        ignore=shutil.ignore_patterns(
            "node_modules", "artifacts", "cache", "typechain-types", "build-tron"
        ),
    )
    if (ROOT / BRIDGE / "evm/node_modules").exists():
        (evm / "node_modules").symlink_to(ROOT / BRIDGE / "evm/node_modules")
    for link in ("build", "crypto"):
        (root / link).symlink_to(ROOT / link)
    return root


def restore(root: Path, rel: str) -> None:
    shutil.copyfile(ROOT / rel, root / rel)


def run_sandbox(root: Path, test: str, target: str = "token_bridge_sandbox") -> tuple[int, str]:
    env = dict(os.environ, TOS_ROOT=str(root))
    env.setdefault("FUNC_PATH", str(ROOT / "build/crypto/func"))
    env.setdefault("FIFT_PATH", str(ROOT / "build/crypto/fift"))
    env.pop("TOKEN_BRIDGE_TRACE_DIR", None)
    cmd = [
        "cargo",
        "test",
        "--manifest-path",
        str(ROOT / "tosctl/src/Cargo.toml"),
        "-p",
        "contracts",
        "--locked",
        "--test",
        target,
        test,
    ]
    p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=3000)
    out = p.stdout + p.stderr
    if "running 0 tests" in out or " 0 passed; 0 failed" in out:
        raise SystemExit(f"the filter {test!r} selects no test")
    return p.returncode, out


def failed_tests(out: str) -> set[str]:
    """The tests a cargo test run reports as failed."""
    return {
        line[len("test ") : -len(" ... FAILED")]
        for line in out.splitlines()
        if line.startswith("test ") and line.endswith(" ... FAILED")
    }


def only_named_fails(root: Path, m: Mutation) -> tuple[bool, str]:
    """Under the mutation, every sibling test passes but the named one."""
    _, out = run_sandbox(root, m.exclusive, m.target)
    failed = failed_tests(out)
    named = {t for t in failed if m.test in t}
    others = failed - named
    if others or not named:
        return False, f"siblings that failed: {sorted(failed)}"
    return True, ""


def run_hardhat(root: Path, title: str) -> tuple[int, str]:
    env = dict(os.environ, PRIVATE_KEY="0x" + "00" * 31 + "01")
    cmd = [
        "npx",
        "hardhat",
        "test",
        "test/Settlement.test.ts",
        "test/LockCaps.test.ts",
        "--no-compile",
    ]
    compile_cmd = ["npx", "hardhat", "compile", "--quiet"]
    cwd = root / BRIDGE / "evm"
    c = subprocess.run(compile_cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=900)
    if c.returncode != 0:
        return c.returncode, c.stdout + c.stderr
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=900)
    out = p.stdout + p.stderr
    # red only when the named test is among the failures
    # A mocha failure line is "  <n>) <title>"; a passing line ("✔ <title> (12ms)")
    # also holds a ")" and must never count.
    failed = p.returncode != 0 and any(
        title in line for line in out.splitlines() if re.match(r"^\s*\d+\) ", line)
    )
    return (1 if failed else 0), out


def main(mutations: list[Mutation] | None = None) -> int:
    """Runs `mutations` (this bridge's when not given) under the command line's options."""
    all_mutations = MUTATIONS if mutations is None else mutations
    ap = argparse.ArgumentParser()
    ap.add_argument("--only")
    ap.add_argument("--results")
    ap.add_argument(
        "--skip-evm",
        "--tvm-only",
        dest="skip_evm",
        action="store_true",
        help="run only the TVM-side controls",
    )
    ap.add_argument("--evm-only", action="store_true")
    ap.add_argument("--show", action="store_true", help="print each mutated run's output")
    ap.add_argument("--no-controls", action="store_true", help="skip the unmutated runs")
    args = ap.parse_args()
    chosen = all_mutations
    if args.only:
        ids = set(args.only.split(","))
        chosen = [m for m in all_mutations if m.id in ids]
    if args.skip_evm:
        chosen = [m for m in chosen if not m.evm]
    if args.evm_only:
        chosen = [m for m in chosen if m.evm]
    root = scratch_root()
    results = []
    try:
        # positive controls: every named test passes unmutated
        unmutated = set()
        for m in chosen:
            if not m.evm:
                unmutated.add((m.target, m.test))
                if m.exclusive:
                    unmutated.add((m.target, m.exclusive))
        for target, test in sorted(unmutated if not args.no_controls else []):
            code, out = run_sandbox(root, test, target)
            if code != 0:
                print(out[-3000:])
                raise SystemExit(f"control: {target} {test} fails without any mutation")
            print(f"green  {target} {test}", flush=True)
        if any(m.evm for m in chosen) and not args.no_controls:
            code, out = run_hardhat(root, "")
            if code != 0 or "failing" in out:
                print(out[-3000:])
                raise SystemExit("control: the Hardhat suite fails without any mutation")
            print("green  Settlement.test.ts LockCaps.test.ts")
        for m in chosen:
            target = root / m.file
            text = target.read_text()
            count = text.count(m.old)
            if count != 1:
                raise SystemExit(f"{m.id}: the guard text occurs {count} times in {m.file}")
            target.write_text(text.replace(m.old, m.new))
            note = ""
            try:
                if m.evm:
                    code, out = run_hardhat(root, m.test)
                else:
                    code, out = run_sandbox(root, m.test, m.target)
                red = code != 0 and m.reason in out
                if red and m.exclusive:
                    red, note = only_named_fails(root, m)
            finally:
                restore(root, m.file)
            verdict = (
                "red"
                if red
                else ("survives" if m.survivor else ("red-wrong-reason" if code != 0 else "GREEN"))
            )
            line = next(
                (
                    l.strip()
                    for l in out.splitlines()
                    if "panicked at" in l
                    or "AssertionError" in l
                    or "over its declared" in l
                    or "I8 atomic" in l
                ),
                "",
            )
            if note:
                line = note
            results.append(
                {
                    "id": m.id,
                    "what": m.what,
                    "target": m.target,
                    "test": m.test,
                    "verdict": verdict,
                    "exit": code,
                    "reason": m.reason,
                    "survivor": m.survivor,
                    "failure": line,
                }
            )
            print(f"{verdict:16} {m.id} {m.what} [{m.test}] {line[:160]}", flush=True)
            if args.show:
                print(out[-6000:])
    finally:
        shutil.rmtree(root, ignore_errors=True)
    if args.results:
        Path(args.results).write_text(json.dumps(results, indent=2) + "\n")
    bad = [r for r in results if r["verdict"] not in ("red", "survives")]
    print(
        f"{len(results)} controls: {sum(r['verdict'] == 'red' for r in results)} red, "
        f"{sum(r['verdict'] == 'survives' for r in results)} recorded survivors, {len(bad)} unexpected"
    )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
