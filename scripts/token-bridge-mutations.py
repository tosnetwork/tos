#!/usr/bin/env python3
"""Mutation controls for the token bridge settlement protocol.

Each control removes or weakens one guard in a copy of the sources and runs
the test that names it. A control counts as red only when the test fails for
its named reason: the expected text must appear in the failure. Before the
mutations, every named test runs once against the unmutated copy and must
pass, so a red result cannot come from a broken test.

The working tree is never modified: the contracts, the shared vectors and the
EVM project are copied to a scratch root, which the sandbox reads through
TOS_ROOT and Hardhat runs from.

Usage: token-bridge-mutations.py [--only ID[,ID...]] [--results FILE]
                                 [--skip-evm | --evm-only] [--show] [--no-controls]

Exit status 0 when every control is red for its reason (or is a recorded
survivor), 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BRIDGE = "crosschain/token-bridge"
C = f"{BRIDGE}/tvm/contracts"
SOL = f"{BRIDGE}/evm/contracts"


@dataclass
class Mutation:
    id: str
    what: str
    file: str
    old: str
    new: str
    test: str          # cargo test filter, or a Hardhat test title for EVM
    reason: str        # text the failure must contain
    evm: bool = False
    survivor: str = "" # why this control cannot go red here, if it cannot


M = Mutation

MUTATIONS = [
    M("M01", "the wallet ignores its floor and its set", f"{C}/jetton-wallet.fc",
      "} elseif (k >= max(w_credit_wm, w_credit_cf)) {", "} elseif (true) {",
      "t_m4_", "credit"),
    M("M02", "the minter counts a COUNTED s", f"{C}/jetton-minter.fc",
      "        if (status == MINT_CREDITING) {\n            m_in_flight -= amount;\n            m_supply += amount;\n"
      "            mint_put(s, MINT_COUNTED, bound_life, k, 0, hash, owner, amount, d);\n"
      "            (h_credits, _) = h_credits.udict_delete?(64, k);\n",
      "        if ((status == MINT_CREDITING) | (status == MINT_COUNTED)) {\n            m_in_flight -= amount;\n"
      "            m_supply += amount;\n            mint_put(s, MINT_COUNTED, bound_life, k, 0, hash, owner, amount, d);\n",
      "t_m4_", "I"),
    M("M03", "the bridge ignores its burn watermark", f"{C}/jetton-bridge.fc",
      "} elseif (m < max(c_burn_wm, c_burn_cf)) {", "} elseif (false) {",
      "t_b6_", "LOG_BURN emitted twice"),
    M("M04", "the bridge honours a second cancellation flag", f"{C}/jetton-bridge.fc",
      "        throw_unless(error::operation_mismatch, e~load_uint(256) == hash);\n        send_burn_result(m, outcome);",
      "        throw_unless(error::operation_mismatch, e~load_uint(256) == hash);\n"
      "        if (cancel) {\n            outcome = OUTCOME_CANCELLED;\n"
      "            c_burns~udict_set_builder(64, m, begin_cell().store_uint(outcome, 1).store_uint(hash, 256));\n        }\n"
      "        send_burn_result(m, outcome);",
      "t_b5_", "I"),
    M("M05", "a bounce triggers a refund", f"{C}/jetton-wallet.fc",
      "  if (op != op::internal_transfer) {\n    return ();\n  }\n  in_msg_body~load_query_id();",
      "  if (op == op::burn_admit) {\n    w_balance += 400;\n    save_data();\n    return ();\n  }\n"
      "  if (op != op::internal_transfer) {\n    return ();\n  }\n  in_msg_body~load_query_id();",
      "t_b7_", "I1:"),
    M("M06", "a settlement handler reads ConfigParam 79", f"{C}/jetton-minter.fc",
      "    cell d = body~load_ref();\n    body.end_parse();\n    if (~ bridge_ok?(sender, life, expected, false)) {",
      "    cell d = body~load_ref();\n    body.end_parse();\n    get_jetton_bridge_config();\n"
      "    if (~ bridge_ok?(sender, life, expected, false)) {",
      "t_m7_", "failed"),
    M("M07", "the wallet's descriptor hash comparison is removed", f"{C}/jetton-wallet.fc",
      "        throw_unless(error::operation_mismatch, entry.preload_uint(256) == hash);\n", "",
      "t_m6_", "panicked"),
    M("M08", "the minter's burn descriptor hash comparison is removed", f"{C}/jetton-minter.fc",
      "        throw_unless(error::operation_mismatch, stored_hash == hash);\n"
      "        if ((status == BURN_AWAITING_BRIDGE) & cancel & (~ stored_cancel)) {",
      "        if ((status == BURN_AWAITING_BRIDGE) & cancel & (~ stored_cancel)) {",
      "t_b8_", "panicked"),
    M("M09", "burn_reserve is not counted", f"{C}/jetton-minter.fc",
      "        m_burn_reserve += amount;\n        m_notices~udict_set_builder",
      "        m_notices~udict_set_builder",
      "t_x1_", "panicked"),
    M("M10", "an exception is dropped without the sender's floor", f"{C}/jetton-minter.fc",
      "if ((status == MINT_COUNTED) | (m_mint_wm < m_mint_cf)) {", "if (true) {",
      "t_x3_a_refusal", "panicked"),
    M("M11", "ADMIT_REFUSED is not stored", f"{C}/jetton-minter.fc",
      "        h_burns~udict_set_builder(64, b, burn_record(BURN_ADMIT_REFUSED, cancel, 0, amount, hash, d));\n"
      "        send_burn_answer(op::admit_refused",
      "        send_burn_answer(op::admit_refused",
      "t_y1_", "panicked"),
    M("M12", "the sender window ignores its acknowledged floor", f"{C}/jetton-bridge.fc",
      "    require_window(s, c_mint_ack, MINT_WINDOW);\n", "",
      "t_y4_", "panicked"),
    M("M13", "the wallet's life check is removed", f"{C}/jetton-wallet.fc",
      "    throw_unless(error::life_mismatch, wallet_life == w_born);\n"
      "    (_, _, int amount, _, _, _, slice minter, slice recipient) = parse_mint_descriptor(descriptor);",
      "    (_, _, int amount, _, _, _, slice minter, slice recipient) = parse_mint_descriptor(descriptor);",
      "t_x4_an_old_life", "panicked"),
    M("M14", "a newer hub life is treated as a recreated wallet", f"{C}/jetton-wallet.fc",
      "    if (minter_life > w_minter_life) {\n        w_minter_terminal = 1;\n        save_data();\n        return false;\n    }",
      "    if (minter_life > w_minter_life) {\n        w_minter_life = minter_life;\n        return true;\n    }",
      "t_y6_a_newer", "panicked"),
    M("M15", "cancel_lock accepts a PREPARING lock", f"{C}/jetton-bridge.fc",
      "        throw_unless(error::not_admissible, e.preload_uint(2) == SWAP_PAID);\n        e~skip_bits(2);\n        slice payer",
      "        throw_unless(error::not_admissible, e.preload_uint(2) <= SWAP_PREPARING);\n        e~skip_bits(2);\n        slice payer",
      "t_y5_", "panicked"),
    M("M16", "an advance takes a field from its body", f"{C}/jetton-bridge.fc",
      "        int s = body~load_uint(64);\n        body.end_parse();\n        int need = advance_need(kind, s);",
      "        int s = body~load_uint(64);\n        int need = advance_need(kind, s);",
      "t_m9_", "extra fields"),
    M("M17", "admission tests only W, not max(W, C)", f"{C}/jetton-minter.fc",
      "    if (s < max(m_mint_wm, m_mint_cf)) {\n        ;; counted, the channel's default",
      "    if (s < m_mint_wm) {\n        ;; counted, the channel's default",
      "t_z2_", "panicked",
      survivor="redundant by construction: no entry at or above W is ever deleted (folding removes an "
               "entry only after W passes it, compaction only below min(W, C)), so a number in [W, C) "
               "always finds its own entry before the admission bound is consulted"),
    M("M18", "a reported floor is accepted without validation", f"{C}/jetton-minter.fc",
      "    throw_unless(error::bad_floor, floor <= entered_high(m_mints, m_mint_wm));\n", "",
      "t_z2_", "panicked"),
    M("M19", "credits are bounded by the global window instead of the holder's k", f"{C}/jetton-minter.fc",
      "        if ((k > MAX_SEQ) | (k >= h_credit_ack + CREDIT_WINDOW)) {",
      "        if (k > MAX_SEQ) {",
      "t_z3_", "panicked"),
    M("M20", "RESERVED is not stranded on recreation", f"{C}/jetton-minter.fc",
      "    if ((status != MINT_RESERVED) & (status != MINT_CREDITING)) {", "    if (status != MINT_CREDITING) {",
      "t_z4_a_wallet_deleted", "panicked"),
    M("M21", "the generation check is removed", f"{C}/jetton-bridge.fc",
      "(b_gen_state == GEN_ACTIVE) & (generation == b_generation)", "b_gen_state == GEN_ACTIVE",
      "t_z1_", "panicked"),
    M("M22", "a sender advances its floor from C instead of S", f"{C}/jetton-minter.fc",
      "            .store_uint(channel::c1, 8)\n            .store_uint(mint_storage_floor(), 64));",
      "            .store_uint(channel::c1, 8)\n            .store_uint(m_mint_cf, 64));",
      "t_z2_", "panicked",
      survivor="equivalent at the current constants: a reply is always computed after a fold of up to "
               "FOLD_LIMIT numbers, and the unfolded backlog never exceeds MINT_WINDOW - FOLD_LIMIT = "
               "FOLD_LIMIT, so W has caught up with C and S = min(W, C) = C whenever a reply is sent"),
    M("M23", "a waiting mint is promoted past the holder's credit window", f"{C}/jetton-minter.fc",
      "if ((h_open == HOLDER_OPEN) & (k <= MAX_SEQ) & (k < h_credit_ack + CREDIT_WINDOW)) {",
      "if (h_open == HOLDER_OPEN) {",
      "t_z7_", "panicked"),
    M("M24", "LOG_LIABILITY_STRANDED is sent in mode 2", f"{C}/settlement.fc",
      "        .store_ref(data)\n        .end_cell(), 0);\n}\n\n;; A record for observers only",
      "        .store_ref(data)\n        .end_cell(), 2);\n}\n\n;; A record for observers only",
      "t_z4_stranding", "panicked",
      survivor="the log cannot be made to fail in the sandbox engine: its message-size check never "
               "refuses (StorageUsageCalc stops counting at the limit), and every leg's funding "
               "check leaves the reserve to pay the log, so mode 0 and mode 2 behave alike here"),
    M("M25", "a record keeps only a hash", f"{C}/jetton-bridge.fc",
      ".store_uint(hash, 256).store_ref(d));\n}", ".store_uint(hash, 256).store_ref(begin_cell().end_cell()));\n}",
      "t_z6_a_mint", "panicked"),
    M("M26", "cancel_lock below the watermark is evaluated", f"{C}/jetton-bridge.fc",
      "    require_open_swap(n);\n    (slice e, int found) = b_swaps.udict_get?(64, n);\n    if (found) {\n"
      "        throw_unless(error::not_admissible, e.preload_uint(2) == SWAP_PAID);",
      "    throw_unless(error::sequence_exhausted, n <= MAX_SEQ);\n    (slice e, int found) = b_swaps.udict_get?(64, n);\n"
      "    if (found) {\n        throw_unless(error::not_admissible, e.preload_uint(2) == SWAP_PAID);",
      "t_z1_", "panicked"),
    M("M27", "atomic send: +2 on the cancellation refund", f"{C}/jetton-bridge.fc",
      "                .store_coins(refund)\n                .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)\n                .end_cell(), 1);",
      "                .store_coins(refund)\n                .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)\n                .end_cell(), 3);",
      "t_x7_", "I8 atomic send"),
    M("M28", "the vote's namespace check is removed", f"{C}/jetton-bridge.fc",
      "    throw_unless(error::wrong_namespace, (evm_chain_id == b_evm_chain) & (evm_bridge == b_evm_bridge) & (b_evm_chain == MY_CHAIN_ID));\n",
      "", "t_x8_votes", "panicked"),
    M("M29", "the zero-destination check is removed", f"{C}/jetton-wallet.fc",
      "  throw_if(error::zero_destination, destination_address == 0);\n", "",
      "t_x8_votes", "panicked"),
    M("M30", "the bridge's capacity check is removed", f"{C}/jetton-bridge.fc",
      "    require_cell_capacity(BRIDGE_WORST_CELLS, true);\n}", "}",
      "t_y8_a_lowered", "panicked"),
    M("M31", "an unpaid cancellation's funding check is removed", f"{C}/jetton-bridge.fc",
      "        throw_unless(error::underfunded, msg_value_of_in() >= get_cancel_cost());\n", "",
      "t_y5_", "panicked"),
    M("M32", "a vote returns all its value, leaving the log to the bridge", f"{C}/jetton-bridge.fc",
      "        if (b_vote_keep > 0) {", "        if (false) {",
      "t_y5_", "I7"),
    M("M33", "a stranded report rewrites a committed swap", f"{C}/jetton-bridge.fc",
      "            if (status == PENDING_PREPARING) {\n                b_swaps~udict_set_builder(64, n, begin_cell().store_uint(SWAP_CONSUMED, 2));\n            }",
      "            b_swaps~udict_set_builder(64, n, begin_cell().store_uint(SWAP_CONSUMED, 2));",
      "t_z4_a_wallet_deleted", "panicked"),
    M("M34", "a step's declared gas is below what it uses", f"{C}/settlement.fc",
      "const int WALLET_STEP_GAS = 40000;", "const int WALLET_STEP_GAS = 4000;",
      "t_m1_", "over its declared"),
    M("M35", "stranding exceeds FOLD_LIMIT per transaction", f"{C}/jetton-minter.fc",
      "    while (more & (steps < FOLD_LIMIT)) {\n        (int b, slice e, int found) = first ?",
      "    while (more & (steps < FOLD_LIMIT + 4)) {\n        (int b, slice e, int found) = first ?",
      "t_z4_stranding", "strand"),
    # EVM
    M("E01", "lock without an active generation", f"{SOL}/Bridge.sol",
      '        require(generation != 0, "No active generation");\n', "",
      "refuses every lock until a generation is active", "failing", evm=True),
    M("E02", "lock nonce exhaustion is not checked", f"{SOL}/Bridge.sol",
      '        require(lockNonce <= MAX_LOCK_NONCE, "Lock nonces exhausted");\n', "",
      "allocates the last nonce and then refuses, never wrapping", "failing", evm=True),
    M("E03", "a refund does not check the lock's status", f"{SOL}/Bridge.sol",
      '        require(record.status == LOCK_OPEN, "Lock is not refundable");\n', "",
      "refunds a cancelled lock once", "failing", evm=True),
    M("E04", "the refund digest omits the amount", f"{SOL}/SignatureChecker.sol",
      "abi.encode(0x4EF0, address(this), block.chainid, n, lockGeneration, locker, token, amount)",
      "abi.encode(0x4EF0, address(this), block.chainid, n, lockGeneration, locker, token, uint256(0))",
      "refunds a cancelled lock once", "failing", evm=True),
    M("E05", "a generation need not follow the current one", f"{SOL}/Bridge.sol",
      '        require(newGeneration == generation + 1, "Generation must follow the current one");\n', "",
      "starts each generation above every allocated lock", "failing", evm=True),
    M("E06", "a stale generation nonce is accepted", f"{SOL}/Bridge.sol",
      '        require(nonce > lastGenerationNonce, "Stale generation nonce");\n', "",
      "starts each generation above every allocated lock", "failing", evm=True),
]


def scratch_root() -> Path:
    root = Path(tempfile.mkdtemp(prefix="token-bridge-mutations-"))
    for sub in ("tvm", "tests"):
        shutil.copytree(ROOT / BRIDGE / sub, root / BRIDGE / sub)
    evm = root / BRIDGE / "evm"
    shutil.copytree(
        ROOT / BRIDGE / "evm", evm,
        ignore=shutil.ignore_patterns("node_modules", "artifacts", "cache", "typechain-types", "build-tron"),
    )
    if (ROOT / BRIDGE / "evm/node_modules").exists():
        (evm / "node_modules").symlink_to(ROOT / BRIDGE / "evm/node_modules")
    for link in ("build", "crypto"):
        (root / link).symlink_to(ROOT / link)
    return root


def restore(root: Path, rel: str) -> None:
    shutil.copyfile(ROOT / rel, root / rel)


def run_sandbox(root: Path, test: str) -> tuple[int, str]:
    env = dict(os.environ, TOS_ROOT=str(root))
    env.setdefault("FUNC_PATH", str(ROOT / "build/crypto/func"))
    env.setdefault("FIFT_PATH", str(ROOT / "build/crypto/fift"))
    env.pop("TOKEN_BRIDGE_TRACE_DIR", None)
    cmd = ["cargo", "test", "--manifest-path", str(ROOT / "tosctl/src/Cargo.toml"), "-p", "contracts",
           "--locked", "--test", "token_bridge_sandbox", test]
    p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=3000)
    out = p.stdout + p.stderr
    if "running 0 tests" in out or " 0 passed; 0 failed" in out:
        raise SystemExit(f"the filter {test!r} selects no test")
    return p.returncode, out


def run_hardhat(root: Path, title: str) -> tuple[int, str]:
    env = dict(os.environ, PRIVATE_KEY="0x" + "00" * 31 + "01")
    cmd = ["npx", "hardhat", "test", "test/Settlement.test.ts", "--no-compile"]
    compile_cmd = ["npx", "hardhat", "compile", "--quiet"]
    cwd = root / BRIDGE / "evm"
    c = subprocess.run(compile_cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=900)
    if c.returncode != 0:
        return c.returncode, c.stdout + c.stderr
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=900)
    out = p.stdout + p.stderr
    # red only when the named test is among the failures
    failed = p.returncode != 0 and any(title in line for line in out.splitlines() if ")" in line)
    return (1 if failed else 0), out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only")
    ap.add_argument("--results")
    ap.add_argument("--skip-evm", action="store_true")
    ap.add_argument("--evm-only", action="store_true")
    ap.add_argument("--show", action="store_true", help="print each mutated run's output")
    ap.add_argument("--no-controls", action="store_true", help="skip the unmutated runs")
    args = ap.parse_args()
    chosen = MUTATIONS
    if args.only:
        ids = set(args.only.split(","))
        chosen = [m for m in MUTATIONS if m.id in ids]
    if args.skip_evm:
        chosen = [m for m in chosen if not m.evm]
    if args.evm_only:
        chosen = [m for m in chosen if m.evm]
    root = scratch_root()
    results = []
    try:
        # positive controls: every named test passes unmutated
        for test in sorted({m.test for m in chosen if not m.evm} if not args.no_controls else []):
            code, out = run_sandbox(root, test)
            if code != 0:
                print(out[-3000:])
                raise SystemExit(f"control: {test} fails without any mutation")
            print(f"green  {test}", flush=True)
        if any(m.evm for m in chosen) and not args.no_controls:
            code, out = run_hardhat(root, "")
            if code != 0 or "failing" in out:
                print(out[-3000:])
                raise SystemExit("control: the Hardhat suite fails without any mutation")
            print("green  Settlement.test.ts")
        for m in chosen:
            target = root / m.file
            text = target.read_text()
            count = text.count(m.old)
            if count != 1:
                raise SystemExit(f"{m.id}: the guard text occurs {count} times in {m.file}")
            target.write_text(text.replace(m.old, m.new))
            try:
                code, out = run_hardhat(root, m.test) if m.evm else run_sandbox(root, m.test)
            finally:
                restore(root, m.file)
            red = code != 0 and m.reason in out
            verdict = "red" if red else ("survives" if m.survivor else ("red-wrong-reason" if code != 0 else "GREEN"))
            line = next((l.strip() for l in out.splitlines() if "panicked at" in l or "AssertionError" in l
                         or "over its declared" in l or "I8 atomic" in l), "")
            detail = next((l.strip() for l in out.splitlines()
                           if l.strip() and not l.startswith(" ") and ("assert" in l or "I" in l[:3])), "")
            results.append({"id": m.id, "what": m.what, "test": m.test, "verdict": verdict,
                            "exit": code, "reason": m.reason, "survivor": m.survivor, "failure": line})
            print(f"{verdict:16} {m.id} {m.what} [{m.test}] {line[:160]}", flush=True)
            if args.show:
                print(out[-6000:])
    finally:
        shutil.rmtree(root, ignore_errors=True)
    if args.results:
        Path(args.results).write_text(json.dumps(results, indent=2) + "\n")
    bad = [r for r in results if r["verdict"] not in ("red", "survives")]
    print(f"{len(results)} controls: {sum(r['verdict'] == 'red' for r in results)} red, "
          f"{sum(r['verdict'] == 'survives' for r in results)} recorded survivors, {len(bad)} unexpected")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
