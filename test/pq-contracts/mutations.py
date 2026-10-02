#!/usr/bin/env python3
"""Removes each guard of the post-quantum contracts in turn and requires a test to fail.

usage: mutations.py --build <build-dir> --signer <test-pq-contracts-sign> [--case NAME]...

A guard that no test notices is either untested or unreachable; both are findings. Each
mutation edits one source file, runs the suite that covers it, and restores the file
whatever happens. A mutation whose text is not found exactly once is itself an error, so
the list cannot silently drift from the sources.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FUNC_LIB = ROOT / "crypto/smartcont/pq-quorum-signatures.fc"
TOL_LIB = ROOT / "crypto/smartcont/tol-stdlib/pq-quorum-signatures.tol"
WALLET = ROOT / "crypto/smartcont/pq-highload-wallet-code.fc"
HIGHLOAD = ("test_pq_highload.py", ())
QUORUM_FUNC = ("test_pq_quorum.py", ("--harness", str(HERE / "pq-quorum-harness.fc")))
QUORUM_TOL = ("test_pq_quorum.py", ("--harness", str(HERE / "pq-quorum-harness.tol")))

# (name, file, old text, replacement, suite)
MUTATIONS = [
    (
        "func-count-early-stop",
        FUNC_LIB,
        "    throw_if(pq_quorum::error::wrong_signature_count, count > quorum);\n",
        "",
        QUORUM_FUNC,
    ),
    (
        "func-count-exact",
        FUNC_LIB,
        "  throw_unless(pq_quorum::error::wrong_signature_count, count == quorum);\n",
        "",
        QUORUM_FUNC,
    ),
    (
        "func-membership-before-verification",
        FUNC_LIB,
        "    pq_quorum::signer_key(config, id);\n    pq_quorum::entry_signature(entry);\n",
        "",
        QUORUM_FUNC,
    ),
    (
        "func-verification",
        FUNC_LIB,
        "    throw_unless(pq_quorum::error::invalid_signature,\n                 pq_check_mldsa44(",
        "    (pq_check_mldsa44(",
        QUORUM_FUNC,
    ),
    (
        "func-signature-wrapper",
        FUNC_LIB,
        "  throw_unless(pq_quorum::error::malformed_signature, stored.preload_uint(32) == pq::mldsa44_signature_bytes);\n",
        "",
        QUORUM_FUNC,
    ),
    (
        "func-key-id-match",
        FUNC_LIB,
        "    throw_unless(pq_quorum::error::key_id_mismatch,\n                 pq::key_id(pq::algorithm::mldsa44, pq_quorum::entry_key(entry)) == id);\n",
        "    pq_quorum::entry_key(entry);\n",
        QUORUM_FUNC,
    ),
    (
        "func-entry-shape",
        FUNC_LIB,
        "  throw_unless(pq_quorum::error::invalid_config, (entry.slice_bits() == 0) & (entry.slice_refs() == 1));\n",
        "",
        QUORUM_FUNC,
    ),
    ("func-max-quorum", FUNC_LIB, " & (quorum <= pq_quorum::max_quorum)", "", QUORUM_FUNC),
    ("func-quorum-reachable", FUNC_LIB, " & (quorum <= verifier_count)", "", QUORUM_FUNC),
    (
        "func-duplicate-verifier",
        FUNC_LIB,
        "  throw_unless(pq_quorum::error::duplicate_verifier, added);\n",
        "",
        QUORUM_FUNC,
    ),
    (
        "func-expiry",
        FUNC_LIB,
        "  throw_if(pq_quorum::error::expired, now() > valid_until);\n",
        "",
        QUORUM_FUNC,
    ),
    ("func-hash-binds-nonce", FUNC_LIB, "      .store_uint(nonce, 64)\n", "", QUORUM_FUNC),
    (
        "func-context",
        FUNC_LIB,
        'begin_cell().store_slice("TOS-PQ-QUORUM-v1")',
        'begin_cell().store_slice("TOS-PQ-QUORUM-v2")',
        QUORUM_FUNC,
    ),
    (
        "func-request-config-range",
        FUNC_LIB,
        "  [_, int verifier_count, int quorum] = config;\n  pq_quorum::require_valid_config(verifier_count, quorum);\n",
        "  [_, int verifier_count, int quorum] = config;\n",
        QUORUM_FUNC,
    ),
    (
        "func-target-size",
        FUNC_LIB,
        "  throw_unless(pq_quorum::error::invalid_target, (target.slice_bits() == 267) & (target.slice_refs() == 0));\n",
        "",
        QUORUM_FUNC,
    ),
    (
        "func-added-bound",
        FUNC_LIB,
        "  pq_quorum::require_valid_config(count + 1, quorum);\n",
        "",
        QUORUM_FUNC,
    ),
    (
        "func-removed-keeps-quorum",
        FUNC_LIB,
        "  pq_quorum::require_valid_config(count - 1, quorum);\n",
        "",
        QUORUM_FUNC,
    ),
    (
        "func-removed-member",
        FUNC_LIB,
        "  throw_unless(pq_quorum::error::unknown_signer, removed);\n",
        "",
        QUORUM_FUNC,
    ),
    (
        "tol-request-config-range",
        TOL_LIB,
        "    pqQuorumRequireValidConfig(self.verifierCount, self.quorum);\n\n",
        "",
        QUORUM_TOL,
    ),
    (
        "tol-added-bound",
        TOL_LIB,
        "    pqQuorumRequireValidConfig(self.verifierCount + 1, self.quorum);\n",
        "",
        QUORUM_TOL,
    ),
    (
        "tol-removed-keeps-quorum",
        TOL_LIB,
        "    pqQuorumRequireValidConfig(self.verifierCount - 1, self.quorum);\n",
        "",
        QUORUM_TOL,
    ),
    (
        "tol-removed-member",
        TOL_LIB,
        "    if (!next.uDictDelete(PQ_QUORUM_KEY_BITS, keyId)) {\n        throw PQ_QUORUM_THROW_UNKNOWN_SIGNER;\n    }\n",
        "    next.uDictDelete(PQ_QUORUM_KEY_BITS, keyId);\n",
        QUORUM_TOL,
    ),
    (
        "tol-key-chunk-boundary",
        TOL_LIB,
        "            if (bytes != PQ_QUORUM_CHUNK_BYTES) {\n                throw PQ_QUORUM_THROW_MALFORMED_KEY;\n            }\n",
        "",
        QUORUM_TOL,
    ),
    (
        "tol-key-length",
        TOL_LIB,
        "    if (declared != PQ_QUORUM_KEY_BYTES) {\n        throw PQ_QUORUM_THROW_KEY_LENGTH;\n    }\n",
        "",
        QUORUM_TOL,
    ),
    (
        "wallet-relayer-workchain",
        WALLET,
        "  throw_unless(error::wrong_workchain, relayer_workchain == basechain);\n",
        "",
        HIGHLOAD,
    ),
    (
        "wallet-own-workchain",
        WALLET,
        "  (int my_workchain, _) = parse_std_addr(my_address());\n  throw_unless(error::wrong_workchain, my_workchain == basechain);\n\n",
        "\n",
        HIGHLOAD,
    ),
    (
        "wallet-network",
        WALLET,
        "  throw_unless(error::wrong_network, r~load_int(32) == pq::global_id());\n",
        "  r~load_int(32);\n",
        HIGHLOAD,
    ),
    (
        "wallet-address",
        WALLET,
        "  throw_unless(error::wrong_wallet, equal_slice_bits(r~load_msg_addr(), my_address()));\n",
        "  r~load_msg_addr();\n",
        HIGHLOAD,
    ),
    (
        "wallet-subwallet",
        WALLET,
        "  throw_unless(error::wrong_subwallet, r~load_uint(SUBWALLET_ID_BITS) == subwallet_id);\n",
        "  r~load_uint(SUBWALLET_ID_BITS);\n",
        HIGHLOAD,
    ),
    (
        "wallet-timeout",
        WALLET,
        "  throw_unless(error::wrong_timeout, r~load_uint(TIMEOUT_BITS) == timeout);\n",
        "  r~load_uint(TIMEOUT_BITS);\n",
        HIGHLOAD,
    ),
    (
        "wallet-replay-check",
        WALLET,
        "  guard~replay_guard::check(query_id, created_at);\n",
        "",
        HIGHLOAD,
    ),
    (
        "wallet-action-bound",
        WALLET,
        "    throw_if(error::invalid_action, count > max_actions);\n",
        "",
        HIGHLOAD,
    ),
    (
        "wallet-send-only",
        WALLET,
        "    throw_unless(error::invalid_action, node~load_uint(32) == action::send_msg);\n",
        "    node~load_uint(32);\n",
        HIGHLOAD,
    ),
    (
        "wallet-no-destroy",
        WALLET,
        "(SEND_MODE_DESTROY_IF_ZERO | SEND_MODE_CARRY_INBOUND_VALUE)",
        "SEND_MODE_CARRY_INBOUND_VALUE",
        HIGHLOAD,
    ),
    (
        "wallet-no-carry-inbound",
        WALLET,
        "(SEND_MODE_DESTROY_IF_ZERO | SEND_MODE_CARRY_INBOUND_VALUE)",
        "SEND_MODE_DESTROY_IF_ZERO",
        HIGHLOAD,
    ),
    (
        "wallet-message-not-bounced",
        WALLET,
        "  throw_if(error::invalid_message, flags & 1);\n",
        "",
        HIGHLOAD,
    ),
    (
        "wallet-message-source",
        WALLET,
        "  throw_unless(error::invalid_message, m~load_uint(2) == 0); ;; src: addr_none",
        "  m~load_msg_addr(); ;; src",
        HIGHLOAD,
    ),
    (
        "wallet-message-no-init",
        WALLET,
        "  throw_if(error::invalid_message, m~load_uint(1)); ;; no StateInit",
        "  m~load_uint(1); ;; no StateInit",
        HIGHLOAD,
    ),
    (
        "wallet-message-body-consumed",
        WALLET,
        "    m~load_ref();\n    m.end_parse();\n",
        "    m~load_ref();\n",
        HIGHLOAD,
    ),
    (
        "wallet-list-terminator",
        WALLET,
        "  node.end_parse(); ;; the empty terminator\n",
        "",
        HIGHLOAD,
    ),
    (
        "wallet-batch-not-empty",
        WALLET,
        "  throw_unless(error::invalid_action, count > 0);\n",
        "",
        HIGHLOAD,
    ),
    (
        "wallet-funding",
        WALLET,
        "  throw_unless(error::insufficient_value, msg_value >= required_value(count));\n",
        "",
        HIGHLOAD,
    ),
    (
        "wallet-signature-length",
        WALLET,
        "  throw_unless(error::bad_submission, stored.preload_uint(32) == pq::mldsa44_signature_bytes);\n",
        "",
        HIGHLOAD,
    ),
    (
        "wallet-verification",
        WALLET,
        "  throw_unless(error::invalid_signature, pq_check_mldsa44(message, context, stored.preload_ref(), key));\n",
        "  pq_check_mldsa44(message, context, stored.preload_ref(), key);\n",
        HIGHLOAD,
    ),
    (
        "wallet-record",
        WALLET,
        "  guard~replay_guard::record(query_id);\n",
        "",
        HIGHLOAD,
    ),
    (
        "wallet-refund",
        WALLET,
        "      .end_cell(), SEND_MODE_CARRY_INBOUND_VALUE | SEND_MODE_IGNORE_ERRORS);\n",
        "      .end_cell(), SEND_MODE_CARRY_INBOUND_VALUE | SEND_MODE_IGNORE_ERRORS | 128);\n",
        HIGHLOAD,
    ),
    (
        "wallet-forced-ignore-errors",
        WALLET,
        "    send_raw_message(outbound, mode | SEND_MODE_IGNORE_ERRORS);\n",
        "    send_raw_message(outbound, mode);\n",
        HIGHLOAD,
    ),
    (
        "tol-count-early-stop",
        TOL_LIB,
        "        if (count > self.quorum) {\n            throw PQ_QUORUM_THROW_WRONG_SIGNATURE_COUNT;\n        }\n",
        "",
        QUORUM_TOL,
    ),
    (
        "tol-count-exact",
        TOL_LIB,
        "    if (count != self.quorum) {\n        throw PQ_QUORUM_THROW_WRONG_SIGNATURE_COUNT;\n    }\n",
        "",
        QUORUM_TOL,
    ),
    (
        "tol-membership-before-verification",
        TOL_LIB,
        "        self.signerKey(id!);\n        pqQuorumEntrySignature(entry!);\n",
        "",
        QUORUM_TOL,
    ),
    (
        "tol-verification",
        TOL_LIB,
        "            throw PQ_QUORUM_THROW_INVALID_SIGNATURE;\n",
        "",
        QUORUM_TOL,
    ),
    (
        "tol-signature-wrapper",
        TOL_LIB,
        "    if (stored.preloadUint(32) != PQ_QUORUM_SIGNATURE_BYTES) {\n        throw PQ_QUORUM_THROW_MALFORMED_SIGNATURE;\n    }\n",
        "",
        QUORUM_TOL,
    ),
    (
        "tol-key-id-match",
        TOL_LIB,
        "        if (pqQuorumKeyId(pqQuorumEntryKey(entry!)) != id!) {\n            throw PQ_QUORUM_THROW_KEY_ID_MISMATCH;\n        }\n",
        "        pqQuorumEntryKey(entry!);\n",
        QUORUM_TOL,
    ),
    (
        "tol-entry-shape",
        TOL_LIB,
        "    if (entry.remainingBitsCount() != 0 || entry.remainingRefsCount() != 1) {\n        throw PQ_QUORUM_THROW_INVALID_CONFIG;\n    }\n",
        "",
        QUORUM_TOL,
    ),
    ("tol-max-quorum", TOL_LIB, "\n        || quorum > PQ_QUORUM_MAX_QUORUM", "", QUORUM_TOL),
    ("tol-quorum-reachable", TOL_LIB, " || quorum > verifierCount", "", QUORUM_TOL),
    (
        "tol-duplicate-verifier",
        TOL_LIB,
        "        throw PQ_QUORUM_THROW_DUPLICATE_VERIFIER;\n",
        "",
        QUORUM_TOL,
    ),
    ("tol-expiry", TOL_LIB, "        throw PQ_QUORUM_THROW_EXPIRED;\n", "", QUORUM_TOL),
    ("tol-hash-binds-nonce", TOL_LIB, "        .storeUint(nonce, 64)\n", "", QUORUM_TOL),
    (
        "tol-context",
        TOL_LIB,
        "0x544f532d50512d51554f52554d2d7631",
        "0x544f532d50512d51554f52554d2d7632",
        QUORUM_TOL,
    ),
]


def run_suite(suite, args):
    """Runs a suite and returns its structured outcome: tests run, failures, errors."""
    script, extra = suite
    with tempfile.TemporaryDirectory() as tmp:
        results = Path(tmp) / "results.json"
        command = [
            sys.executable,
            str(HERE / script),
            "--build",
            args.build,
            "--signer",
            args.signer,
            "--results",
            str(results),
            *extra,
        ]
        run = subprocess.run(command, capture_output=True, text=True, env=os.environ)
        if not results.exists():
            return {
                "testsRun": 0,
                "failures": [],
                "errors": ["suite did not report"],
                "log": run.stderr[-2000:],
            }
        outcome = json.loads(results.read_text())
        outcome["log"] = run.stderr[-2000:]
        return outcome


def passes(outcome):
    return outcome["testsRun"] > 0 and not outcome["failures"] and not outcome["errors"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", required=True)
    parser.add_argument("--signer", required=True)
    parser.add_argument("--case", action="append", dest="selected")
    args = parser.parse_args()

    selected = [m for m in MUTATIONS if not args.selected or m[0] in args.selected]
    suites = sorted({m[4] for m in selected})
    for suite in suites:
        baseline = run_suite(suite, args)
        if not passes(baseline):
            raise SystemExit(f"baseline of {suite[0]} {suite[1]} does not pass:\n{baseline['log']}")

    survivors, broken = [], []
    for name, path, old, new, suite in selected:
        original = path.read_text()
        if original.count(old) != 1:
            raise SystemExit(
                f"{name}: mutation text found {original.count(old)} times, expected once"
            )
        try:
            path.write_text(original.replace(old, new))
            outcome = run_suite(suite, args)
        finally:
            path.write_text(original)
        # Killed means the suite ran and an assertion failed, with no test breaking: a mutant
        # that breaks the build, the harness or a test's setup says nothing about the guard.
        if outcome["testsRun"] > 0 and outcome["failures"] and not outcome["errors"]:
            verdict = f"killed by {', '.join(t.rsplit('.', 1)[-1] for t in outcome['failures'])}"
        elif outcome["testsRun"] > 0 and not outcome["failures"] and not outcome["errors"]:
            verdict = "SURVIVED"
            survivors.append(name)
        else:
            verdict = f"BROKEN (run {outcome['testsRun']}, errors {outcome['errors']})"
            broken.append(name)
        print(f"{name}: {verdict}", flush=True)

    for suite in suites:
        if not passes(run_suite(suite, args)):
            raise SystemExit(
                f"{suite[0]} {suite[1]} no longer passes after the sources were restored"
            )
    if survivors or broken:
        raise SystemExit(f"surviving mutants: {survivors}; mutants that broke the suite: {broken}")
    print(
        f"all {len(selected)} mutants killed by assertions; sources restored; baselines pass before and after"
    )


if __name__ == "__main__":
    main()
