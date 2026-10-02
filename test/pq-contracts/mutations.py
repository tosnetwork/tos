#!/usr/bin/env python3
"""Removes each guard of the post-quantum contracts in turn and requires a test to fail.

usage: mutations.py --build <build-dir> --signer <test-pq-contracts-sign> [--case NAME]...

A guard that no test notices is either untested or unreachable; both are findings. Each
mutation edits one source file, runs the suite that covers it, and restores the file
whatever happens. A mutation whose text is not found exactly once is itself an error, so
the list cannot silently drift from the sources.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FUNC_LIB = ROOT / "crypto/smartcont/pq-quorum-signatures.fc"
TOL_LIB = ROOT / "crypto/smartcont/tol-stdlib/pq-quorum-signatures.tol"
QUORUM_FUNC = ("test_pq_quorum.py", HERE / "pq-quorum-harness.fc")
QUORUM_TOL = ("test_pq_quorum.py", HERE / "pq-quorum-harness.tol")

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
    script, harness = suite
    command = [
        sys.executable,
        str(HERE / script),
        "--build",
        args.build,
        "--signer",
        args.signer,
        "--harness",
        str(harness),
    ]
    return subprocess.run(command, capture_output=True, text=True, env=os.environ)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", required=True)
    parser.add_argument("--signer", required=True)
    parser.add_argument("--case", action="append", dest="selected")
    args = parser.parse_args()

    survivors = []
    broken = []
    for name, path, old, new, suite in MUTATIONS:
        if args.selected and name not in args.selected:
            continue
        original = path.read_text()
        if original.count(old) != 1:
            raise SystemExit(
                f"{name}: mutation text found {original.count(old)} times, expected once"
            )
        try:
            path.write_text(original.replace(old, new))
            result = run_suite(suite, args)
        finally:
            path.write_text(original)
        # A mutant only counts as killed when the suite ran and a test failed; a mutant that
        # breaks the build or the harness says nothing about the guard it removed.
        ran = "\nRan " in result.stderr
        failed = "FAILED (" in result.stderr
        if ran and failed:
            verdict = "killed"
        elif ran:
            verdict = "SURVIVED"
            survivors.append(name)
        else:
            verdict = "BROKEN (suite did not run)"
            broken.append(name)
        print(f"{name}: {verdict}", flush=True)
    if survivors or broken:
        raise SystemExit(f"surviving mutants: {survivors}; mutants that broke the suite: {broken}")
    print("every mutant killed; sources restored")


if __name__ == "__main__":
    main()
