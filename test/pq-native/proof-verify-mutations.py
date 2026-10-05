#!/usr/bin/env python3
"""Sensitivity controls for test-proof-verify.

Each mutation removes one verification check from the production sources,
rebuilds test-proof-verify, and runs the cases that exercise that check. A case
must turn red (FAIL) under its mutation; the line records whether the mutated
verifier then accepted the input or refused it for another reason. Sources are
restored after every mutation, and the full suite must be green at the end.

usage: proof-verify-mutations.py --build-dir BUILD [--only NAME]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VERIFY = "lite-client/proof-verify/proof-verify.cpp"
CHECK = "crypto/block/check-proof.cpp"
SIGNATURES = "crypto/block/signature-set.cpp"

UNKNOWN = 'return td::Status::Error("pq signatures: unknown validator_id");'
QUORUM = "if (weight < tos::quorum_threshold(vset->get_total_weight())) {"
ROLE_MESSAGE = (
    "TRY_RESULT(message, build_simplex_data_to_sign(session_id_, slot_, candidate_, final_, block_id));\n"
    "    TRY_RESULT(weight, get_weight(vset));"
)
ROLE_VERIFY = (
    "      const auto result = tos::pq::verify_mldsa44(\n"
    "          std::string_view(message.data(), message.size()), tos::pq::simplex_sign_context,\n"
    "          std::string_view(signature.signature.data(), signature.signature.size()), validator->pq_public_key);"
)

# (name, control, [(file, old, new)], [cases that must turn red])
MUTATIONS = [
    (
        "anchor-origin",
        "1, 5",
        [(VERIFY, "if (chain->from != current) {", "if (false && chain->from != current) {")],
        [
            "synthetic-real-anchor",
            "synthetic-wrong-origin",
            "real-anchor-substituted",
            "real-foreign-chain",
            "synthetic-gap-between-responses",
        ],
    ),
    (
        "forged-signature",
        "2, 4 (slot, finality role)",
        [
            (
                SIGNATURES,
                "if (result != tos::pq::VerifyResult::valid) {",
                "if (false && result != tos::pq::VerifyResult::valid) {",
            )
        ],
        ["real-forged-signature", "synthetic-wrong-slot", "synthetic-approve-role"],
    ),
    (
        "unknown-signer",
        "2",
        [(SIGNATURES, UNKNOWN, "continue;")],
        ["real-unknown-signer"],
    ),
    (
        "duplicate-signer",
        "2",
        [
            (
                SIGNATURES,
                "if (!validator_ids.insert(signature.validator_id).second) {",
                "if (false && !validator_ids.insert(signature.validator_id).second) {",
            )
        ],
        ["real-duplicate-signer"],
    ),
    (
        "quorum",
        "2",
        [(SIGNATURES, QUORUM, "if (false) {")],
        ["real-insufficient-quorum", "synthetic-insufficient-quorum"],
    ),
    (
        "membership-and-quorum",
        "3",
        [(SIGNATURES, UNKNOWN, "continue;"), (SIGNATURES, QUORUM, "if (false) {")],
        ["synthetic-wrong-validator-set", "synthetic-replacement-claims-current-set"],
    ),
    (
        "session",
        "4",
        [
            (
                SIGNATURES,
                "if (carried_session_id != context.expected_session_id) {",
                "if (false && carried_session_id != context.expected_session_id) {",
            )
        ],
        [
            "synthetic-wrong-session",
            "synthetic-wrong-network-session",
            "synthetic-wrong-config-session",
        ],
    ),
    (
        "candidate-block",
        "4",
        [
            (
                SIGNATURES,
                "if (block_id != expected_block_id) {",
                "if (false && block_id != expected_block_id) {",
            )
        ],
        ["synthetic-wrong-candidate"],
    ),
    (
        "finality-role",
        "4",
        [
            (
                SIGNATURES,
                ROLE_MESSAGE,
                ROLE_MESSAGE + "\n    TRY_RESULT(other_role, build_simplex_data_to_sign("
                "session_id_, slot_, candidate_, !final_, block_id));",
            ),
            (
                SIGNATURES,
                ROLE_VERIFY,
                ROLE_VERIFY.replace("const auto result", "auto result")
                + "\n      if (result != tos::pq::VerifyResult::valid) {\n"
                "        result = tos::pq::verify_mldsa44(std::string_view(other_role.data(), other_role.size()),\n"
                "            tos::pq::simplex_sign_context,\n"
                "            std::string_view(signature.signature.data(), signature.signature.size()),\n"
                "            validator->pq_public_key);\n      }",
            ),
        ],
        ["synthetic-approve-role"],
    ),
    (
        "post-quantum-carrier",
        "4",
        [
            (
                VERIFY,
                "if (link.sig_set.is_null() || !link.sig_set->is_pq()) {",
                "if (link.sig_set.is_null()) {",
            )
        ],
        ["real-classic-carrier"],
    ),
    (
        "link-continuity",
        "5",
        [(CHECK, "if (link.from != cur) {", "if (false && link.from != cur) {")],
        ["real-missing-link", "real-reordered-links", "synthetic-missing-link"],
    ),
    (
        "exact-target",
        "5",
        [
            (
                VERIFY,
                "if (last && chain->to != target) {",
                "if (false && last && chain->to != target) {",
            ),
            (VERIFY, "if (current != target || outcome.utime == 0) {", "if (outcome.utime == 0) {"),
            (CHECK, "  if (cur != to) {\n", "  if (false && cur != to) {\n"),
        ],
        ["real-truncated-chain", "real-wrong-target", "synthetic-truncated-at-key-block"],
    ),
    (
        "governing-set-from-source",
        "6",
        [
            (
                CHECK,
                "auto cfg_res = from.seqno() ? block::Config::extract_from_key_block(vs_root, "
                "block::ConfigInfo::needValidatorSet)",
                "auto cfg_res = (is_key && to.seqno()) ? block::Config::extract_from_key_block(vd_root, "
                "block::ConfigInfo::needValidatorSet) : from.seqno() ? block::Config::extract_from_key_block(vs_root, "
                "block::ConfigInfo::needValidatorSet)",
            )
        ],
        ["synthetic-unauthenticated-replacement"],
    ),
    (
        "state-root",
        "7",
        [
            (
                CHECK,
                "if (state_hash != state_virt_root->get_hash().bits()) {",
                "if (false && state_hash != state_virt_root->get_hash().bits()) {",
            )
        ],
        ["real-config-substituted-state"],
    ),
    (
        "block-header-root",
        "7",
        [(CHECK, "if (vhash != blkid.root_hash) {", "if (false && vhash != blkid.root_hash) {")],
        ["real-config-other-block-header"],
    ),
    (
        "answered-block",
        "7",
        [(VERIFY, "if (answered != target) {", "if (false && answered != target) {")],
        ["real-config-other-block-answer"],
    ),
    (
        "rollback",
        "10",
        [
            (
                VERIFY,
                "if (target.seqno() < head.seqno()) {",
                "if (false && target.seqno() < head.seqno()) {",
            )
        ],
        ["real-live-rollback"],
    ),
    (
        "same-height-conflict",
        "10",
        [
            (
                VERIFY,
                "if (target.seqno() == head.seqno() && target != head) {",
                "if (false && target.seqno() == head.seqno() && target != head) {",
            )
        ],
        ["real-live-same-height-conflict"],
    ),
    (
        "maximum-age",
        "10",
        [
            (
                VERIFY,
                "if (age > request.max_age_seconds) {",
                "if (false && age > request.max_age_seconds) {",
            )
        ],
        ["real-live-expired"],
    ),
    (
        "future-dating",
        "10",
        [
            (
                VERIFY,
                "> policy.now + kMaxFutureSkewSeconds) {",
                "> policy.now + kMaxFutureSkewSeconds && false) {",
            )
        ],
        ["real-live-future"],
    ),
    (
        "descent",
        "10",
        [
            (
                VERIFY,
                "if (target.seqno() > head.seqno()) {",
                "if (false && target.seqno() > head.seqno()) {",
            )
        ],
        ["real-live-missing-descent", "real-live-other-head"],
    ),
]


def build(build_dir: Path) -> None:
    subprocess.run(
        ["cmake", "--build", str(build_dir), "-j48", "--target", "test-proof-verify"],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def run_case(build_dir: Path, case: str) -> str:
    result = subprocess.run(
        [str(build_dir / "test-proof-verify"), str(REPO / "test/pq-native/data"), "--case", case],
        capture_output=True,
        text=True,
    )
    for line in result.stdout.splitlines():
        if line.startswith(f"PROOF_VERIFY_CASE {case} "):
            return line
    return f"PROOF_VERIFY_CASE {case} FAIL no-output exit={result.returncode}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--only")
    args = parser.parse_args()
    build_dir = args.build_dir.resolve()
    failures = 0
    for name, control, patches, cases in MUTATIONS:
        if args.only and args.only != name:
            continue
        originals = {}
        try:
            for file, old, new in patches:
                path = REPO / file
                text = originals.setdefault(path, path.read_text())
                current = path.read_text()
                if current.count(old) < 1:
                    raise SystemExit(f"mutation {name}: target not found in {file}: {old!r}")
                path.write_text(current.replace(old, new))
            build(build_dir)
            for case in cases:
                line = run_case(build_dir, case)
                red = " FAIL " in line
                outcome = line.split(" ", 3)[3] if line.count(" ") >= 3 else line
                print(
                    f"MUTATION {name} control={control} case={case} {'RED' if red else 'GREEN'} {outcome[:220]}"
                )
                failures += 0 if red else 1
        finally:
            for path, text in originals.items():
                path.write_text(text)
    build(build_dir)
    final = subprocess.run(
        [str(build_dir / "test-proof-verify"), str(REPO / "test/pq-native/data")],
        capture_output=True,
        text=True,
    )
    summary = [
        line for line in final.stdout.splitlines() if line.startswith("PROOF_VERIFY_SUMMARY")
    ]
    print(f"RESTORED exit={final.returncode} {summary[-1] if summary else 'no summary'}")
    if final.returncode != 0:
        failures += 1
    print(f"MUTATION_SUMMARY not_red={failures}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
