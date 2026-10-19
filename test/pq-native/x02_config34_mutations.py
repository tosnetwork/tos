#!/usr/bin/env python3
"""Sensitivity controls for the X02 Config34 verifier tests.

Each mutation removes one check from scripts/x02_config34_proof.py or the X02
coordinator, then runs the tests that exercise it; each must fail. Sources are
restored after every mutation and the tests must pass again at the end. The coordinator's
process check pins the committed script, so it is exercised by the gate mutation only.

usage: TOS_PROOF_VERIFY=... PYTHONPATH=scripts uv run python test/pq-native/x02_config34_mutations.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PROOF = "scripts/x02_config34_proof.py"
COORDINATOR = "scripts/x02_four_node.py"
TESTS = {
    "verifier": "test/pq-native/test_x02_config34_verifier.py",
    "shape": "test/pq-native/test_x02_config34_proof.py",
    "gate": "test/pq-native/test_x02_four_node_config34_gate.py",
    "capture": "test/pq-native/test_x02_stage_a_capture.py",
}

MUTATIONS = [
    (
        "verifier-refusal-ignored",
        [
            (
                PROOF,
                'if completed.returncode != 0 or result.get("status") != "verified":',
                "if False:",
            )
        ],
        [
            ("verifier", "test_another_networks_anchor_does_not_authenticate_a_consistent_bundle"),
            ("verifier", "test_a_chain_that_does_not_start_at_the_zerostate_is_refused"),
            ("verifier", "test_a_refusal_with_exit_zero_is_still_a_refusal"),
        ],
    ),
    (
        "result-binding",
        [
            (
                PROOF,
                '        and result.get("anchor") == anchor\n'
                "        and {k: proven_target.get(k) for k in target} == target\n"
                '        and result.get("request_sha256") == hashlib.sha256(request).hexdigest(),',
                "",
            )
        ],
        [("verifier", "test_a_verified_result_for_another_request_is_a_refusal")],
    ),
    (
        "retained-parameter",
        [(PROOF, "retained.hash == cell.hash,", "True,")],
        [
            ("verifier", "test_the_retained_parameter_must_be_the_proven_cell"),
            ("capture", "test_a_retained_parameter_that_is_not_the_proven_cell_is_refused"),
        ],
    ),
    (
        "zerostate-anchor-shape",
        [(PROOF, 'and anchor["kind"] == "zerostate"', 'and anchor.get("kind") is not None')],
        [("shape", "test_only_a_full_zerostate_identity_is_an_anchor")],
    ),
    (
        "frozen-closure-verifier",
        [
            (
                COORDINATOR,
                'and hashlib.sha256(verifier.read_bytes()).hexdigest() == receipt.get("sha256"),',
                ",",
            )
        ],
        [("gate", "test_the_process_check_refuses_a_verifier_outside_the_frozen_closure")],
    ),
    (
        "material-shape",
        [(PROOF, 'set(material) == {*chain, "config.tl"}', "True")],
        [("shape", "test_material_must_be_a_contiguous_chain_and_one_configuration_proof")],
    ),
]


def run(test_file: str, name: str) -> int:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", test_file, "-k", name],
        cwd=REPO,
        capture_output=True,
        text=True,
    ).returncode


def main() -> int:
    not_red = 0
    for name, patches, cases in MUTATIONS:
        originals = {}
        try:
            for file, old, new in patches:
                path = REPO / file
                originals.setdefault(path, path.read_text())
                text = path.read_text()
                if old not in text:
                    raise SystemExit(f"mutation {name}: target not found in {file}")
                path.write_text(text.replace(old, new))
            for suite, case in cases:
                code = run(TESTS[suite], case)
                red = code != 0
                not_red += 0 if red else 1
                print(f"MUTATION {name} case={case} {'RED' if red else 'GREEN'} exit={code}")
        finally:
            for path, text in originals.items():
                path.write_text(text)
    # The old-gate test needs a commit absent from fresh clones; it is not under test here.
    final = [
        run(path, "not old_gate_accepted" if suite == "gate" else "")
        for suite, path in TESTS.items()
    ]
    print(f"RESTORED exits={final}")
    not_red += sum(1 for code in final if code != 0)
    print(f"MUTATION_SUMMARY not_red={not_red}")
    return 0 if not_red == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
