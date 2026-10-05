"""Require AUTH SDK tests to fail semantically after independent binding guard deletions."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tosctl/src/node-control/contracts/src/wallet_v5r2.rs"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--pop", action="store_true")
    modes.add_argument("--prepare", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source_path = SOURCE.with_name("wallet_v5r2_pop.rs") if args.pop else SOURCE
    module = "wallet_v5r2_pop" if args.pop else "wallet_v5r2"
    if args.prepare:
        source_path = SOURCE.with_name("wallet_v5r2_prepare.rs")
        module = "wallet_v5r2_prepare"
    source = source_path.read_text()
    cases = [
        ("parties", "binding.account != binding.module", "true", "wallet_cannot_be_its_own_module"),
        (
            "primary_authority",
            "role != AuthRole::Primary || kind == 0",
            "true",
            "primary_cannot_change_authority",
        ),
        ("ttl", "(1..=3600).contains(&ttl)", "true", "deadline_and_signature_framing_are_strict"),
        (
            "signature_width",
            "signature.len() == role.signature_bytes()",
            "true",
            "deadline_and_signature_framing_are_strict",
        ),
        (
            "domain",
            'domain.append_raw(b"TOS-AUTH", 64)?;',
            'domain.append_raw(b"BAD-AUTH", 64)?;',
            "independent_python_wire_vectors",
        ),
    ]

    if args.pop:
        cases = [
            (
                "challenge",
                "binding.challenge != [0; 32]",
                "true",
                "zero_challenge_and_equal_parties_refused",
            ),
            (
                "parties",
                "binding.account != binding.module",
                "true",
                "zero_challenge_and_equal_parties_refused",
            ),
            ("ttl", "(1..=3600).contains(&ttl)", "true", "pop_deadline_boundaries"),
            (
                "domain",
                'domain.append_raw(b"TOS-POP1", 64)?;',
                'domain.append_raw(b"BAD-POP1", 64)?;',
                "independent_pop_vectors",
            ),
            (
                "context",
                'b"TOS-RESCUE-POP-v1"\n',
                'b"BAD-RESCUE-POP-v1"\n',
                "independent_pop_vectors",
            ),
        ]

    if args.prepare:
        cases = [
            (
                "parties",
                "binding.wallet != binding.source_module",
                "true",
                "distinct_parties_and_deadline",
            ),
            ("ttl", "(1..=3600).contains(&ttl)", "true", "distinct_parties_and_deadline"),
            (
                "amount",
                "plan.module_amount > 0 && plan.vault_amount > 0",
                "true",
                "amount_encoding_has_no_truncation_or_zero_deployment",
            ),
            (
                "context",
                'b"TOS-RESCUE-FEE-PREP-v1"\n',
                'b"BAD-RESCUE-FEE-PREP-v1"\n',
                "independent_preparation_vectors",
            ),
            (
                "witness",
                "targets.checked_append_reference(plan.metadata)?;",
                "targets.checked_append_reference(plan.vault_init.clone())?;",
                "independent_preparation_vectors",
            ),
            (
                "sum",
                ".checked_add(plan.vault_amount)",
                ".checked_sub(plan.vault_amount)",
                "independent_preparation_vectors",
            ),
        ]

    def test(label):
        result = subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "--locked",
                "-p",
                "contracts",
                "--lib",
                module + "::tests",
            ],
            capture_output=True,
            text=True,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    results = {}
    try:
        code, _ = test("baseline")
        assert code == 0
        for name, old, new, witness in cases:
            assert source.count(old) == 1
            source_path.write_text(source.replace(old, new))
            code, log = test(name)
            assert code != 0 and f"{module}::tests::{witness} ... FAILED" in log, log[-3000:]
            results[name] = {"exit": code, "semantic_witness": witness}
    finally:
        source_path.write_text(source)
        code, log = test("restored")
        assert code == 0, log[-3000:]
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(cases)} {module} SDK semantic deletion controls detected; restored tests pass")


if __name__ == "__main__":
    main()
