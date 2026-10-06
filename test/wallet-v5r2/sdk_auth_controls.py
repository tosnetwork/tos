"""Require wallet SDK tests to fail semantically after independent binding guard deletions."""

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
    modes.add_argument("--fee", action="store_true")
    modes.add_argument("--genesis", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source_path = SOURCE.with_name("wallet_v5r2_pop.rs") if args.pop else SOURCE
    module = "wallet_v5r2_pop" if args.pop else "wallet_v5r2"
    if args.prepare:
        source_path = SOURCE.with_name("wallet_v5r2_prepare.rs")
        module = "wallet_v5r2_prepare"
    if args.fee:
        source_path = SOURCE.with_name("wallet_v5r2_fee.rs")
        module = "wallet_v5r2_fee"
    if args.genesis:
        source_path = SOURCE.with_name("wallet_v5r2_genesis.rs")
        module = "wallet_v5r2_genesis"
    source = source_path.read_text()
    cases = [
        ("action_gate", "validate_actions(&actions)?;", "", "strict_send_modes_before_signing"),
        ("action_ignore_errors", "mode & 2 != 0", "true", "strict_send_modes_before_signing"),
        ("action_flags", "mode & 44 == 0", "true", "strict_send_modes_before_signing"),
        ("action_value_modes", "mode & 192 != 192", "true", "strict_send_modes_before_signing"),
        ("action_count", "count < 255", "true", "strict_action_shape_and_count_before_signing"),
        (
            "action_tail",
            'slice.remaining_references() == 0, "action tail must be empty"',
            'true, "action tail must be empty"',
            "strict_action_shape_and_count_before_signing",
        ),
        (
            "action_shape",
            "slice.remaining_bits() == 40 && slice.remaining_references() == 2",
            "true",
            "strict_action_shape_and_count_before_signing",
        ),
        (
            "action_tag",
            "slice.get_next_u32()? == 0x0ec3c86d",
            "{ slice.get_next_u32()?; true }",
            "strict_action_shape_and_count_before_signing",
        ),
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

    if args.fee:
        cases = [
            (
                "primary",
                "r.get_next_byte()? == 2",
                "r.get_next_byte()? != 0",
                "primary_auth_and_class_mismatch_refused",
            ),
            (
                "class",
                "s.get_next_u32()? == tag",
                "s.get_next_u32()? != 0",
                "structural_mismatches_refused",
            ),
            (
                "shape",
                "s.remaining_bits() == 32 && s.remaining_references() == 2",
                "true",
                "structural_mismatches_refused",
            ),
            (
                "request_shape",
                "r.remaining_bits() == bits && r.remaining_references() == refs",
                "true",
                "structural_mismatches_refused",
            ),
            (
                "ttl",
                "(1..=SLOT_SECONDS).contains(&ttl)",
                "true",
                "leaf_deadline_value_and_framing_boundaries",
            ),
            ("range", "binding.leaf < LEAF_COUNT", "true", "exhausted_tree_even_at_matching_slot"),
            (
                "slot",
                "binding.leaf / LEAVES_PER_SLOT == elapsed / SLOT_SECONDS",
                "true",
                "leaf_deadline_value_and_framing_boundaries",
            ),
            ("value", "binding.value > 0", "true", "leaf_deadline_value_and_framing_boundaries"),
            ("length", "signature.len() == 2832", "true", "trailing_signature_bytes_refused"),
            (
                "leaf_binding",
                "signature[4..8] == self.binding.leaf.to_be_bytes()",
                "true",
                "leaf_deadline_value_and_framing_boundaries",
            ),
            (
                "domain",
                'b.append_raw(b"TOS-RESCUE-FEE-v1", 136)?;',
                'b.append_raw(b"BAD-RESCUE-FEE-v1", 136)?;',
                "independent_fee_vectors",
            ),
        ]

    if args.genesis:
        cases = [
            (
                "successor_parties",
                "wallet != module_hash",
                "true",
                "independent_successor_vectors",
            ),
            (
                "code_pin",
                "*code.repr_hash().as_array() == pin",
                "true",
                "wrong_code_and_fee_profile_refused",
            ),
            (
                "ordinary_code",
                "code.cell_type() == CellType::Ordinary && code.level() == 0",
                "true",
                "matching_pin_does_not_allow_exotic_code",
            ),
            (
                "fee_profile",
                "p.fee_public_key[..4] == 1u32.to_be_bytes()",
                "true",
                "wrong_code_and_fee_profile_refused",
            ),
            (
                "classic_flag",
                "wallet.append_bit_zero()?; // Classic signature entry is disabled.",
                "wallet.append_bit_one()?; // Deleted disabled-classic invariant.",
                "independent_genesis_vectors",
            ),
            (
                "classic_key",
                "wallet.append_u256(&[0; 32])?;",
                "wallet.append_u256(&[1; 32])?;",
                "independent_genesis_vectors",
            ),
            (
                "initial_epoch",
                "auth.append_u64(1)?;",
                "auth.append_u64(0)?;",
                "independent_genesis_vectors",
            ),
            (
                "paired_metadata",
                "config.checked_append_reference(metadata.clone())?;",
                "config.checked_append_reference(key.clone())?;",
                "independent_genesis_vectors",
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
