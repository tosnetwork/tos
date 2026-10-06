"""Require semantic failures for Rust signer wiping, rejection and enrollment binding."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    wrapper = ROOT / "tosctl/src/wallet-pq-signer/src/lib.rs"
    state = ROOT / "tosctl/src/node-control/contracts/src/wallet_v5r2_wallet_state.rs"
    pop = ROOT / "tosctl/src/node-control/contracts/src/wallet_v5r2_pop.rs"
    sources = {path: path.read_text() for path in (wrapper, state, pop)}
    commands = {
        wrapper: ["-p", "wallet-pq-signer", "--lib"],
        state: [
            "-p",
            "contracts",
            "--features",
            "native-wallet-signer",
            "--lib",
            "fee_state_tests",
        ],
    }
    commands[pop] = [
        "-p",
        "contracts",
        "--features",
        "native-wallet-signer",
        "--lib",
        "native_pop_signing_binds_initial_and_successor_enrollment",
    ]
    cases = [
        (
            "pop_enrollment",
            pop,
            'expected.cell.repr_hash() == self.cell.repr_hash(),\n            "POP enrollment binding mismatch"',
            'true,\n            "POP enrollment binding mismatch"',
            "native_pop_signing_binds_initial_and_successor_enrollment",
        ),
        (
            "pop_domain",
            pop,
            "wallet_pq_signer::Purpose::Pop",
            "wallet_pq_signer::Purpose::Auth",
            "native_pop_signing_binds_initial_and_successor_enrollment",
        ),
        (
            "pop_key",
            pop,
            "signer.sign_bound(role, &key,",
            "signer.sign_bound(role, &signer.public_key().to_vec(),",
            "native_pop_signing_binds_initial_and_successor_enrollment",
        ),
        ("seed_wipe", wrapper, "self.0.zeroize();", "", "import_wipes_on_success_and_failure"),
        (
            "failure_status",
            wrapper,
            "if status != 1 {\n            return Err(Rejected);\n        }\n        Ok(output)",
            "if false {\n            return Err(Rejected);\n        }\n        Ok(output)",
            "bound_signatures_and_independent_primary_verification",
        ),
        (
            "proven_key",
            state,
            "signer.sign_bound(role, key, wallet_pq_signer::Purpose::Auth, request.digest())?",
            "signer.sign_bound(role, &signer.public_key().to_vec(), wallet_pq_signer::Purpose::Auth, request.digest())?",
            "native_wallet_signing_binds_proven_keys_and_policy",
        ),
    ]

    cases.extend(
        [
            (
                "challenge_rng_status",
                wrapper,
                "status != 1 || challenge == [0; 32]",
                "challenge == [0; 32]",
                "challenge_rng_failures_are_rejected",
            ),
            (
                "challenge_nonzero",
                wrapper,
                "status != 1 || challenge == [0; 32]",
                "status != 1",
                "challenge_rng_failures_are_rejected",
            ),
            (
                "fresh_challenge",
                pop,
                "wallet_pq_signer::fresh_pop_challenge()?",
                "[7; 32]",
                "native_pop_signing_binds_initial_and_successor_enrollment",
            ),
        ]
    )
    preparation_witness = "native_preparation_signing_binds_successor_and_current_rescue"
    for name, old, new in [
        ("preparation_wallet", "successor.wallet() == &self.wallet", "true"),
        (
            "preparation_module_code",
            "module_code.repr_hash().as_array() == &self.module_code",
            "true",
        ),
        ("preparation_vault_code", "vault_code.repr_hash().as_array() == &self.vault_code", "true"),
        ("preparation_namespace", "global_id == self.global_id && network == self.network", "true"),
        (
            "preparation_domain",
            "wallet_pq_signer::Purpose::Preparation",
            "wallet_pq_signer::Purpose::Auth",
        ),
        (
            "preparation_key",
            "&self.rescue_key,\n            wallet_pq_signer::Purpose::Preparation",
            "&signer.public_key().to_vec(),\n            wallet_pq_signer::Purpose::Preparation",
        ),
        (
            "preparation_ready_policy",
            '1 => self.require_global_primary(\n                policy_source\n                    .ok_or_else(|| anyhow::anyhow!("successor READY requires proven policy"))?,\n                now,\n            )?',
            "1 => ()",
        ),
    ]:
        cases.append((name, state, old, new, preparation_witness))

    # Validate every target before any expensive test or temporary mutation.
    for name, path, old, _, _ in cases:
        expected = 2 if name == "fresh_challenge" else 1
        actual = sources[path].count(old)
        assert actual == expected, (name, str(path), expected, actual)

    def run(path, label):
        command = [
            "cargo",
            "test",
            "--manifest-path",
            str(ROOT / "tosctl/src/Cargo.toml"),
            "--locked",
            *commands[path],
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    results = {}
    try:
        for index, path in enumerate(sources):
            code, log = run(path, f"baseline-{index}")
            assert code == 0, log[-3000:]
        for name, path, old, new, witness in cases:
            path.write_text(sources[path].replace(old, new))
            code, log = run(path, name)
            assert code != 0 and f"{witness} ... FAILED" in log, log[-3000:]
            results[name] = {"exit": code, "witness": witness}
            path.write_text(sources[path])
    finally:
        for path, source in sources.items():
            path.write_text(source)
        for index, path in enumerate(sources):
            code, log = run(path, f"restored-{index}")
            assert code == 0, log[-3000:]
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(cases)} Rust signer controls detected; restored tests pass")


if __name__ == "__main__":
    main()
