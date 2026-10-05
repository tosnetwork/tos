"""Semantic guard controls for proven configuration and PRIMARY retirement gating."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "tosctl/src/node-control/contracts/src"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    files = {
        name: (BASE / name).read_text()
        for name in ["proven_getters.rs", "wallet_v5r2_policy.rs", "wallet_v5r2_wallet_state.rs"]
    }
    config_test = "config_response_cells_are_bound_to_requested_indices_and_hashes"
    policy_test = "primary_policy_strict_retirement"
    request_test = "primary_request_requires_current_proven_policy"
    cases = [
        (
            "count",
            "proven_getters.rs",
            "params.len() == expected.len()",
            "true",
            config_test,
            "accepted missing config output",
        ),
        (
            "index",
            "proven_getters.rs",
            "param.index == *index",
            "true",
            config_test,
            "accepted wrong config index",
        ),
        (
            "hash",
            "proven_getters.rs",
            "cell.repr_hash().to_hex_string() == param.cell_hash",
            "true",
            config_test,
            "accepted wrong config hash",
        ),
        (
            "network",
            "wallet_v5r2_policy.rs",
            "s.get_next_hash()?.as_array() == network",
            "{ s.get_next_hash()?; true }",
            policy_test,
            "accepted invalid primary policy: network",
        ),
        (
            "bits",
            "wallet_v5r2_policy.rs",
            "retired & !2 == 0",
            "true",
            policy_test,
            "accepted invalid primary policy: unknown retirement bits",
        ),
        (
            "spec",
            "wallet_v5r2_policy.rs",
            's.get_next_hash()?.to_hex_string()\n            == "5e4380aedc95f8cb72de55f7506de0269b47c03ad1d1ed0e5184c332544262c0"',
            "{ s.get_next_hash()?; true }",
            policy_test,
            "accepted invalid primary policy: specification",
        ),
        (
            "schedule",
            "wallet_v5r2_policy.rs",
            "!seen && key.get_next_byte()? == 1",
            "{ key.get_next_byte()?; true }",
            policy_test,
            "accepted invalid primary policy: unsupported",
        ),
        (
            "deadline",
            "wallet_v5r2_policy.rs",
            "deadline > 0",
            "true",
            policy_test,
            "accepted invalid primary policy: zero retirement deadline",
        ),
        (
            "retired",
            "wallet_v5r2_policy.rs",
            "retired & 2 == 0 && (deadline == 0 || now < deadline)",
            "true",
            policy_test,
            "accepted invalid primary policy: retired",
        ),
        (
            "local",
            "wallet_v5r2_wallet_state.rs",
            "self.primary_locally_enabled()",
            "true",
            request_test,
            "accepted REQUIRED primary",
        ),
        (
            "checkpoint",
            "wallet_v5r2_wallet_state.rs",
            "policy_source.evidence().checkpoint == self.checkpoint\n                && policy_source.evidence().block_gen_utime == self.master_time",
            "true",
            request_test,
            "accepted policy at another checkpoint",
        ),
        (
            "counter",
            "wallet_v5r2_wallet_state.rs",
            "self.primary_nonce < u64::MAX && self.seqno < u32::MAX",
            "true",
            request_test,
            "accepted exhausted primary counter",
        ),
    ]

    def run(label, name):
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
                name,
            ],
            capture_output=True,
            text=True,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    results = {}
    try:
        for name in [config_test, policy_test, request_test]:
            code, log = run("baseline-" + name, name)
            assert code == 0 and "1 passed" in log, log[-3000:]
        for label, file, old, new, test, reason in cases:
            for name, source in files.items():
                (BASE / name).write_text(source)
            assert files[file].count(old) == 1, label
            (BASE / file).write_text(files[file].replace(old, new))
            code, log = run(label, test)
            assert code != 0 and " ... FAILED" in log and reason in log, log[-3000:]
            results[label] = {"exit": code, "semantic_failure": reason}
    finally:
        for name, source in files.items():
            (BASE / name).write_text(source)
        for name in [config_test, policy_test, request_test]:
            code, log = run("restored-" + name, name)
            assert code == 0 and "1 passed" in log, log[-3000:]
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("12 configuration/PRIMARY controls detected; restored tests pass")


if __name__ == "__main__":
    main()
