"""Require POP enrollment, deadline and post-load clock gates for Vault custody."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST = "vault_pop_signing_binds_enrollment_and_time"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    vault = ROOT / "tosctl/src/node-control/contracts/src/wallet_v5r2_vault.rs"
    pop = ROOT / "tosctl/src/node-control/contracts/src/wallet_v5r2_pop.rs"
    originals = {path: path.read_text() for path in (vault, pop)}
    cases = [
        (
            "enrollment",
            pop,
            'expected.cell.repr_hash() == self.cell.repr_hash(),\n            "POP enrollment binding mismatch"',
            'true,\n            "POP enrollment binding mismatch"',
            "initial POP opened custody before enrollment validation",
        ),
        (
            "deadline",
            pop,
            "(1..=3600).contains(&ttl)",
            "true",
            "initial POP opened custody before deadline validation",
        ),
    ]
    for route in ("initial", "successor"):
        method = (
            originals[vault]
            .split(f"    pub async fn sign_pop_{route}(", 1)[1]
            .split("\n    }", 1)[0]
        )
        clock = "let after = checked_time(before, clock()?)?;"
        call = f"request.sign_{route}(enrollment, after, &mut signer)"
        assert method.count(clock) == 1 and method.count(call) == 1, route
        cases.extend(
            [
                (
                    f"{route}_clock",
                    vault,
                    method,
                    method.replace(clock, "let after = clock()?;"),
                    f"{route} POP accepted regressed clock after loading",
                ),
                (
                    f"{route}_recheck",
                    vault,
                    method,
                    method.replace(call, call.replace("after,", "before,")),
                    f"{route} POP accepted expired request after loading",
                ),
            ]
        )
    for name, path, old, _, _ in cases:
        assert originals[path].count(old) == 1, name

    def run(label):
        result = subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "--locked",
                "-p",
                "contracts",
                "--features",
                "native-wallet-vault",
                "--lib",
                TEST,
            ],
            capture_output=True,
            text=True,
            timeout=1200,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    def positive(label):
        code, log = run(label)
        assert code == 0 and "1 passed; 0 failed" in log and f"::{TEST} ... ok" in log, log[-4000:]

    results = {}
    try:
        positive("baseline")
        for name, path, old, new, witness in cases:
            path.write_text(originals[path].replace(old, new))
            code, log = run(name)
            assert (
                code != 0
                and "test result: FAILED" in log
                and f"::{TEST} ... FAILED" in log
                and witness in log
            ), log[-4000:]
            results[name] = {"exit": code, "semantic_witness": witness}
            path.write_text(originals[path])
    finally:
        for path, original in originals.items():
            path.write_text(original)
        positive("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} Vault POP controls detected; restored test passes")


if __name__ == "__main__":
    main()
