"""Require POP receipt guards to reject semantically wrong successful executions."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ROOT / "tosctl/src/node-control/contracts/src"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    cases = [
        (
            "funding_vault",
            "wallet_v5r2_pop.rs",
            "POP funding vault address mismatch",
            "accepted another POP funding vault",
        ),
        (
            "funding_code",
            "wallet_v5r2_pop.rs",
            "POP funding vault code mismatch",
            "accepted altered POP funding pre-state",
        ),
        ("funding_config", "wallet_v5r2_pop.rs", "", "accepted altered POP funding pre-state"),
        (
            "funding_external",
            "wallet_v5r2_pop.rs",
            "POP funding requires external input",
            "accepted internal POP funding input",
        ),
        (
            "funding_delivery",
            "proven_transactions.rs",
            "transaction did not emit expected message",
            "accepted undelivered POP funding",
        ),
        (
            "enrollment",
            "wallet_v5r2_pop.rs",
            "POP receipt enrollment binding mismatch",
            "accepted POP for another enrolled wallet",
        ),
        (
            "pre_state",
            "proven_transactions.rs",
            "transaction pre-state hash mismatch",
            "accepted substituted POP pre-state",
        ),
        (
            "code",
            "wallet_v5r2_pop.rs",
            "POP executed code or keys differ from enrollment",
            "accepted POP under other code",
        ),
        (
            "challenge",
            "wallet_v5r2_pop.rs",
            "POP challenge differs from request",
            "accepted unrelated POP challenge",
        ),
        (
            "bounced",
            "wallet_v5r2_pop.rs",
            "bounced message is not POP",
            "accepted bounced POP input",
        ),
    ]
    originals = {name: (SOURCES / name).read_text() for _, name, _, _ in cases}

    def run(label):
        p = subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "--locked",
                "-p",
                "contracts",
                "--lib",
                "receipt_pop_",
            ],
            capture_output=True,
            text=True,
        )
        log = p.stdout + p.stderr
        (args.output / f"{label}.log").write_text(log)
        return p.returncode, log

    results = {}
    try:
        code, log = run("baseline")
        assert code == 0 and "1 passed" in log, log[-3000:]
        for label, name, message, failure in cases:
            source = originals[name]
            if label == "funding_config":
                marker = "crate::wallet_v5r2_state::checked_counter(&data, &expected)?;"
                assert source.count(marker) == 1
                changed = source.replace(marker, "")
            else:
                marker = json.dumps(message)
                assert source.count(marker) == 1
                at = source.index(marker)
                start = source.rfind("anyhow::ensure!(", 0, at)
                end = source.index(");", at) + 2
                assert start >= 0
                changed = source[:start] + source[end:]
            (SOURCES / name).write_text(changed)
            code, log = run(label)
            assert code != 0 and " ... FAILED" in log and failure in log, log[-3000:]
            results[label] = {"exit": code, "semantic_failure": failure}
            (SOURCES / name).write_text(source)
    finally:
        for name, source in originals.items():
            (SOURCES / name).write_text(source)
        code, log = run("restored")
        assert code == 0 and "1 passed" in log, log[-3000:]
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(cases)} POP receipt guard controls detected; restored test passes")


if __name__ == "__main__":
    main()
