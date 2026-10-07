"""Require PQ Vault creation to reject RNG, overwrite and persistence faults."""

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
    path = ROOT / "tosctl/src/wallet-pq-signer/src/vault.rs"
    original = path.read_text()
    store = "vault.put(&secret, StoreMode::NewOnly).await.map_err(|_| Rejected)?;"
    flush = "vault.flush().await.map_err(|_| Rejected)?;"
    cases = [
        (
            "rng_status",
            "status != 1 || locked.iter().all(|byte| *byte == 0)",
            "locked.iter().all(|byte| *byte == 0)",
            "accepted invalid seed randomness",
        ),
        (
            "rng_zero",
            "status != 1 || locked.iter().all(|byte| *byte == 0)",
            "status != 1",
            "accepted invalid seed randomness",
        ),
        (
            "overwrite",
            store,
            store.replace("NewOnly", "CreateOrReplace"),
            "overwrote existing PQ key",
        ),
        (
            "store_error",
            store,
            "let _ = vault.put(&secret, StoreMode::NewOnly).await;",
            "returned signer after store failure",
        ),
        (
            "flush_error",
            flush,
            "let _ = vault.flush().await;",
            "returned signer after flush failure",
        ),
        (
            "readback_key",
            "signer.public_key() != expected_key",
            "false",
            "returned signer after readback failure",
        ),
    ]
    for _, old, _, _ in cases:
        assert original.count(old) == 1

    def run(label):
        result = subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "--locked",
                "-p",
                "wallet-pq-signer",
                "--features",
                "vault",
                "--lib",
                "vault::creation_tests",
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
        assert code == 0 and "3 passed; 0 failed" in log, log[-5000:]

    results = {}
    try:
        positive("baseline")
        for name, old, new, witness in cases:
            path.write_text(original.replace(old, new))
            code, log = run(name)
            assert code != 0 and "test result: FAILED" in log and witness in log, log[-5000:]
            results[name] = {"exit": code, "semantic_witness": witness}
            path.write_text(original)
    finally:
        path.write_text(original)
        positive("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} Vault creation controls detected; restored tests pass")


if __name__ == "__main__":
    main()
