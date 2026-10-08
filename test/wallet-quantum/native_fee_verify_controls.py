"""Require native fee cryptography and journal export verification to fail when removed."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NATIVE_TEST = "fee_verifier_binds_reserved_leaf_digest_key_and_signature"
CACHE_TEST = "native_fee_verification_guards_backend_cache_and_retry"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    native = ROOT / "crypto/pq/wallet-lms-fee-c.cpp"
    cache = ROOT / "tosctl/src/node-control/contracts/src/lms_fee_cache.rs"
    originals = {p: p.read_text() for p in (native, cache)}
    crypto = (
        originals[native][originals[native].index("  return tos::pq::verify_lms_fee") :].split(
            ";", 1
        )[0]
        + ";"
    )
    export = """        wallet_pq_signer::fee::verify_reserved_signature(
            public_key,
            leaf,
            &intent_hash,
            &signature,
        )?;"""
    cases = [
        (
            "reserved_leaf",
            native,
            "encoded_leaf != leaf",
            "false",
            "wallet-pq-signer",
            NATIVE_TEST,
            "fee verifier ignored reserved leaf",
        ),
        (
            "cryptography",
            native,
            crypto,
            "  return 1;",
            "wallet-pq-signer",
            NATIVE_TEST,
            "fee verifier accepted wrong digest",
        ),
        (
            "backend_verification",
            cache,
            ".is_ok())\n            },",
            ".is_ok() || true)\n            },",
            "contracts",
            CACHE_TEST,
            "invalid backend wrote signature cache",
        ),
        (
            "export_verification",
            cache,
            export,
            "",
            "contracts",
            CACHE_TEST,
            "native cache ignored enrolled key",
        ),
    ]
    for name, path, old, _, _, _, _ in cases:
        assert originals[path].count(old) == 1, name

    def run(label, package, test):
        command = [
            "cargo",
            "test",
            "--manifest-path",
            str(ROOT / "tosctl/src/Cargo.toml"),
            "--locked",
            "-p",
            package,
            "--lib",
            test,
        ]
        if package == "contracts":
            command += ["--features", "native-wallet-signer"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=1200)
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    def positives(label):
        for package, test in [("wallet-pq-signer", NATIVE_TEST), ("contracts", CACHE_TEST)]:
            code, log = run(label + "-" + package, package, test)
            assert code == 0 and "1 passed; 0 failed" in log and f"::{test} ... ok" in log, log[
                -4000:
            ]

    results = {}
    try:
        positives("baseline")
        for name, path, old, new, package, test, witness in cases:
            path.write_text(originals[path].replace(old, new))
            code, log = run(name, package, test)
            assert (
                code != 0
                and "test result: FAILED" in log
                and f"::{test} ... FAILED" in log
                and witness in log
            ), log[-4000:]
            results[name] = {"exit": code, "semantic_witness": witness}
            path.write_text(originals[path])
    finally:
        for path, content in originals.items():
            path.write_text(content)
        positives("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("4 native fee verification controls detected; restored tests pass")


if __name__ == "__main__":
    main()
