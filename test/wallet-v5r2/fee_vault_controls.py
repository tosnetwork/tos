"""Require encrypted fee custody to bind enrollment and preserve reservation gates."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST = "fee_vault_restore_binds_reopens_and_never_overwrites"
INTEGRATION = "native_fee_signing_preserves_proof_reservation_and_seed_cleanup"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = ROOT / "tosctl/src/node-control/contracts/src/lms_fee_vault.rs"
    original = source.read_text()
    cases = [
        (
            "prestore_binding",
            "        verify_seed_and_wipe(seed.0, key, leaf, path)?;",
            "",
            TEST,
            "fee restore persisted wrong seed",
        ),
        (
            "load_binding",
            "    verify_seed_and_wipe(&mut locked, key, leaf, path)?;",
            "",
            TEST,
            "fee vault loaded wrong enrollment",
        ),
        (
            "record_profile",
            "meta.get_tag(PROFILE_TAG) != Some(PROFILE)",
            "false",
            TEST,
            "fee vault accepted untagged record",
        ),
        (
            "new_only",
            "vault.put(&secret, StoreMode::NewOnly).await.map_err(|_| Rejected)?;",
            "vault.put(&secret, StoreMode::CreateOrReplace).await.map_err(|_| Rejected)?;",
            TEST,
            "fee restore overwrote enrolled record",
        ),
        (
            "unpolled_wipe",
            "    let seed = Wipe(seed);\n    async move {",
            "    async move {\n        let seed = Wipe(seed);",
            TEST,
            "unpolled fee restore retained seed",
        ),
        (
            "fresh_clock",
            "        let plan = self.preview_proven(view, clock())?;",
            "        let old_now = clock();\n        let mut clock = || old_now;\n        let plan = self.preview_proven(view, clock())?;",
            INTEGRATION,
            "fee vault signed after proof expired during load",
        ),
    ]
    for name, old, _, _, _ in cases:
        assert original.count(old) == 1, name

    def run(label, test):
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
                test,
            ],
            capture_output=True,
            text=True,
            timeout=1200,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    def positive(label):
        for test in (TEST, INTEGRATION):
            code, log = run(label + "-" + test, test)
            assert code == 0 and "1 passed; 0 failed" in log and f"::{test} ... ok" in log, log[
                -4000:
            ]

    results = {}
    try:
        positive("baseline")
        for name, old, new, test, witness in cases:
            source.write_text(original.replace(old, new))
            code, log = run(name, test)
            assert (
                code != 0
                and "test result: FAILED" in log
                and f"::{test} ... FAILED" in log
                and witness in log
            ), log[-4000:]
            results[name] = {"exit": code, "semantic_witness": witness}
            source.write_text(original)
    finally:
        source.write_text(original)
        positive("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("6 encrypted fee custody controls detected; restored tests pass")


if __name__ == "__main__":
    main()
