#!/usr/bin/env python3
"""Require native runtime failures when wallet identity/quote/expiry guards are removed.

Run in a disposable checkout. Source is restored on every exit; use a dedicated
Cargo target directory and do not run another build against that checkout.
"""

import argparse
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "tools/bonded-relayer/provider/Cargo.toml"
CASES = (
    (
        "client.rs",
        "RelayerBond::policy(&bond.init)?.repr_hash().to_hex_string() == release.policy_hash",
        "true",
        "client::tests::public_identity_binds_all_wallet_pins_without_custody",
    ),
    (
        "identity.rs",
        "relayer_quote::verify_terms(&public, terms, &signature)?;",
        "let _ = (&public, terms, &signature);",
        "client::tests::public_quote_authenticates_exact_terms_and_pinned_worker",
    ),
    (
        "prepared.rs",
        "ensure!(u64::from(expiry) > deadline,",
        "ensure!(u64::from(expiry) > 0 || deadline == 0,",
        "prepared::deadline_tests::wallet_deadline_is_read_from_exact_external_message",
    ),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()
    # These are exact unit tests; unrelated standalone integration executables
    # implement their own argument protocol and must not receive libtest filters.
    command = [
        "cargo",
        "test",
        "--bin",
        "br1-native-provider",
        "--manifest-path",
        MANIFEST,
        "--locked",
        "-j2",
    ]
    if args.release:
        command.append("--release")
    results = []
    for file, before, after, test in CASES:
        path = ROOT / "tools/bonded-relayer/provider/src" / file
        original = path.read_text()
        if original.count(before) != 1:
            raise RuntimeError("native control anchor changed: " + test)
        invocation = command + [test, "--", "--exact"]

        def run():
            return subprocess.run(
                invocation,
                cwd=ROOT,
                capture_output=True,
                text=True,
                env={**os.environ, "CARGO_TERM_COLOR": "never"},
                timeout=1800,
            )

        baseline = run()
        if baseline.returncode or "1 passed" not in baseline.stdout:
            raise RuntimeError("native baseline did not run: " + test + baseline.stderr)
        try:
            path.write_text(original.replace(before, after))
            broken = run()
            if broken.returncode == 0 or f"test {test} ... FAILED" not in broken.stdout:
                raise RuntimeError(
                    "native control did not fail at runtime: " + test + broken.stderr
                )
        finally:
            path.write_text(original)
        restored = run()
        if restored.returncode or "1 passed" not in restored.stdout:
            raise RuntimeError("native restored baseline failed: " + test + restored.stderr)
        results.append({"test": test, "baseline": 0, "mutation": broken.returncode, "restored": 0})
    print(json.dumps({"native_controls": results}, indent=2))


if __name__ == "__main__":
    main()
