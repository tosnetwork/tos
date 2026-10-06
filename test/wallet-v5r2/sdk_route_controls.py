"""Require dropped configured fee identities to fail native SDK cache tests.

Run exclusively: temporarily rebuilds the public fixture driver.
"""

# ruff: noqa: E402
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/wallet-v5r2"), str(ROOT / "test/auth-extensions")]
from cached_fee_fixture import signature


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--examples", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    examples = args.examples.resolve()
    assert examples.name == "examples" and examples.parent.name == "debug"
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    request = json.loads((args.fixtures / "sdk-cache/sign-input.json").read_text())
    os.environ["TOS_TEST_REQUIRE_NATIVE_FEE"] = "1"
    env = dict(os.environ, CARGO_INCREMENTAL="0", CARGO_TARGET_DIR=str(examples.parent.parent))
    path = ROOT / "tosctl/src/node-control/contracts/examples/lms_fee_cache_fixture.rs"
    original = path.read_text()
    results = {}

    def probe(label):
        try:
            signature(
                examples / "lms_fee_cache_fixture",
                out / label,
                tree=Path(request["tree"]),
                key=bytes.fromhex(request["public_key"]),
                vault=int(request["vault"], 16),
                digest=bytes.fromhex(request["digest"]),
                now=request["proven_time"],
                epoch0=request["epoch0"],
                global_id=request["global_id"],
                network=int(request["network"], 16),
                vm_version=request["vm_version"],
            )
        except AssertionError as error:
            if str(error) != "cached signer route mismatch":
                raise
            results[label] = dict(outcome="assertion_failed", assertion=str(error))
            return False
        results[label] = dict(outcome="passed")
        return True

    def build(label):
        with (out / (label + "-build.log")).open("w") as log:
            result = subprocess.run(
                [
                    "cargo",
                    "build",
                    "--manifest-path",
                    "tosctl/src/Cargo.toml",
                    "--locked",
                    "-p",
                    "contracts",
                    "--features",
                    "native-wallet-signer",
                    "--example",
                    "lms_fee_cache_fixture",
                    "-j1",
                ],
                cwd=ROOT,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        assert result.returncode == 0, "build failure is not mutation evidence"

    assert probe("baseline")
    for label, old, new in [
        ("drop-global-id", "global_id: input.global_id,", "global_id: 42,"),
        ("drop-namespace", "hex::decode(&input.network)?", "hex::decode(fixture_network())?"),
    ]:
        assert original.count(old) == 1
        try:
            path.write_text(original.replace(old, new))
            build(label)
            assert not probe(label), "identity mutation survived"
        finally:
            path.write_text(original)
            build(label + "-restored")
        assert probe(label + "-restored")
    report = dict(
        passed=True,
        runs=results,
        restored_green=True,
        identity={name: request[name] for name in ("global_id", "network", "vm_version")},
    )
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
