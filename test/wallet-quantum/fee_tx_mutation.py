"""Prove full fee-transaction parity detects disabled LMS verification in Rust."""

import argparse
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()
    out = args.artifacts.resolve()
    env = dict(os.environ, CARGO_TARGET_DIR=str(args.target.resolve()))
    driver = args.target.resolve() / "debug/examples/pq-tx-parity"
    source = ROOT / "tosctl/src/vm/src/executor/pq.rs"
    original = source.read_text()
    needle = 'lms_fee::Outcome::Invalid => push_outcome(engine, Some(false), "LMS fee hash"),'
    assert original.count(needle) == 1
    build = [
        "cargo",
        "build",
        "--manifest-path",
        str(ROOT / "tosctl/src/Cargo.toml"),
        "--locked",
        "-p",
        "tos_executor",
        "--example",
        "pq-tx-parity",
    ]
    replay = [str(driver), str(out / "config.boc"), str(out / "scenarios.tsv"), "17", "--details"]
    expected = (out / "native.tsv").read_text().splitlines()
    assert len(expected) >= 20
    try:
        source.write_text(original.replace(needle, needle.replace("Some(false)", "Some(true)")))
        with (out / "mutation-build.log").open("w") as log:
            subprocess.run(build, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        result = subprocess.run(replay, capture_output=True, text=True, check=True)
        (out / "mutated-rust.tsv").write_text(result.stdout)
        observed = result.stdout.splitlines()
        assert len(expected) == len(observed)
        witnesses = []
        for left, right in zip(expected, observed):
            before, after = left.split("\t"), right.split("\t")
            if before[1] == "2007":
                assert after[0] == before[0] and after[1] == "0" and after[3] != "-"
                witnesses.append({"native_refusal": left, "mutated_rust_acceptance": right})
        assert witnesses, "must expose real fee acceptance after an invalid LMS signature"
        (out / "mutation.json").write_text(json.dumps(witnesses, indent=2) + "\n")
    finally:
        source.write_text(original)
        with (out / "restored-build.log").open("w") as log:
            subprocess.run(build, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    restored = subprocess.run(replay, capture_output=True, text=True, check=True)
    (out / "restored-rust.tsv").write_text(restored.stdout)
    assert restored.stdout.splitlines() == expected
    print("Disabled LMS verification changes fee refusal to acceptance; restored parity passes")


if __name__ == "__main__":
    main()
