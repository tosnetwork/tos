"""Require public fee tree caches to bind enrollment, all nodes and exact framing."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST = "fee_tree_cache_authenticates_all_nodes_and_exact_framing"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = ROOT / "tosctl/src/wallet-pq-signer/src/fee_tree_cache.rs"
    original = source.read_text()
    cases = [
        ("magic", "&magic != MAGIC", "false", "fee cache accepted changed magic"),
        ("enrollment", "&key != expected_key", "false", "fee cache ignored enrollment"),
        (
            "profile",
            "key[..12] != [0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 3]",
            "false",
            "fee cache accepted wrong profile",
        ),
        ("unused", "nodes[..32] != [0; 32]", "false", "fee cache accepted changed unused"),
        ("root", "nodes[32..64] != key[28..]", "false", "fee cache ignored tree root"),
        (
            "parents",
            "nodes.get(start..end).ok_or(Rejected)? != digest",
            "false",
            "fee cache accepted changed parent",
        ),
        (
            "trailing",
            "input.read(&mut extra).map_err(|_| Rejected)? != 0",
            "false",
            "fee cache accepted trailing data",
        ),
        ("new_only", ".create_new(true)", ".create(true)", "fee cache overwrote destination"),
    ]
    for name, old, _, _ in cases:
        assert original.count(old) == 1, name

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
        for name, old, new, witness in cases:
            source.write_text(original.replace(old, new))
            code, log = run(name)
            assert (
                code != 0
                and "test result: FAILED" in log
                and f"::{TEST} ... FAILED" in log
                and witness in log
            ), log[-4000:]
            results[name] = {"exit": code, "semantic_witness": witness}
            source.write_text(original)
    finally:
        source.write_text(original)
        positive("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("8 public fee cache controls detected; restored test passes")


if __name__ == "__main__":
    main()
