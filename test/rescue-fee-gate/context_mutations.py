"""Require intended behavioral failures for version, leaf, and trusted-count mutations.

Replays retained public fixtures; never regenerates a signing key. Restores sources
and rebuilds the original binaries even when a control fails.
"""

import argparse
import json
import os
import subprocess
from pathlib import Path

from context_transactions import compare, normalized, replay_native
from probe_native_cost import run_driver

ROOT = Path(__file__).resolve().parents[2]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--artifacts", type=Path, required=True)
    p.add_argument("--target", type=Path, required=True)
    args = p.parse_args()
    out = args.artifacts / "mutations"
    out.mkdir(exist_ok=True)
    cpp = ROOT / "build/crypto/pq/test-fee-native-cost"
    rust = args.target / "debug/examples/fee-native-cost"
    rust_tx = args.target / "debug/examples/pq-tx-parity"
    env = dict(os.environ, CARGO_TARGET_DIR=str(args.target))
    mutations = [
        (
            "cpp_leaf",
            "crypto/vm/pqops.cpp",
            "if (q != static_cast<std::uint32_t>(leaf))",
            "if (false)",
            "wrong_leaf",
        ),
        (
            "cpp_version",
            "crypto/vm/pqops.h",
            "pq_lms_fee_hash_min_version = 17",
            "pq_lms_fee_hash_min_version = 16",
            "version_16",
        ),
        (
            "cpp_count",
            "crypto/block/transaction.cpp",
            "        cells += 1;",
            "        cells += 0;",
            "stats_ref",
        ),
        (
            "rust_leaf",
            "tosctl/src/vm/src/executor/pq.rs",
            "Some(q == leaf)",
            "Some(true)",
            "wrong_leaf",
        ),
        (
            "rust_version",
            "tosctl/src/vm/src/executor/pq.rs",
            "engine.block_version() < 17",
            "engine.block_version() < 16",
            "version_16",
        ),
        (
            "rust_count",
            "tosctl/src/executor/src/ordinary_transaction.rs",
            '.checked_add(1)\n                .ok_or_else(|| error!("incoming cell count overflow"))?;',
            '.checked_add(0)\n                .ok_or_else(|| error!("incoming cell count overflow"))?;',
            "stats_ref",
        ),
    ]
    baseline = {
        line.split("\t")[0]: tuple(map(int, line.split("\t")[1:]))
        for line in (args.artifacts / "cpp.tsv").read_text().splitlines()
    }
    receipts = {}

    def build(language, log):
        command = (
            ["cmake", "--build", "build", "--target", "emulator", "test-fee-native-cost", "-j", "4"]
            if language == "cpp"
            else [
                "cargo",
                "build",
                "--manifest-path",
                "tosctl/src/Cargo.toml",
                "--locked",
                "-p",
                "tos_vm",
                "-p",
                "tos_executor",
                "--example",
                "fee-native-cost",
                "--example",
                "pq-tx-parity",
            ]
        )
        with log.open("w") as f:
            subprocess.run(
                command, cwd=ROOT, env=env, stdout=f, stderr=subprocess.STDOUT, check=True
            )

    for name, relative, old, new, row in mutations:
        path = ROOT / relative
        original = path.read_text()
        assert original.count(old) == 1, (name, "mutation target count")
        language = name.split("_")[0]
        try:
            path.write_text(original.replace(old, new))
            build(language, out / f"{name}-build.log")
            if row == "stats_ref":
                if language == "cpp":
                    # A separate process loads the rebuilt dylib (no stale dlopen handle).
                    script = """import json,sys
from native import Emulator,from_boc,Cell
from context_transactions import compare, normalized, replay_native
from pathlib import Path
p=Path(sys.argv[1]); row=next(l.split('\\t') for l in (p/'transactions.tsv').read_text().splitlines() if l.startswith('stats_ref\\t'))
e=Emulator(17);e.lt=int(row[2])-1000000
print(json.dumps(normalized(e.send(Cell().uint(0,256).uint(0,64).ref(from_boc(bytes.fromhex(row[3]))),from_boc(bytes.fromhex(row[4]))))))
e.close()
"""
                    child_env = dict(
                        env,
                        PYTHONPATH=os.pathsep.join(
                            [str(ROOT / "test/auth-extensions"), str(ROOT / "test/rescue-fee-gate")]
                        ),
                    )
                    result = subprocess.run(
                        [os.environ.get("PYTHON", "python3"), "-c", script, str(args.artifacts)],
                        env=child_env,
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    actual = json.loads(result.stdout)
                else:
                    result = subprocess.run(
                        [
                            str(rust_tx),
                            str(args.artifacts / "config.boc"),
                            str(args.artifacts / "transactions.tsv"),
                            "17",
                        ],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    actual = next(
                        line.split("\t")[1:]
                        for line in result.stdout.splitlines()
                        if line.startswith("stats_ref\t")
                    )
                expected = normalized(json.loads((args.artifacts / "stats_ref.json").read_text()))
                assert actual[0] == expected[0] == "0", "must reach successful metadata writer"
                assert actual[-1] != expected[-1], "count mutation must change stored context"
            else:
                text, got = run_driver(
                    cpp if language == "cpp" else rust, args.artifacts / "opcodes.tsv"
                )
                (out / f"{name}.tsv").write_text(text)
                actual, expected = got[row], baseline[row]
                assert actual[0] == 0 and actual[2] == -1, (name, actual)
                assert actual != expected, (name, "mutation survived")
            receipts[name] = {"row": row, "expected": expected, "mutant": actual, "caught": True}
        finally:
            path.write_text(original)
            build(language, out / f"{name}-restored-build.log")
    for driver in [cpp, rust]:
        _, restored = run_driver(driver, args.artifacts / "opcodes.tsv")
        assert restored == baseline, "restored opcode mismatch"
    assert compare(args.artifacts, rust_tx) > 0
    assert replay_native(args.artifacts) > 0
    (out / "summary.json").write_text(json.dumps(receipts, indent=2) + "\n")
    print(json.dumps(receipts, indent=2))


if __name__ == "__main__":
    main()
