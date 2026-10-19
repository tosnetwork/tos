# Usage: `check-scaffolds.py` from the tol-tester directory, with the same
# environment as tol-tester.py (TOL_EXECUTABLE, FIFT_EXECUTABLE, FIFTPATH).
#
# Every committed scaffold example is the output of `tol new`. This regenerates
# each one into a temporary directory, requires the result to match the
# committed tree file for file, and runs the generated tests with
# tol-tester.py. An edited template that was not regenerated, an edited example
# that no template produces, or a generated test that fails all exit non-zero.

import filecmp
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# (pattern, contract name, committed example directory)
SCAFFOLDS = [
    ("jetton", "Slice4JettonBehaviour", "examples/slice4/jetton-behaviour-scaffold"),
    ("nft", "Slice4NftBehaviour", "examples/slice4/nft-behaviour-scaffold"),
    ("multisig", "Slice4MultisigBehaviour", "examples/slice4/multisig-behaviour-scaffold"),
    ("auction", "AuctionScaffold", "examples/slice5/auction-scaffold"),
    ("governance", "GovernanceScaffold", "examples/slice5/governance-scaffold"),
    ("oracle", "OracleScaffold", "examples/slice5/oracle-scaffold"),
    ("payment-channel", "PaymentChannelScaffold", "examples/slice5/payment-channel-scaffold"),
]


def tree_files(root: str) -> set:
    found = set()
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            found.add(os.path.relpath(os.path.join(dirpath, name), root))
    return found


def compare_trees(generated: str, committed: str) -> list:
    problems = []
    gen_files = tree_files(generated)
    committed_files = tree_files(committed)
    for rel in sorted(gen_files - committed_files):
        problems.append("missing from the example: " + rel)
    for rel in sorted(committed_files - gen_files):
        problems.append("not produced by tol new: " + rel)
    for rel in sorted(gen_files & committed_files):
        if not filecmp.cmp(
            os.path.join(generated, rel), os.path.join(committed, rel), shallow=False
        ):
            problems.append("differs from tol new output: " + rel)
    return problems


def main() -> int:
    tol = os.environ.get("TOL_EXECUTABLE")
    if not tol:
        print("Environment variable TOL_EXECUTABLE is not set", file=sys.stderr)
        return 1
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        for pattern, name, example in SCAFFOLDS:
            out = os.path.join(tmp, pattern)
            gen = subprocess.run(
                [tol, "new", "--pattern", pattern, "--name", name, "--output", out],
                capture_output=True,
                text=True,
            )
            if gen.returncode != 0:
                print(
                    "%s: tol new exited %d\n%s" % (pattern, gen.returncode, gen.stderr),
                    file=sys.stderr,
                )
                failures += 1
                continue
            problems = compare_trees(out, os.path.join(ROOT, example))
            for problem in problems:
                print("%s: %s" % (example, problem), file=sys.stderr)
            if problems:
                failures += 1
            tests = subprocess.run(
                # tol-tester.py places its artifacts by the tests path, so pass it relative.
                [sys.executable, os.path.join(HERE, "tol-tester.py"), "tests"],
                cwd=out,
                capture_output=True,
                text=True,
            )
            if tests.returncode != 0:
                print(
                    "%s: generated tests failed\n%s%s" % (pattern, tests.stdout, tests.stderr),
                    file=sys.stderr,
                )
                failures += 1
                continue
            # tol-tester.py succeeds on an empty directory; a pass must have run something.
            found = re.search(r"Found (\d+) tests", tests.stderr)
            if found is None or int(found.group(1)) == 0:
                print("%s: no generated tests ran\n%s" % (pattern, tests.stderr), file=sys.stderr)
                failures += 1
                continue
            print("%s: matches %s, generated tests pass" % (pattern, example))
    if failures:
        print("%d scaffold check(s) failed" % failures, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
