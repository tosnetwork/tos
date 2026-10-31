#!/usr/bin/env python3
"""Kill actual contract guards; compilation errors do not count as killed mutants."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "crypto/smartcont/relayer-bond-code.fc"
TEST = ROOT / "test/bonded-relayer/test_native.py"
MUTATIONS = (
    ("owner", "throw_unless(br::not_owner, equal_slice_bits(sender, owner));", "",
     "test_owner_authority"),
    ("canonical-initial-state", "throw_unless(br::bad_identity, hash == cell_hash(init));", "",
     "test_forged_initial_state_is_not_a_bond"),
    ("exit-delay", "throw_unless(br::too_early, now() >= after);", "",
     "test_early_exit_and_repeated_exit"),
    ("different-statements", " & (cell_hash(a) != cell_hash(b))", "",
     "test_identical_statement_is_not_equivocation"),
    ("signature", "pq_check_mldsa44(bytes, context, s.preload_ref(), key.begin_parse().preload_ref())",
     "-1", "test_invalid_evidence_signature_and_context"),
    ("same-slot", "(slot_a == slot_b) & ", "",
     "test_different_slots_are_not_equivocation"),
)


def run(path, test):
    env = dict(os.environ, RELAYER_SOURCE=str(path))
    return subprocess.run([sys.executable, str(TEST), "BondTests." + test],
                          capture_output=True, text=True, env=env, timeout=180)


def main():
    original = SOURCE.read_text()
    results = []
    for label, needle, replacement, test in MUTATIONS:
        if original.count(needle) != 1:
            raise RuntimeError(f"{label}: expected exactly one mutation anchor")
        baseline = run(SOURCE, test)
        if baseline.returncode:
            raise RuntimeError(f"{label}: baseline is not green\n{baseline.stdout}\n{baseline.stderr}")
        fd, name = tempfile.mkstemp(prefix=".br-mutant-", suffix=".fc", dir=SOURCE.parent)
        os.close(fd)
        path = Path(name)
        try:
            path.write_text(original.replace(needle, replacement, 1))
            mutant = run(path, test)
            log = mutant.stdout + mutant.stderr
            killed = mutant.returncode != 0 and "FAIL: " in log and "ERROR: " not in log
            results.append({"guard": label, "test": test, "killed_by_assertion": killed})
            if not killed:
                raise RuntimeError(f"{label}: survived or broke for the wrong reason\n{log}")
        finally:
            path.unlink(missing_ok=True)
        restored = run(SOURCE, test)
        if restored.returncode:
            raise RuntimeError(f"{label}: restored baseline failed\n{restored.stderr}")
    if SOURCE.read_text() != original:
        raise RuntimeError("mutation run changed the production source")
    print(json.dumps({"native_mutations": results}, indent=2))


if __name__ == "__main__":
    main()
