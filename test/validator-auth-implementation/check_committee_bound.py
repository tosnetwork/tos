"""Require the measured committee bound and the installed one to be the same number.

The masterchain subset signs governance certificates and the cost of one is
linear in it, so the size the genesis installs decides whether a governance
operation fits a block -- under a post-quantum suite it decides it by a factor
of five. The capacity bound measures exactly that, at a size it holds as a
constant.

Two places therefore state one fact. If they drift, the measurement keeps
passing against a committee the network does not have, which is the only way the
bound can be wrong while everything is green. So this compares them, and the
capacity bound does the rest: raise the installed size past what a post-quantum
certificate can carry and its own case fails.

Raising it is not hypothetical. The counts are configuration parameter 16, which
a governance operation may change; what cannot be changed later is the same
parameter under a post-quantum suite, because the operation that lowers it needs
a certificate of the size being lowered.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENESIS = ROOT / "crypto/smartcont/gen-zerostate.fif"
BOUND = ROOT / "test/validator-auth-implementation/governance-capacity-test.cpp"

GENESIS_COUNTS = re.compile(r"^(\d+) (\d+) (\d+) config\.validator_num!$", re.MULTILINE)
MEASURED = re.compile(
    r"^constexpr unsigned installed_main_validators = (\d+), profile_ceiling = (\d+);$", re.MULTILINE
)


def main() -> int:
    genesis = GENESIS_COUNTS.search(GENESIS.read_text())
    if genesis is None:
        print("FAIL: the genesis does not state the validator counts", file=sys.stderr)
        return 1
    installed = MEASURED.search(BOUND.read_text())
    if installed is None:
        print("FAIL: the capacity bound does not state the size it measures", file=sys.stderr)
        return 1

    max_validators, max_main, _ = (int(value) for value in genesis.groups())
    measured_main, measured_ceiling = (int(value) for value in installed.groups())
    failures = []
    if measured_main != max_main:
        failures.append(
            f"the genesis installs {max_main} masterchain validators and the capacity bound "
            f"measures {measured_main}"
        )
    if measured_ceiling != max_validators:
        failures.append(
            f"the genesis admits {max_validators} elected validators and the capacity bound "
            f"measures a ceiling of {measured_ceiling}"
        )
    for failure in failures:
        print("FAIL:", failure, file=sys.stderr)
    if failures:
        return 1
    print(
        f"PASS: the committee measured is the committee installed, {max_main} of {max_validators}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
