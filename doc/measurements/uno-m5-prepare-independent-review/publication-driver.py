#!/usr/bin/env python3
"""Require the isolated publication mutant to fail at the output observation.

Observation: caller-owned Native Account transaction out_msgs.
Path: NativePayoutExactFeeNonpublication with the attached publication patch.
An unmutated binary is NOT a valid input. Removing the observation while keeping
that patch must make this driver exit 1, even though the inner test exits 0.
"""
import subprocess
import sys

result = subprocess.run(
    [sys.argv[1], "--filter", "NativePayoutExactFeeNonpublication"],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
)
caught = result.returncode != 0 and b"Expectation failed: out_msgs.is_empty()" in result.stdout
print("PUBLICATION_MUTATION_CAUGHT" if caught else "EXPECTED_PUBLICATION_REJECTION_MISSING")
sys.exit(0 if caught else 1)
