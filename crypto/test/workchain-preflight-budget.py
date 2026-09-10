#!/usr/bin/env python3
"""Explicit private host contract; never infer completion from an empty run."""
import argparse
from pathlib import Path
import subprocess

CASES = ('positive', 'block-bound', 'sticky', 'failure', 'exception',
         'reservation-failure', 'overflow', 'zero', 'allowance')
EXPECTED_COUNT = 9


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if len(CASES) != EXPECTED_COUNT or len(set(CASES)) != EXPECTED_COUNT:
        raise RuntimeError('preflight selection count changed')
    listed = subprocess.run([str(binary), '--list'], capture_output=True, text=True, timeout=5)
    if listed.returncode or listed.stderr or tuple(listed.stdout.splitlines()) != CASES:
        raise RuntimeError('preflight native dispatch/driver selection mismatch')
    for name in CASES:
        result = subprocess.run([str(binary), name], capture_output=True, text=True, timeout=5)
        print(result.stdout, end='')
        print(result.stderr, end='')
        expected = f'completed preflight host case: {name}\n'
        if result.returncode != 0 or result.stdout != expected or result.stderr:
            raise RuntimeError(f'{name}: incomplete/failed contract check, exit={result.returncode}')
    print(f'{len(CASES)} private preflight host cases completed; no production engine claim')


if __name__ == '__main__':
    main()
