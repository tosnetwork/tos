#!/usr/bin/env python3
"""Readiness gate, NOT evidence that Withdrawal tariff admission is correct.

Observes default CTest registration and the execution result of the named host
contract. The contract itself must observe actual host admission, not a kernel
or standalone tariff helper. Missing/disabled/skipped execution fails closed.
"""
import argparse
import json
import subprocess
import sys

TEST = 'test-workchain-withdrawal-host-authenticated-fee'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True)
    args = parser.parse_args()
    listing = subprocess.run(['ctest', '--test-dir', args.build, '--show-only=json-v1'],
                             capture_output=True, text=True, check=True)
    matches = [t for t in json.loads(listing.stdout)['tests'] if t['name'] == TEST]
    if len(matches) != 1 or any(p['name'] == 'DISABLED' and p['value']
                               for p in matches[0].get('properties', [])):
        print('FEE_HANDOFF_NOT_READY: missing or disabled ' + TEST)
        return 1
    run = subprocess.run(['ctest', '--test-dir', args.build, '--output-on-failure',
                          '--no-tests=error', '-R', '^' + TEST + '$'],
                         capture_output=True, text=True)
    print(run.stdout, end='')
    print(run.stderr, end='', file=sys.stderr)
    if run.returncode or 'Skipped' in run.stdout or 'Not Run' in run.stdout:
        print('FEE_HANDOFF_NOT_READY: host contract failed or did not execute')
        return 1
    print('FEE_HOST_CONTRACT_EXECUTED: review fixture and mutation provenance')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print('FEE_HANDOFF_ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)
