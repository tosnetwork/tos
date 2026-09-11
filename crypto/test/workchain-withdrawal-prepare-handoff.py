#!/usr/bin/env python3
"""Fail-closed handoff runner; missing host tests are NOT successful coverage.

This runner checks registration and executes named CTest contracts. It cannot
establish that their implementation observes authentic state: review the
producer/validator adapters against doc/uno-m5-withdrawal-prepare-handoff.md.
"""
import argparse
import json
import subprocess
import sys

TESTS = tuple('test-workchain-withdrawal-prepare-' + name for name in (
    'debit', 'overflow', 'no-pending', 'record', 'cap', 'fee-admission',
    'enqueue', 'onoff', 'oracle-control',
))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True)
    args = parser.parse_args()
    listed = subprocess.run(['ctest', '--test-dir', args.build, '--show-only=json-v1'],
                            text=True, capture_output=True, check=True)
    registered = {entry['name']: entry for entry in json.loads(listed.stdout)['tests']}
    missing = [name for name in TESTS if name not in registered]
    disabled = [name for name in TESTS if name in registered and any(
        prop['name'] == 'DISABLED' and prop['value']
        for prop in registered[name].get('properties', []))]
    if missing or disabled:
        print('WITHDRAWAL-PREPARE_NOT_READY: missing=' + repr(missing) + '; disabled=' + repr(disabled))
        return 1
    for name in TESTS:
        result = subprocess.run(['ctest', '--test-dir', args.build, '--verbose', '--output-on-failure',
                                 '--no-tests=error', '-R', '^' + name + '$'],
                                text=True, capture_output=True, check=True)
        print(result.stdout, end='')
        print(result.stderr, end='', file=sys.stderr)
        if 'WITHDRAWAL-PREPARE_OBSERVED:' + name not in result.stdout:
            print('WITHDRAWAL-PREPARE_NOT_READY: observation marker absent: ' + name)
            return 1
        if 'Skipped' in result.stdout or 'Not Run' in result.stdout:
            print('WITHDRAWAL-PREPARE_NOT_READY: test did not execute: ' + name)
            return 1
    print('WITHDRAWAL-PREPARE_TESTS_EXECUTED: independent source/observation review still required')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print('WITHDRAWAL-PREPARE_ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)
