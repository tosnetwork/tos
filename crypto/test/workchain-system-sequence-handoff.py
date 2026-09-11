#!/usr/bin/env python3
"""Fail-closed handoff runner; missing host tests are NOT successful coverage.

This runner checks registration and executes named CTest contracts. It cannot
establish that their implementation observes authentic state: review the
producer/validator adapters against doc/uno-m5-sequence-handoff.md.
"""
import argparse
import json
import subprocess
import sys

TESTS = (
    'test-workchain-system-sequence-host-staged',
    'test-workchain-system-sequence-host-competing',
    'test-workchain-system-sequence-host-nonpublication',
    'test-workchain-system-sequence-host-stale-read-control',
    'test-workchain-system-sequence-host-publish-control',
    'test-workchain-system-sequence-host-oracle-control',
)


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
        print('HANDOFF_NOT_READY: missing=' + repr(missing) + '; disabled=' + repr(disabled))
        return 1
    for name in TESTS:
        result = subprocess.run(['ctest', '--test-dir', args.build, '--output-on-failure',
                                 '--no-tests=error', '-R', '^' + name + '$'],
                                text=True, capture_output=True, check=True)
        print(result.stdout, end='')
        print(result.stderr, end='', file=sys.stderr)
        if 'Skipped' in result.stdout or 'Not Run' in result.stdout:
            print('HANDOFF_NOT_READY: test did not execute: ' + name)
            return 1
    print('HANDOFF_TESTS_EXECUTED: review adapter provenance before retiring expiry inventory')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print('HANDOFF_ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)
