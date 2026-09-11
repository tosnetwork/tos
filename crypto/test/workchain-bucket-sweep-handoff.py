#!/usr/bin/env python3
"""BUCKET-SWEEP readiness runner, not a substitute for host evidence review.

Missing real CTest contracts fail closed. Markers attest execution only; the
observation cuts and execution paths in the companion contract require review.
"""
import argparse
import json
import subprocess
import sys

TESTS = tuple('test-workchain-bucket-sweep-' + suffix for suffix in (
    'return-once', 'terminal', 'close', 'transfer', 'fee-routing',
    'sequence', 'atomicity', 'oracle-control',
))
MARKER = 'BUCKET-SWEEP_OBSERVED:'


def check(build):
    listed = subprocess.run(['ctest', '--test-dir', build, '--show-only=json-v1'],
                            text=True, capture_output=True, check=True, timeout=60)
    entries = json.loads(listed.stdout)['tests']
    registered = {entry['name']: entry for entry in entries}
    missing = [name for name in TESTS if name not in registered]
    disabled = [name for name in TESTS if name in registered and any(
        prop['name'] == 'DISABLED' and prop['value']
        for prop in registered[name].get('properties', []))]
    duplicated = [name for name in TESTS if sum(e['name'] == name for e in entries) != 1
                  and name not in missing]
    if missing or disabled or duplicated:
        print('BUCKET-SWEEP HANDOFF_NOT_READY: missing=' + repr(missing)
              + '; disabled=' + repr(disabled) + '; duplicated=' + repr(duplicated))
        return 1
    for name in TESTS:
        result = subprocess.run(
            ['ctest', '--test-dir', build, '--verbose', '--output-on-failure',
             '--no-tests=error', '-R', '^' + name + '$'],
            text=True, capture_output=True, check=True, timeout=1800)
        print(result.stdout, end='')
        print(result.stderr, end='', file=sys.stderr)
        if (MARKER + name not in result.stdout
                or 'Skipped' in result.stdout or 'Not Run' in result.stdout):
            print('BUCKET-SWEEP HANDOFF_NOT_READY: missing observation or unexecuted test: ' + name)
            return 1
    print('BUCKET-SWEEP_TESTS_EXECUTED: independent observation/source review still required')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True)
    args = parser.parse_args()
    try:
        return check(args.build)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print('BUCKET-SWEEP HANDOFF_NOT_READY: tool/test error: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
