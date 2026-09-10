#!/usr/bin/env python3
"""Expire prepared local decisions when either real validator refusal changes.

This source-lifecycle guard is not evidence of runtime gate reachability.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


def check(source):
    failures = []
    refusal = re.compile(
        r'\s*return\s+td::Status::Error\(\s*static_cast<int>\('
        r'block::WorkchainExecutionFailure::LocalUnavailable\)\s*,\s*'
        r'"multi-account admission and replay are not connected"\s*\)\s*;\s*')
    for name, end, identity in [
        ('custom', '}), *resolved_execution.ok());', 1350),
        ('ready', '}), *execution_res.ok());', 1351),
    ]:
        start = f'auto {name} = std::visit(td::overloaded('
        # Scope each check to its own visitor and AccountBinding lambda. A
        # refusal in another branch or a comment cannot satisfy this check.
        if source.count(start) != 1:
            failures.append(identity)
            continue
        begin = source.index(start)
        finish = source.find(end, begin)
        region = source[begin:finish + len(end)] if finish >= 0 else ''
        bodies = re.findall(
            r'\[\]\(const block::ResolvedWorkchainAccountBinding&\)'
            r'(?:\s*->\s*td::Result<bool>)?\s*\{([^{}]*)\}', region)
        if len(bodies) != 1 or refusal.fullmatch(bodies[0]) is None:
            failures.append(identity)
    return failures


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--probe', type=Path)
    p.add_argument('--fixture', type=Path)
    a = p.parse_args()
    if (a.probe is None) != (a.fixture is None):
        p.error("--probe and --fixture must be supplied together")
    try:
        source = (a.repo / 'validator/impl/validate-query.cpp').read_text()
    except OSError as error:
        print(json.dumps({'failure_identity': 1352, 'detail': str(error)}), file=sys.stderr)
        return 1
    failures = check(source)
    for identity in failures:
        print(json.dumps({'failure_identity': identity,
                          'detail': 'Prepared decisions expired: remove the prepared file and retarget controls to production call sites.'}), file=sys.stderr)
    if failures:
        return 1
    print('Prepared expiry guard passed: both production account refusals remain.', flush=True)
    # The default CTest is a source-only expiry check. It has no optional
    # native fixture dependency; the opt-in test additionally runs the probe.
    if a.probe is None:
        return 0
    # Missing binary/fixture is a failure, never a skip. Do not synthesize a
    # successful private run merely because the source guard passed.
    return subprocess.run([str(a.probe), str(a.fixture)]).returncode


if __name__ == '__main__':
    sys.exit(main())
