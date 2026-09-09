#!/usr/bin/env python3
"""Run the private ledger mechanism; missing dependencies are failures, not skips."""
import argparse
from pathlib import Path
import subprocess
import sys
import shlex


def check_sources(build, repository):
    # This opt-in harness uses Ninja, as do the other private I13 drivers.
    expected_source = (repository / 'crypto/test/test-workchain-execution-ledger.cpp').resolve(strict=True)
    expected_header = (repository / 'crypto/block/workchain-execution-ledger.h').resolve(strict=True)
    commands = subprocess.check_output(
        ['ninja', '-C', str(build), '-t', 'commands', 'test-workchain-execution-ledger'], text=True)
    objects = []
    for command in commands.splitlines():
        words = shlex.split(command)
        if '-c' not in words or '-o' not in words:
            continue
        source = Path(words[words.index('-c') + 1])
        if source.name != expected_source.name:
            continue
        if source.resolve() != expected_source:
            raise RuntimeError(f'ledger source provenance mismatch: {source} != {expected_source}')
        objects.append(words[words.index('-o') + 1])
    if len(objects) != 1:
        raise RuntimeError(f'ledger source provenance: expected one compiled source, got {objects!r}')
    deps = subprocess.check_output(['ninja', '-C', str(build), '-t', 'deps', objects[0]], text=True)
    headers = {Path(line.strip()).resolve() for line in deps.splitlines()
               if line.strip().endswith('/workchain-execution-ledger.h')}
    if headers != {expected_header}:
        raise RuntimeError(f'ledger header provenance mismatch: {headers!r} != {expected_header}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    build = args.build.resolve(strict=True)
    if binary != build / 'test-workchain-execution-ledger':
        raise RuntimeError(f'ledger binary provenance mismatch: {binary}, build={build}')
    check_sources(build, Path(__file__).resolve().parents[2])
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=45)
    print(result.stdout, end='')
    print(result.stderr, end='', file=sys.stderr)
    if result.returncode != 0:
        raise RuntimeError(f'ledger mechanism failed: exit={result.returncode}')
    expected = 'ledger mechanism: first/duplicate/bound/allocation and actor lifecycle passed; no live enforcement\n'
    if result.stdout != expected:
        raise RuntimeError(f'missing completed mechanism checks: stdout={result.stdout!r}')


if __name__ == '__main__':
    main()
