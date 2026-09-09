#!/usr/bin/env python3
"""Run the explicitly built private scan target; absence is never a skip."""
import argparse
from pathlib import Path
import shlex
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--later-only', action='store_true')
    args = parser.parse_args()
    build = args.build.resolve(strict=True)
    binary = args.binary.resolve(strict=True)
    repository = Path(__file__).resolve().parents[2]
    source = (repository / 'crypto/test/test-workchain-batch-scan.cpp').resolve(strict=True)
    header = (repository / 'crypto/block/workchain-batch-scan.h').resolve(strict=True)
    if binary != build / 'test-workchain-batch-scan':
        raise RuntimeError(f'binary/build mismatch: {binary}, {build}')
    commands = subprocess.check_output(
        ['ninja', '-C', str(build), '-t', 'commands', 'test-workchain-batch-scan'], text=True)
    objects = []
    for command in commands.splitlines():
        words = shlex.split(command)
        if '-c' not in words or '-o' not in words:
            continue
        actual = Path(words[words.index('-c') + 1])
        if actual.name == source.name:
            if actual.resolve() != source:
                raise RuntimeError(f'source mismatch: {actual} != {source}')
            objects.append(words[words.index('-o') + 1])
    if len(objects) != 1:
        raise RuntimeError(f'expected one test compilation, got {objects!r}')
    deps = subprocess.check_output(['ninja', '-C', str(build), '-t', 'deps', objects[0]], text=True)
    actual_headers = {Path(line.strip()).resolve() for line in deps.splitlines()
                      if line.strip().endswith('/workchain-batch-scan.h')}
    if actual_headers != {header}:
        raise RuntimeError(f'header mismatch: {actual_headers!r} != {header}')
    # These are narrow source-selection checks, not a complete build freshness
    # attestation. The workflow explicitly builds this target before invoking it.
    command = [str(binary)] + (['--later-only'] if args.later_only else [])
    result = subprocess.run(command, capture_output=True, text=True, timeout=45)
    print(result.stdout, end='')
    print(result.stderr, end='', file=sys.stderr)
    if result.returncode != 0 or result.stdout != 'batch-scan.completed\n':
        raise RuntimeError(f'incomplete or failed scan checks: exit={result.returncode}, stdout={result.stdout!r}')


if __name__ == '__main__':
    main()
