#!/usr/bin/env python3
"""Require a real completed private coverage run, never an empty success."""
import argparse
from pathlib import Path
import subprocess
import sys
import shlex


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if binary.name != 'test-workchain-coverage':
        raise RuntimeError(f'wrong coverage target: {binary}')
    build = binary.parent
    repository = Path(__file__).resolve().parents[2]
    source = repository / 'crypto/test/test-workchain-coverage.cpp'
    commands = subprocess.check_output(['ninja', '-C', str(build), '-t', 'commands',
                                        'test-workchain-coverage'], text=True)
    objects = []
    for line in commands.splitlines():
        words = shlex.split(line)
        if '-c' not in words or '-o' not in words:
            continue
        actual = Path(words[words.index('-c') + 1])
        if actual.name == source.name:
            if actual.resolve() != source.resolve():
                raise RuntimeError(f'wrong coverage source: {actual}')
            objects.append(words[words.index('-o') + 1])
    if len(objects) != 1:
        raise RuntimeError(f'expected one coverage compilation: {objects!r}')
    deps = subprocess.check_output(['ninja', '-C', str(build), '-t', 'deps', objects[0]], text=True)
    names = {'workchain-coverage.h', 'workchain-read-phase.h'}
    headers = {Path(line.strip()).resolve() for line in deps.splitlines()
               if Path(line.strip()).name in names}
    expected = {(repository / 'crypto/block' / name).resolve(strict=True) for name in names}
    if headers != expected:
        raise RuntimeError(f'wrong coverage headers: {headers!r}')
    # Selection evidence only: the workflow explicitly rebuilds the target;
    # mutation archives separately bind final source and binary hashes.
    for suffix, expected_output in [([], 'coverage.completed\n'), (['later'], 'coverage.later.completed\n')]:
        result = subprocess.run([str(binary)] + suffix, capture_output=True, text=True, timeout=25)
        print(result.stdout, end='')
        print(result.stderr, end='', file=sys.stderr)
        if result.returncode != 0 or result.stdout != expected_output:
            raise RuntimeError(f'incomplete coverage: exit={result.returncode}, stdout={result.stdout!r}')


if __name__ == '__main__':
    main()
