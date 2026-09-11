#!/usr/bin/env python3
"""Reject test harness flags that could silently fall back to raw VM tests.

Both executables first have to pass their real public corpus. Rejections must
then be explicit assertion failures, never missing binaries, crashes or OOG.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess


def run(build: Path, vectors: Path, output: Path) -> None:
    build, vectors, output = build.resolve(), vectors.resolve(), output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    marker = output / 'cli-checks.json'
    marker.unlink(missing_ok=True)
    programs = {name: build / 'crypto/pq' / name for name in
                ('test-pq-mldsa44', 'test-pq-mldsa44-wrapper')}
    for name, program in programs.items():
        subprocess.run([str(program), str(vectors), str(output / f'cli-baseline-{name}.tsv')],
                       check=True, timeout=300)
    cases = [
        ('native-unknown-flag', 'test-pq-mldsa44', ['--cod', 'unused.boc'], 'usage: test'),
        ('wrapper-unknown-flag', 'test-pq-mldsa44-wrapper', ['--benchmak'], 'usage: test'),
        ('wrapper-cannot-execute-code', 'test-pq-mldsa44-wrapper', ['--code', 'unused.boc'],
         'compiled code requires the native VM'),
        ('native-extra-argument', 'test-pq-mldsa44', ['--code', 'unused.boc', 'extra'], 'usage: test'),
    ]
    verified = []
    for label, name, extra, error in cases:
        result = subprocess.run([str(programs[name]), str(vectors), str(output / 'cli-negative.tsv'), *extra],
                                text=True, capture_output=True, timeout=300)
        if result.returncode != 1 or 'FAIL:' not in result.stderr or error not in result.stderr:
            raise RuntimeError(f'{label}: expected explicit CLI rejection, got {result}')
        verified.append(label)
    marker.write_text(json.dumps({'schema': 1, 'status': 'passed', 'checks': verified},
                                 sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--vectors', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    run(args.build, args.vectors, args.out)
