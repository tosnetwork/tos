#!/usr/bin/env python3
"""Build/run work-budget checks and prove sensitivity to missing work debit.

Run without concurrent builds or edits of the budget header. Logs remain outside
Git in the required output directory; the original source is always restored.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    build = args.build_dir.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    header = root / 'validator/impl/ext-message-work-budget.hpp'
    original = header.read_bytes()
    anchor = b'    available_ -= quote;'
    if original.count(anchor) != 1:
        raise RuntimeError('expected exactly one debit mutation anchor')
    results = {}

    def run(name, command):
        with (output / (name + '.log')).open('wb') as log:
            result = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT)
        results[name] = result.returncode
        return result.returncode

    def build_and_test(name):
        if run(name + '-build', ['cmake', '--build', str(build), '--target',
                                'test-ext-message-admission-budget', '-j', '2']):
            raise RuntimeError(name + ' build failed')
        return run(name, [str(build / 'test-ext-message-admission-budget')])

    if build_and_test('baseline'):
        raise RuntimeError('baseline failed')
    try:
        header.write_bytes(original.replace(anchor, b'    // Controlled deletion of work debit.'))
        if build_and_test('missing-debit') == 0:
            raise RuntimeError('missing debit unexpectedly passed')
        failure = (output / 'missing-debit.log').read_text(errors='replace')
        if 'ChargesEveryAttemptUntilTimedRefill' not in failure or 'available' not in failure:
            raise RuntimeError('mutation did not fail at the work accounting assertion')
    finally:
        header.write_bytes(original)
        if build_and_test('restored'):
            raise RuntimeError('restored tests failed')
        files = {}
        for path in sorted(output.glob('*.log')):
            data = path.read_bytes()
            files[path.name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        (output / 'results.json').write_text(json.dumps({
            'source_sha256': hashlib.sha256(original).hexdigest(),
            'returncodes': results, 'logs': files,
            'scope': 'token bucket only; not pool dispatch or VM execution counts',
        }, indent=2) + '\n')


if __name__ == '__main__':
    main()
