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
    controls = parser.add_mutually_exclusive_group()
    controls.add_argument('--quote-gas-bound', action='store_true')
    controls.add_argument('--precompiled-profile', action='store_true')
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    build = args.build_dir.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    header = root / ('validator/impl/ext-message-work-quote.hpp' if args.quote_gas_bound or args.precompiled_profile
                     else 'validator/impl/ext-message-work-budget.hpp')
    original = header.read_bytes()
    anchor = b'special_gas_limit + special_credit' if args.quote_gas_bound else b'    available_ -= quote;'
    replacement = b'special_gas_limit' if args.quote_gas_bound else b'    // Controlled deletion of work debit.'
    mutation = 'missing-special-credit' if args.quote_gas_bound else 'missing-debit'
    expected_test = 'IncludesSpecialAccountCreditInInitialGas' if args.quote_gas_bound else 'ChargesEveryAttemptUntilTimedRefill'
    expected_assertion = 'special.ok()' if args.quote_gas_bound else 'available'
    if args.precompiled_profile:
        anchor = b'  if (has_precompiled_contracts) {'
        replacement = b'  if (false) {'
        mutation = 'unpriced-precompiled'
        expected_test = 'RefusesUncalibratedPrecompiledProfile'
        expected_assertion = 'result.is_error()'
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
        header.write_bytes(original.replace(anchor, replacement))
        if build_and_test(mutation) == 0:
            raise RuntimeError(mutation + ' unexpectedly passed')
        failure = (output / (mutation + '.log')).read_text(errors='replace')
        if expected_test not in failure or expected_assertion not in failure:
            raise RuntimeError(mutation + ' did not fail at the expected assertion')
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
            'scope': 'token bucket / initial gas bound only; not pool dispatch, CPU calibration or VM execution counts',
        }, indent=2) + '\n')


if __name__ == '__main__':
    main()
