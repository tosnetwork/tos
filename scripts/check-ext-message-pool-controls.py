#!/usr/bin/env python3
"""Prove queued admission observes current limits and counts only dispatched work.

Run after all other builds have stopped. Source mutations are restored in finally.
The optional container must contain this checkout; only the mutated source is
synchronized by this runner. The test and header are hash-checked first.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container')
    parser.add_argument('--container-source-dir', default='/checkout')
    parser.add_argument('--build-dir', required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = root / 'validator/impl/ext-message-pool.cpp'
    original = source.read_bytes()
    if args.container:
        for relative in ['test/test-ext-message-pool.cpp',
                         'validator/impl/ext-message-pool.hpp',
                         'validator/impl/ext-message-work-profile.hpp',
                         'validator/admission-work-profile.h',
                         'validator/validator.h', 'validator/validator-options.hpp']:
            actual = subprocess.check_output(['docker', 'exec', args.container, 'sha256sum',
                                              args.container_source_dir + '/' + relative], text=True).split()[0]
            expected = hashlib.sha256((root / relative).read_bytes()).hexdigest()
            if actual != expected:
                raise RuntimeError('container source mismatch: ' + relative)
    queued_test = 'QueuedRequestUsesFreshLimitsWithoutCountingDispatch'
    mutations = [
        ('stale-limits', b'  ext_msg_limits = admission_state->get_ext_msg_limits();',
         b'  // Controlled deletion of the post-wait limits refresh.', 'external message too large', queued_test),
        ('false-completion', b'  if (dispatched) {\n    ++completions_in_rate_window_;',
         b'  if (true) {\n    ++completions_in_rate_window_;', 'completions_in_rate_window_', queued_test),
        ('reset-work-on-update',
         b'    TRY_STATUS(work_admission_->update_profile(std::move(profile)));',
         b'    TRY_STATUS(work_admission_->update_profile(profile));\n'
         b'    TRY_RESULT(reset, ExtMessageWorkAdmission::create(std::move(profile)));\n'
         b'    work_admission_ = std::move(reset);',
         'external message admission work budget exhausted', 'WorkBudgetChargesFailuresAcrossPeerAndLocalSources'),
        ('disable-on-options-update', b'  opts_ = std::move(opts);',
         b'  opts_ = std::move(opts);\n  work_admission_.reset();',
         'external message admission work budget exhausted', 'WorkBudgetChargesFailuresAcrossPeerAndLocalSources'),
        ('skip-work-charge', b'    if (!work_admission_->try_consume()) {',
         b'    if (false) {', 'external message admission work budget exhausted',
         'WorkBudgetChargesFailuresAcrossPeerAndLocalSources'),
        ('skip-profile-check', b'    if (!work_profile_supported_) {',
         b'    if (false) {', 'external admission configuration is outside the work profile',
         'WorkBudgetRejectsUnmatchedConfigurationWithoutDispatch'),
    ]
    for name, anchor, _, _, _ in mutations:
        if original.count(anchor) != 1:
            raise RuntimeError(f'{name}: expected exactly one mutation anchor')
    prefix = ['docker', 'exec', args.container] if args.container else []
    results = {}

    def run(name, command):
        with (output / (name + '.log')).open('wb') as log:
            result = subprocess.run(prefix + command, cwd=root, stdout=log, stderr=subprocess.STDOUT)
        results[name] = result.returncode
        return result.returncode

    def build_and_test(name):
        if args.container:
            subprocess.run(['docker', 'cp', str(source), args.container + ':' +
                            args.container_source_dir + '/validator/impl/ext-message-pool.cpp'], check=True)
            # docker cp can truncate mtimes to whole seconds; force the build
            # system to observe every distinct mutation and the restoration.
            subprocess.run(['docker', 'exec', args.container, 'touch',
                            args.container_source_dir + '/validator/impl/ext-message-pool.cpp'], check=True)
        if run(name + '-build', ['cmake', '--build', args.build_dir, '--target',
                                'test-ext-message-pool', '-j', '2']):
            raise RuntimeError(name + ' build failed')
        return run(name, [str(Path(args.build_dir) / 'test-ext-message-pool')])

    if build_and_test('baseline'):
        raise RuntimeError('baseline failed; no mutations applied')
    try:
        for name, anchor, replacement, assertion, test_name in mutations:
            source.write_bytes(original.replace(anchor, replacement))
            if build_and_test(name) == 0:
                raise RuntimeError(name + ' unexpectedly passed')
            failure = (output / (name + '.log')).read_text(errors='replace')
            if test_name not in failure or assertion not in failure:
                raise RuntimeError(name + ' did not reach the expected assertion')
    finally:
        source.write_bytes(original)
        restored = build_and_test('restored')
        logs = {}
        for path in sorted(output.glob('*.log')):
            data = path.read_bytes()
            logs[path.name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        (output / 'results.json').write_text(json.dumps({
            'source_sha256': hashlib.sha256(original).hexdigest(),
            'returncodes': results, 'logs': logs,
            'scope': 'actual pool coroutine, shared work charge, exact config pin, and failure VM-count regression',
        }, indent=2) + '\n')
        if restored:
            raise RuntimeError('restored tests failed')


if __name__ == '__main__':
    main()
