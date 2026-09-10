#!/usr/bin/env python3
"""Isolated local-visitor controls; deliberately not live call-site evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    commit = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
    path = 'validator/impl/validate-query.cpp'
    original = subprocess.check_output(['git', '-C', str(repo), 'show', commit + ':' + path])
    if (repo / path).read_bytes() != original:
        raise RuntimeError('commit the reviewed source before measuring its copy')
    copy, build = out / 'source', out / 'build'
    counter = 0

    def run(name, command):
        nonlocal counter
        counter += 1
        result = subprocess.run(command, capture_output=True)
        (out / f'{counter:02d}-{name}.stdout.log').write_bytes(result.stdout)
        (out / f'{counter:02d}-{name}.stderr.log').write_bytes(result.stderr)
        return result

    def require_success(name, command):
        result = run(name, command)
        if result.returncode:
            raise RuntimeError(f'{name} failed; see complete archived logs')
        return result

    require_success('checkout', ['git', '-C', str(repo), 'worktree', 'add', '--quiet', '--detach', str(copy), commit])
    require_success('configure', ['cmake', '-S', str(copy), '-B', str(build),
        '-DCMAKE_PROJECT_TOS_INCLUDE=crypto/test/workchain-validator-local-visitors.cmake'])
    target = 'test-workchain-validator-local-visitors'
    rebuild = ['cmake', '--build', str(build), '--target', target, '-j32']
    command = [str(build / target), str(copy / 'doc/measurements/uno-local-profile/run-3/state/zerostate.boc')]
    require_success('baseline-build', rebuild)
    require_success('baseline-run', command)
    # Each source replacement is one exact visitor arm. No registry or caller
    # gate is modified; only extracted local-expression behavior is measured.
    source = original.decode()
    custom_start = source.index('          [](const block::ResolvedWorkchainAccountBinding&) -> td::Result<bool> {')
    custom_end = source.index('\n          }', custom_start) + len('\n          }')
    custom = source[custom_start:custom_end]
    ready_start = source.index('        [](const block::ResolvedWorkchainAccountBinding&) {', source.index('bool ValidateQuery::check_this_shard_mc_info()'))
    ready_end = source.index('\n        }', ready_start) + len('\n        }')
    ready = source[ready_start:ready_end]
    controls = [
        ('custom-answer', custom, custom.replace('return false;', 'return true;'), 1311),
        ('custom-refusal', custom, custom.replace('return false;', 'return td::Status::Error(-7201, "isolated local refusal");'), 1310),
        ('binding-refusal', ready, ready.replace('return td::Status::OK();', 'return td::Status::Error(-7201, "isolated local refusal");'), 1320),
    ]
    sha = lambda value: hashlib.sha256(value).hexdigest()
    report = {'source_commit': commit, 'path': path, 'original_sha256': sha(original),
              'targets': [target], 'explicit_rebuild_command': rebuild,
              'scope': 'Verbatim local visitor statements only. No ValidateQuery caller execution, no I13 or live seam acceptance.',
              'controls': []}
    for name, old, new, expected in controls:
        if old == new or source.count(old) != 1:
            raise RuntimeError('mutation preimage is absent or ambiguous')
        mutant = source.replace(old, new).encode()
        try:
            (copy / path).write_bytes(mutant)
            require_success(name + '-build', rebuild)
            result = run(name, command)
            identities = [json.loads(line)['failure_identity'] for line in result.stderr.decode().splitlines()
                          if line.startswith('{') and 'failure_identity' in json.loads(line)]
            if result.returncode != 1 or identities != [expected]:
                raise RuntimeError('wrong numerical failure identity')
        finally:
            (copy / path).write_bytes(original)
        require_success(name + '-restored-build', rebuild)
        require_success(name + '-restored-run', command)
        report['controls'].append({'name': name, 'from': old, 'to': new,
            'copy_before_sha256': sha(original), 'mutant_sha256': sha(mutant),
            'restored_sha256': sha((copy / path).read_bytes()),
            'restore_audit_sha256': sha((copy / path).read_bytes().replace(old.encode(), new.encode())),
            'failure_identity': expected, 'compile_exit': 0, 'behavior_exit': result.returncode})
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    if (repo / path).read_bytes() != original:
        raise RuntimeError('production source changed during measurement')


if __name__ == '__main__':
    main()
