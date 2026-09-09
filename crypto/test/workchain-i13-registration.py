#!/usr/bin/env python3
"""Measure opt-in CTest registration and driver-failure propagation."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=False)
    stems = {'construction': 'workchain-construction-isolation',
             'coverage': 'workchain-i13-acceptance', 'usage': 'workchain-i13-usage-acceptance'}
    names = {'test-' + stem + '-gates' for stem in stems.values()}
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
    report = {'base_commit': commit, 'events': [], 'controls': [], 'sources': {},
              'scope': 'Opt-in CTest plumbing and private drivers only. No activation, live integration or I13e acceptance.'}
    for stem in stems.values():
        for suffix in ('.py', '.cmake'):
            rel = 'crypto/test/' + stem + suffix
            data = subprocess.check_output(['git', 'show', commit + ':' + rel], cwd=repo)
            assert (repo / rel).read_bytes() == data
            report['sources'][rel] = {'commit': commit, 'path': rel, 'blob_sha256': sha(data),
                'git_blob_oid': subprocess.check_output(['git', 'rev-parse', commit + ':' + rel], cwd=repo, text=True).strip()}
    rel = 'crypto/test/workchain_i13_paths.py'
    data = subprocess.check_output(['git', 'show', commit + ':' + rel], cwd=repo)
    assert (repo / rel).read_bytes() == data
    report['path_helper_sha256'] = sha(data)
    def save():
        (args.output / 'measurement.json').write_text(json.dumps(report, indent=2) + '\n')
    def command(label, argv):
        r = subprocess.run(list(map(str, argv)), cwd=repo, capture_output=True)
        event = {'label': label, 'argv': list(map(str, argv)), 'exit': r.returncode}
        for stream in ('stdout', 'stderr'):
            data = getattr(r, stream)
            (args.output / (label + '.' + stream + '.log')).write_bytes(data)
            event[stream + '_sha256'] = sha(data)
        report['events'].append(event)
        save()
        return r
    def config(label, include):
        r = command(label, ['cmake', '-S', repo, '-B', args.build, '-G', 'Ninja',
            '-DCMAKE_BUILD_TYPE=Release', '-DTOS_UNO_CRYPTO_PROTOTYPE_TESTS=OFF',
            '-DCMAKE_PROJECT_TOS_INCLUDE=' + include])
        assert r.returncode == 0
    def registry(label):
        r = command(label, ['ctest', '--test-dir', args.build, '--show-only=json-v1'])
        assert r.returncode == 0
        return {t['name']: t for t in json.loads(r.stdout)['tests']}
    def run_ctest(label, selection, expected):
        r = command(label, ['ctest', '--test-dir', args.build, '-T', 'Test', '--no-compress-output',
            '--output-on-failure', '-j32', '-R', selection])
        assert r.returncode == expected
        tag = (args.build / 'Testing/TAG').read_text().splitlines()[0]
        source = args.build / 'Testing' / tag / 'Test.xml'
        data = source.read_bytes()
        (args.output / (label + '.xml')).write_bytes(data)
        tests = ET.fromstring(data).findall('./Testing/Test')
        assert tests, 'empty CTest selection is not success'
        return tests
    config('default-configure', '')
    default = registry('default-registry')
    assert not names.intersection(default)
    config('opt-in-configure', str(repo / 'crypto/test/workchain-construction-isolation.cmake'))
    registered = registry('opt-in-registry')
    assert names.issubset(registered)
    assert set(registered) - set(default) == names
    report['default_count'] = len(default)
    report['opt_in_count'] = len(registered)
    for short, stem in stems.items():
        name = 'test-' + stem + '-gates'
        test = registered[name]
        props = {p['name']: p['value'] for p in test['properties']}
        assert props['TIMEOUT'] > 0 and 'workchain_i13_measurements' in props['RESOURCE_LOCK']
        assert not any(p.startswith('SKIP_') or p == 'DISABLED' for p in props)
        path = repo / 'crypto/test' / (stem + '.py')
        assert str(path) in test['command'] and '--ctest-root' in test['command']
        original = path.read_bytes()
        binding = report['sources'][str(path.relative_to(repo))]
        assert sha(original) == binding['blob_sha256']
        before = b"if __name__ == '__main__':\n    main()"
        after = b"if __name__ == '__main__':\n    raise SystemExit(113)"
        assert original.count(before) == 1
        mutant = original.replace(before, after)
        c = {'label': short, 'test': name, 'committed_source': binding,
             'from': before.decode(), 'to': after.decode(), 'offset': original.index(before),
             'original_sha256': sha(original), 'mutant_sha256': sha(mutant)}
        report['controls'].append(c)
        try:
            path.write_bytes(mutant)
            result = command(short + '-compile', [sys.executable, '-c',
                'import pathlib,sys; compile(pathlib.Path(sys.argv[1]).read_bytes(), sys.argv[1], "exec")', path])
            assert result.returncode == 0
            c['compiled'] = True
            tests = run_ctest(short + '-fails', '^' + name + '$', 8)
            assert len(tests) == 1 and tests[0].findtext('Name') == name
            assert tests[0].get('Status') == 'failed'
            values = {m.get('name'): m.findtext('Value') for m in tests[0].findall('./Results/NamedMeasurement')}
            assert values['Exit Value'] == '113'
            c['ctest_status'] = tests[0].get('Status')
            c['driver_exit'] = int(values['Exit Value'])
            c['behavior_confirmed'] = True
        finally:
            path.write_bytes(original)
            restored = path.read_bytes()
            c['restored_sha256'] = sha(restored)
            c['restore_audit_sha256'] = sha(restored.replace(before, after))
            assert restored == original and c['restore_audit_sha256'] == c['mutant_sha256']
            save()
        print('restored CTest driver:', short, flush=True)
    # Delete a fixture created by this run, not a cached file from an earlier run.
    path = repo / 'crypto/test/workchain-construction-isolation.py'
    original = path.read_bytes()
    before = b"runs('baseline', range(35), 0)"
    after = b"check_oracles(); (oracle / 'before.state').unlink(); runs('baseline', range(35), 0)"
    assert original.count(before) == 1
    mutant = original.replace(before, after)
    name = 'test-workchain-construction-isolation-gates'
    c = {'label': 'missing-current-oracle', 'test': name,
         'committed_source': report['sources'][str(path.relative_to(repo))],
         'from': before.decode(), 'to': after.decode(), 'offset': original.index(before),
         'original_sha256': sha(original), 'mutant_sha256': sha(mutant)}
    report['controls'].append(c)
    try:
        path.write_bytes(mutant)
        result = command('missing-current-oracle-compile', [sys.executable, '-c',
            'import pathlib,sys; compile(pathlib.Path(sys.argv[1]).read_bytes(), sys.argv[1], "exec")', path])
        assert result.returncode == 0
        c['compiled'] = True
        tests = run_ctest('missing-current-oracle-fails', '^' + name + '$', 8)
        assert len(tests) == 1 and tests[0].get('Status') == 'failed'
        values = {m.get('name'): m.findtext('Value') for m in tests[0].findall('./Results/NamedMeasurement')}
        assert values['Exit Value'] == '1'
        runs = list((args.build / 'workchain-i13-ctest/construction/runs').glob('run-*/evidence'))
        assert len(runs) == 1
        fixture = runs[0] / 'oracles'
        assert not (fixture / 'before.state').exists()
        assert {p.name for p in fixture.iterdir()} == {'before.messages', 'after.state', 'after.messages'}
        measurement = json.loads((runs[0] / 'measurement.json').read_text())
        assert any(e['label'] == 'freeze-oracles' and e['exit'] == 0 for e in measurement['events'])
        shutil.copytree(runs[0], args.output / 'missing-current-oracle')
        c.update({'ctest_status': 'failed', 'driver_exit': 1, 'behavior_confirmed': True,
                  'scope': 'A current-run oracle is physically deleted after all four hashes are checked. The driver fails on the missing file before executing baseline cases; this is dependency-failure propagation, not an application guard result.'})
    finally:
        path.write_bytes(original)
        restored = path.read_bytes()
        c['restored_sha256'] = sha(restored)
        c['restore_audit_sha256'] = sha(restored.replace(before, after))
        assert restored == original and c['restore_audit_sha256'] == c['mutant_sha256']
        save()
    print('restored CTest missing-fixture control', flush=True)
    tests = run_ctest('restored-all', '^test-workchain-(construction-isolation|i13-acceptance|i13-usage-acceptance)-gates$', 0)
    assert {t.findtext('Name') for t in tests} == names
    assert all(t.get('Status') == 'passed' for t in tests)
    for c in report['controls']:
        c['restored_ctest_passed'] = True
    for short in stems:
        runs = list((args.build / 'workchain-i13-ctest' / short / 'runs').glob('run-*/evidence'))
        runs = [p for p in runs if json.loads((p / 'measurement.json').read_text()).get('complete') or
                json.loads((p / 'measurement.json').read_text()).get('original_source_files_unchanged')]
        assert len(runs) == 1, 'expected one complete fresh positive run per driver'
        shutil.copytree(runs[0], args.output / short)
        report[short + '_report'] = short + '/measurement.json'
    for rel, binding in report['sources'].items():
        assert sha((repo / rel).read_bytes()) == binding['blob_sha256']
    report['complete'] = True
    save()
    print('PASS: three explicitly registered drivers fail under control and pass after restoration', flush=True)


if __name__ == '__main__':
    main()
