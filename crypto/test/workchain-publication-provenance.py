#!/usr/bin/env python3
"""Manual persistent-content calibration; intentionally not a CI mutation driver."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', required=True, type=Path)
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    for path in (args.work, args.output):
        path.mkdir(parents=True, exist_ok=False)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
    path = 'crypto/block/workchain-candidate-publication.cpp'
    original = (repo / path).read_bytes()
    sources = {}
    for name in (path, 'crypto/block/workchain-candidate-publication.h',
                 'crypto/test/test-workchain-publication-provenance.cpp',
                 'crypto/test/test-workchain-construction-isolation.cpp',
                 'crypto/test/workchain-publication-provenance.cmake'):
        blob = subprocess.check_output(['git', 'show', commit + ':' + name], cwd=repo)
        assert blob == (repo / name).read_bytes(), name
        sources[name] = {'sha256': sha(blob), 'git_blob_oid': subprocess.check_output(
            ['git', 'rev-parse', commit + ':' + name], cwd=repo, text=True).strip()}
    report = {'schema': 1, 'base_commit': commit, 'sources': sources, 'events': [],
              'scope': 'One manual content-origin calibration, independent of PersistentRead observations. '
                       'A real backend WriteBatch changes a valid account-root BOC after durable commit and '
                       'before first release, retaining identity/input and all other fields. This is codec-level '
                       'provenance, not whole-candidate semantic validity or live I13e acceptance. '
                       'An already released changed same-identity record remains subject to immutable-view rejection.',
              'runner_sha256': sha(Path(__file__).read_bytes())}
    def record():
        (args.output / 'measurement.json').write_text(json.dumps(report, indent=2) + '\n')
    def command(label, argv):
        env = dict(os.environ)
        env.pop('LD_PRELOAD', None)
        with (args.output / (label + '.stdout.log')).open('wb') as out, (args.output / (label + '.stderr.log')).open('wb') as err:
            result = subprocess.run([str(a) for a in argv], cwd=repo, env=env, stdout=out, stderr=err)
        report['events'].append({'label': label, 'command': [str(a) for a in argv], 'exit': result.returncode,
                                 **{s + '_sha256': sha((args.output / (label + '.' + s + '.log')).read_bytes()) for s in ('stdout', 'stderr')}})
        record()
        return result.returncode
    shadow = args.work / 'workchain-candidate-publication.cpp'
    def build(label, source):
        argv = ['cmake', '-S', repo, '-B', args.build, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
                '-DCMAKE_PROJECT_TOS_INCLUDE=' + str(repo / 'crypto/test/workchain-publication-provenance.cmake'),
                '-DPUBLICATION_SOURCE=' + str(source), '-DTOS_UNO_CRYPTO_PROTOTYPE_TESTS=OFF']
        assert command(label + '-configure', argv) == 0
        assert command(label + '-build', ['cmake', '--build', args.build, '--target', 'test-workchain-publication-provenance', '-j32']) == 0, 'build failure is not behavior evidence'
        relative = path if source == repo / path else str(source).lstrip('/')
        objects = ['CMakeFiles/workchain-private-publication.dir/' + relative + '.o',
                   'CMakeFiles/test-workchain-publication-provenance.dir/crypto/test/test-workchain-publication-provenance.cpp.o']
        assert command(label + '-commands', ['ninja', '-C', args.build, '-t', 'commands', *objects]) == 0
        text = (args.output / (label + '-commands.stdout.log')).read_text()
        assert (str(shadow) in text) == (source == shadow)
        assert command(label + '-dependencies', ['ninja', '-C', args.build, '-t', 'deps', *objects]) == 0
        assert str(repo / 'crypto/block/workchain-candidate-publication.h') in (args.output / (label + '-dependencies.stdout.log')).read_text()
    def run(label, expected):
        directory = args.work / label
        directory.mkdir(exist_ok=False)
        status = command(label, [args.build / 'test-workchain-publication-provenance', directory])
        record_dir = args.output / label
        record_dir.mkdir(exist_ok=False)
        hashes = {}
        for name in ('original-component.boc', 'replacement-component.boc', 'released-component.boc', 'stored-record.bin'):
            hashes[name] = sha((directory / name).read_bytes())
            shutil.copyfile(directory / name, record_dir / name)
        observation = json.loads((args.output / (label + '.stdout.log')).read_text().splitlines()[0])
        report[label] = {'exit': status, 'artifacts': hashes, 'observation': observation,
                         'binary_sha256': sha((args.build / 'test-workchain-publication-provenance').read_bytes())}
        record()
        assert status == expected
        assert observation['executions'] == observation['substitutions'] == 1
        assert observation['stored_matches_replacement'] and observation['bindings_and_other_fields_unchanged']
        assert observation['view_matches_replacement'] == (expected == 0)
        assert observation['view_matches_original'] == (expected != 0)
        assert hashes['original-component.boc'] != hashes['replacement-component.boc']
    build('baseline', repo / path)
    run('baseline', 0)
    before = 'return read_and_release(bundle.batch_identity, bundle.admitted_input, observer);'
    after = ('released_.store(std::make_shared<const Bundle>(bundle)); recovery_required_.store(false); '
             'observe(observer, Point::PersistentRead); observe(observer, Point::ReleaseInstall); '
             'return {Outcome::Committed, Availability::Ready, td::Status::OK()};')
    assert original.count(before.encode()) == 1
    mutant = original.replace(before.encode(), after.encode())
    shadow.write_bytes(original)
    control = {'name': 'bypass-readback-and-forge-read-event', 'committed_source': {'commit': commit, 'path': path,
               'blob_sha256': sources[path]['sha256'], 'git_blob_oid': sources[path]['git_blob_oid']},
               'from': before, 'to': after, 'offset': original.index(before.encode()),
               'original_sha256': sha(original), 'copy_before_sha256': sha(shadow.read_bytes()), 'mutant_sha256': sha(mutant)}
    assert control['copy_before_sha256'] == sources[path]['sha256']
    shadow.write_bytes(mutant)
    try:
        build('replacement', shadow)
        run('replacement', 230)
    finally:
        shadow.write_bytes(original)
        control['restored_sha256'] = sha(shadow.read_bytes())
        control['restore_audit_sha256'] = sha(shadow.read_bytes().replace(before.encode(), after.encode()))
        assert control['restore_audit_sha256'] == control['mutant_sha256']
        assert (repo / path).read_bytes() == original
        shadow.unlink()
        report['controls'] = [control]
        record()
        build('restored', repo / path)
        run('restored', 0)
    for name in ('original-component.boc', 'replacement-component.boc', 'stored-record.bin'):
        assert len({report[stage]['artifacts'][name] for stage in ('baseline', 'replacement', 'restored')}) == 1
    assert report['baseline']['artifacts']['released-component.boc'] == report['restored']['artifacts']['released-component.boc']
    report['production_sources_unchanged'] = all((repo / name).read_bytes() == subprocess.check_output(
        ['git', 'show', commit + ':' + name], cwd=repo) for name in sources)
    assert report['production_sources_unchanged']
    record()
    print('PASS: real persistent bytes distinguish readback from a forged read observation; no production source changes.')


if __name__ == '__main__':
    main()
