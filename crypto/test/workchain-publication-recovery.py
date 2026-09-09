#!/usr/bin/env python3
"""Private disk recovery checks with source-bound, isolated controls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from workchain_i13_paths import resolve_ctest_paths


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--work', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--ctest-root', type=Path)
    args = parser.parse_args()
    resolve_ctest_paths(parser, args)
    for p in (args.work, args.output):
        p.mkdir(parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parents[2]
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
    names = {'source': 'crypto/block/workchain-candidate-publication.cpp',
             'test': 'crypto/test/test-workchain-publication-recovery.cpp',
             'fault': 'crypto/test/workchain-publication-io-fault.cpp',
             'set_fault': 'crypto/test/workchain-publication-set-fault.cpp'}
    originals, blobs = {}, {}
    for key, path in names.items():
        original = (repo / path).read_bytes()
        blob = subprocess.check_output(['git', 'show', commit + ':' + path], cwd=repo)
        assert original == blob, 'uncommitted measured source: ' + path
        originals[key] = original
        blobs[key] = {'commit': commit, 'path': path, 'blob_sha256': sha(blob),
                      'git_blob_oid': subprocess.check_output(['git', 'rev-parse', commit + ':' + path], cwd=repo, text=True).strip()}
    report = {'schema': 1, 'base_commit': commit, 'events': [], 'controls': [],
              'scope': 'Private RocksDb publication and passive immutable readers. No live host integration, '
                       'activation, finality or permission to send. D31 provider allocation/history bounds remain open. '
                       'Runtime I/O controls cover isolated WAL operations and actual reopen, not every power-loss failure. '
                       'No production VmVirtError classification or I13 acceptance is established.',
              'runner_sha256': sha(Path(__file__).read_bytes())}
    def record():
        (args.output / 'measurement.json').write_text(json.dumps(report, indent=2) + '\n')
    def command(label, argv, preload=True):
        env = dict(os.environ)
        env.pop('LD_PRELOAD', None)
        if preload:
            env['LD_PRELOAD'] = str(args.build / 'libworkchain-publication-io-fault.so')
        with (args.output / (label + '.stdout.log')).open('wb') as out, (args.output / (label + '.stderr.log')).open('wb') as err:
            result = subprocess.run([str(a) for a in argv], cwd=repo, env=env, stdout=out, stderr=err)
        event = {'label': label, 'command': [str(a) for a in argv], 'exit': result.returncode,
                 'preload': env.get('LD_PRELOAD'), **{s + '_sha256': sha((args.output / (label + '.' + s + '.log')).read_bytes()) for s in ('stdout', 'stderr')}}
        report['events'].append(event)
        record()
        return result.returncode
    def configure(label, key=None, shadow=None):
        switches = {'source': 'PUBLICATION_SOURCE', 'test': 'PUBLICATION_TEST_SOURCE', 'fault': 'PUBLICATION_FAULT_SOURCE', 'set_fault': 'PUBLICATION_SET_FAULT_SOURCE'}
        argv = ['cmake', '-S', repo, '-B', args.build, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
                '-DCMAKE_PROJECT_TOS_INCLUDE=' + str(repo / 'crypto/test/workchain-publication-recovery.cmake'),
                '-DTOS_UNO_CRYPTO_PROTOTYPE_TESTS=OFF']
        argv += ['-D' + switch + '=' + str(shadow if k == key else repo / names[k]) for k, switch in switches.items()]
        assert command(label + '-configure', argv, False) == 0, 'configuration failure, not behavioral evidence'
        assert command(label + '-build', ['cmake', '--build', args.build, '--target', 'test-workchain-publication-recovery', 'workchain-publication-io-fault', '-j32'], False) == 0, 'build failure, not behavioral evidence'
        assert command(label + '-dependencies', ['ninja', '-C', args.build, '-t', 'deps'], False) == 0
        deps = (args.output / (label + '-dependencies.stdout.log')).read_text()
        if key:
            assert str(shadow) in deps
        else:
            # Ninja retains obsolete object entries. Query active compile commands
            # instead of treating its historical dependency database as active.
            assert command(label + '-commands', ['ninja', '-C', args.build, '-t', 'commands', 'test-workchain-publication-recovery', 'workchain-publication-io-fault'], False) == 0
            assert str(args.work / 'shadow') not in (args.output / (label + '-commands.stdout.log')).read_text()
    oracle = args.output / 'oracle'
    oracle.mkdir(exist_ok=False)
    def oracle_hashes():
        return {str(p.relative_to(oracle)): sha(p.read_bytes()) for p in sorted(oracle.rglob('*')) if p.is_file()}
    def run(label, expected=None, preload=True):
        results = {}
        for case in range(12):
            directory = args.work / (label + '-' + str(case))
            directory.mkdir(exist_ok=False)
            results[case] = command(label + '-case-' + str(case), [args.build / 'test-workchain-publication-recovery', case, directory, oracle], preload)
            if (directory / 'trace').exists():
                shutil.copyfile(directory / 'trace', args.output / (label + '-case-' + str(case) + '.trace'))
        assert oracle_hashes() == report['oracle_sha256'], 'frozen oracle changed'
        if expected is not None:
            assert results == {i: expected.get(i, 0) for i in range(12)}, (label, results, expected)
        return results
    configure('baseline')
    assert command('freeze', [args.build / 'test-workchain-publication-recovery', 'freeze', oracle]) == 0
    report['oracle_sha256'] = oracle_hashes()
    assert len(report['oracle_sha256']) == 45
    report['baseline'] = run('baseline', {})
    committed = [0, 2, 3, 5, 6, 7, 8, 9]
    def failures(cases, identity):
        return dict.fromkeys(cases, identity)
    controls = []
    def add(name, key, before, after, expected, claim):
        controls.append((name, key, before, after, expected, claim))
    duplicate = 'if (recorded.move_as_ok() == td::KeyValue::GetStatus::Ok) return read_and_release(identity, admitted_input, observer);'
    add('reexecute-identical-retry', 'source', duplicate,
        'if (recorded.move_as_ok() == td::KeyValue::GetStatus::Ok) { auto repeated = build(); if (repeated.is_error()) return absent(repeated.move_as_error()); return read_and_release(identity, admitted_input, observer); }',
        failures(committed, 205), 'Independent durable execution probe, with identical result, write and release behavior.')
    add('rewrite-identical-retry', 'source', duplicate,
        'if (recorded.move_as_ok() == td::KeyValue::GetStatus::Ok) { auto repeated = decode(previous, limits_.max_bundle_bytes); if (repeated.is_error()) return unavailable(repeated.move_as_error()); return write(repeated.ok(), observer); }',
        failures(committed, 219), 'Extra durable write without re-execution or changed bytes.')
    add('reinstall-identical-view', 'source', 'if (prior && prior->batch_identity == current_identity) {', 'if (false) {',
        failures(committed, 206), 'Passive release idempotence; values remain identical.')
    add('remove-read-observation', 'source', 'observe(observer, Point::PersistentRead);\n  bool installed', '/* Read observation removed. */\n  bool installed',
        failures([0, 5, 7, 8, 9], 220), 'Same read observation guard in normal and cold recovery entry points.')
    add('remove-new-release-observation', 'source', 'observe(observer, Point::ReleaseInstall);',
        'if (released_.load()->committed_batch_count == 0) observe(observer, Point::ReleaseInstall);',
        failures(committed, 207), 'Same release observation guard in both entry points; bootstrap observation retained.')
    add('normalize-external-count', 'source', 'append_u64(out, b.committed_batch_count);', 'append_u64(out, b.committed_batch_count == 0 ? 0 : 1);',
        {7: 222}, 'External count fidelity, independent of I13a semantic validity.')
    add('retain-old-message-bytes', 'source', 'auto encoded = encode(bundle, limits_.max_bundle_bytes);',
        'auto altered = bundle; if (auto prior = released_.load()) altered.pending_messages = prior->pending_messages; auto encoded = encode(altered, limits_.max_bundle_bytes);',
        failures(committed, 203), 'Actual message reader compares frozen payload and queue metadata.')
    add('drift-account-bytes', 'source', 'auto encoded = encode(bundle, limits_.max_bundle_bytes);',
        'auto altered = bundle; if (released_.load()) altered.components[0] += "drift"; auto encoded = encode(altered, limits_.max_bundle_bytes);',
        {**failures([0, 2, 3, 6, 7, 8, 9], 201), 5: 207}, 'Full state bytes; cold-reader identity 207 includes complete state observation.')
    add('expose-view-while-undetermined', 'source', 'if (recovery_required_.load()) return td::Status::Error(local_unavailable, "publication read requires recovery");',
        '/* Recovery read guard removed. */', failures([2, 3, 4, 6, 10, 11], 208), 'Current reader refuses unresolved storage state.')
    add('execute-while-undetermined', 'source', 'if (active_ || recovery_required_.load()) return unavailable();', 'if (active_) return unavailable();',
        failures([2, 3, 4, 6, 10, 11], 211), 'No execution or retry before persistent resolution.')
    add('infer-absence-from-reopen-error', 'source', 'if (reopened.is_error()) return unavailable(std::move(reopened));',
        'if (reopened.is_error()) return absent();', {6: 212}, 'Unavailable recovery must not mean absent.')
    add('erase-store-binding', 'source', 'status != td::KeyValue::GetStatus::Ok || binding != store_identity_.as_slice().str()',
        'status != td::KeyValue::GetStatus::Ok', {9: 223}, 'Actual store identity, not an implicitly new recovery store.')
    add('erase-completed-sync-counter', 'fault', 'synced.fetch_add(1);', '/* Completed sync probe removed. */',
        failures([3, 6], 216), 'Successful underlying sync must be observed before synthetic EIO.')
    add('disable-commit-point-io-fault', 'fault', 'mode.load()==2 && matches(fd,true)', 'false && matches(fd,true)',
        failures([3, 6], 204), 'Real commit-point I/O control is active; this is instrument calibration.')
    add('erase-execution-probe', 'test', 'trace(dir,"execute");auto result', '/* Execution probe removed. */auto result',
        {**failures(list(range(12)), 205), 2: 221}, 'Independent execution counter cannot silently disappear.')
    add('disable-partial-write-fault', 'fault', 'mode.store(selected);', 'mode.store(selected == 1 ? 0 : selected);',
        {2: 204}, 'Partial-write runtime instrument must be active; no writer-status inference.')
    add('disable-prewrite-cancellation', 'test', 'if(mode==1)throw CancelBeforeWrite{};', 'if(false)throw CancelBeforeWrite{};',
        {1: 204}, 'Before-write cancellation actually occurs, not an unexercised label.')
    add('disable-postcommit-crash', 'test', 'p==PubPoint::AfterCommitBeforeRead&&mode==5', 'false',
        {5: 215}, 'Cold recovery scenario must terminate before its first release.')
    add('mark-record-set-error-ready', 'source', 'return not_committed_unavailable(std::move(stored));',
        'return absent(std::move(stored));', {10: 225}, 'Known non-commit does not make a local record-set error Ready.')
    add('mark-head-set-error-ready', 'source', 'return not_committed_unavailable(std::move(headed));',
        'return absent(std::move(headed));', {11: 225}, 'Known non-commit does not make a local head-set error Ready.')
    add('erase-set-error-probe', 'set_fault', 'errors.fetch_add(1);', '/* API error probe removed. */',
        failures([10, 11], 227), 'The actual backend set boundary must be crossed before error substitution.')
    add('disable-set-error-injection', 'set_fault', 'const auto mode = selected.load();', 'const auto mode = 0;',
        failures([10, 11], 225), 'API-boundary status injection, not a physical disk failure claim.')
    shadow_dir = args.work / 'shadow'  
    shadow_dir.mkdir()
    for name, key, before, after, expected, claim in controls:
        original = originals[key]
        source = repo / names[key]
        assert original.count(before.encode()) == 1, name
        mutant = original.replace(before.encode(), after.encode())
        shadow = shadow_dir / source.name
        shadow.write_bytes(original)
        assert sha(shadow.read_bytes()) == blobs[key]['blob_sha256']
        entry = {'name': name, 'claim': claim, 'committed_source': blobs[key], 'from': before, 'to': after,
                 'offset': original.index(before.encode()), 'original_sha256': sha(original),
                 'copy_before_sha256': sha(shadow.read_bytes()), 'mutant_sha256': sha(mutant)}
        shadow.write_bytes(mutant)
        try:
            configure(name, key, shadow)
            entry['results'] = run(name, expected)
        finally:
            shadow.write_bytes(original)
            entry['restored_sha256'] = sha(shadow.read_bytes())
            entry['restore_audit_sha256'] = sha(shadow.read_bytes().replace(before.encode(), after.encode()))
            assert entry['restore_audit_sha256'] == entry['mutant_sha256']
            assert source.read_bytes() == original
            shadow.unlink()
            report['controls'].append(entry)
            record()
        configure(name + '-restored')
        run(name + '-restored', {})
    report['missing_io_dependency'] = run('missing-io-dependency', failures(list(range(12)), 213), False)
    report['source_files_unchanged'] = all((repo / names[k]).read_bytes() == v for k, v in originals.items())
    assert report['source_files_unchanged']
    record()
    print('PASS: 12 private disk scenarios, 22 isolated controls; no milestone acceptance claimed.')


if __name__ == '__main__':
    main()
