#!/usr/bin/env python3
"""Build private multi-account cases and archive isolated, restored controls."""
import argparse
import hashlib
import json
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
    repo = Path(__file__).resolve().parents[2]
    args.work.mkdir(parents=True, exist_ok=False)
    args.output.mkdir(parents=True, exist_ok=False)
    shadow = args.work / 'include/block'
    shadow.mkdir(parents=True)
    originals = {}
    paths = {}
    for name in ('workchain-account-access.h', 'workchain-account-dictionary.h', 'workchain-storage-overlay.h'):
        source = repo / 'crypto/block' / name
        paths[name] = shadow / name
        originals[name] = source.read_bytes()
    name = 'test-workchain-i13-acceptance.cpp'
    paths[name] = args.work / name
    originals[name] = (repo / 'crypto/test' / name).read_bytes()
    base_commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
    blobs = {}
    for file, original in originals.items():
        relpath = ('crypto/block/' if file.endswith('.h') else 'crypto/test/') + file
        blob = subprocess.check_output(['git', 'show', base_commit + ':' + relpath], cwd=repo)
        assert original == blob, 'source differs from committed blob: ' + file
        blobs[file] = {'commit': base_commit, 'path': relpath, 'blob_sha256': sha(blob),
                       'git_blob_oid': subprocess.check_output(
                           ['git', 'rev-parse', base_commit + ':' + relpath], cwd=repo, text=True).strip()}
    report = {'schema': 1, 'base_commit': base_commit,
        'source_sha256': {k: sha(v) for k, v in originals.items()},
        'runner_sha256': sha(Path(__file__).read_bytes()), 'events': [], 'controls': [],
        'scope': 'Private host primitive/storage-overlay acceptance. No activation. '
                 'Temporary source copies only. Full admitted engine/settlement/replay integration is not certified. '
                 'Usage absence alone does not imply unchanged state; case 10 demonstrates this limit.'}

    def record():
        (args.output / 'measurement.json').write_text(json.dumps(report, indent=2) + '\n')

    def command(label, argv):
        proc = subprocess.run([str(a) for a in argv], cwd=repo, capture_output=True)
        for stream in ('stdout', 'stderr'):
            (args.output / (label + '.' + stream + '.log')).write_bytes(getattr(proc, stream))
        event = {'label': label, 'command': [str(a) for a in argv], 'exit': proc.returncode,
                 'stdout_sha256': sha(proc.stdout), 'stderr_sha256': sha(proc.stderr)}
        report['events'].append(event)
        record()
        return proc.returncode

    def build(label):
        status = command(label, ['cmake', '--build', args.build, '--target',
                                 'test-workchain-i13-acceptance', '-j32'])
        if status != 0:
            raise RuntimeError('build failed; no behavioral evidence: ' + label)

    def run(label, cases, expected):
        for case in cases:
            status = command(label + '-case-' + str(case),
                             [args.build / 'test-workchain-i13-acceptance', str(case)])
            if status != expected:
                raise RuntimeError(f'{label}: case {case}: expected exit {expected}, got {status}')

    def configure(label, file=None):
        # Only a mutant build sees a copied source/header. Baseline and restored
        # builds consume real repository paths, with the shadow directory empty.
        source = paths[file] if file and file.endswith('.cpp') else ''
        include = shadow.parent if file and file.endswith('.h') else ''
        argv = ['cmake', '-S', repo, '-B', args.build, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
                '-DCMAKE_PROJECT_TOS_INCLUDE=' + str(repo / 'crypto/test/workchain-i13-acceptance.cmake'),
                '-DI13_ACCEPTANCE_SOURCE=' + str(source), '-DI13_ACCEPTANCE_HEADER_DIR=' + str(include),
                '-DTOS_UNO_CRYPTO_PROTOTYPE_TESTS=OFF']
        if command(label, argv) != 0:
            raise RuntimeError('configuration failed')

    def dependencies(label, file=None):
        obj = 'CMakeFiles/test-workchain-i13-acceptance.dir/'
        if file and file.endswith('.cpp'):
            obj += str(paths[file]).lstrip('/') + '.o'
        else:
            obj += 'crypto/test/test-workchain-i13-acceptance.cpp.o'
        status = command(label, ['ninja', '-C', args.build, '-t', 'deps', obj])
        assert status == 0
        text = (args.output / (label + '.stdout.log')).read_text()
        for header in ('workchain-account-access.h', 'workchain-account-dictionary.h', 'workchain-storage-overlay.h'):
            expected = paths[header] if file == header else repo / 'crypto/block' / header
            assert str(expected) in text, 'actual header dependency missing: ' + str(expected)
            if file != header:
                assert str(paths[header]) not in text, 'shadow header leaked into production build'

    configure('baseline-configure')
    build('baseline-build')
    dependencies('baseline-dependencies')
    run('baseline', range(16), 0)
    access = 'workchain-account-access.h'
    cpp = name
    controls = [
        ('misroute-overlay-write', 'workchain-storage-overlay.h',
         '!staged.set_builder(account.addr, entry, vm::Dictionary::SetMode::Replace)',
         '!staged.set_builder(writes.back().account, entry, vm::Dictionary::SetMode::Replace)', [0], 10),
        ('omit-actual-equality', access,
         'if (actual_changed_accounts != writes_)', 'if (false)', [1, 2], 41),
        ('omit-participant-equality', access,
         'if (participant_accounts != writes_)', 'if (false)', [3, 4], 41),
        ('omit-unused-read-check', access,
         'if (std::find(read_seen_.begin(), read_seen_.end(), false) != read_seen_.end())',
         'if (false)', [5], 42),
        ('omit-old-hash-binding', access, 'if (expected != actual_hash)', 'if (false)', [6, 7, 12], 42),
        ('permit-undeclared-middle-read', access,
         'if (it == reads_.end() || it->account != account)', 'if (it == reads_.end())', [8], 42),
        ('omit-difference-key', 'workchain-account-dictionary.h',
         'keys.emplace_back(key);', '(void)key;', [13, 14, 15], 40),
        ('remove-usage-observation', cpp,
         'if (cell.get_hash() == body->get_hash()) bodies_read.insert(id);',
         'if (false) bodies_read.insert(id);', [9], 43),
        ('read-unparticipating-body', cpp,
         'result = overlay(f, tracked, {16, 64}).accounts;',
         'result = overlay(f, tracked, {16, 64}).accounts;\n'
         '      vm::AugmentedDictionary probe(vm::load_cell_slice_ref(tracked), 256, block::tlb::aug_ShardAccounts);\n'
         '      block::tlb::ShardAccount::Record entry;\n'
         '      require(entry.unpack(probe.lookup(key(128))), "probe.entry");\n'
         '      auto loaded = vm::load_cell_slice(entry.account);\n'
         '      require(loaded.size() > 0, "probe.loaded");', [9], 43),
        ('alter-unparticipating-result', cpp,
         'result = overlay(f, tracked, {16, 64}).accounts;',
         'result = overlay(f, tracked, {16, 64}).accounts;\n'
         '      vm::AugmentedDictionary altered(vm::load_cell_slice_ref(result), 256, block::tlb::aug_ShardAccounts);\n'
         '      put(altered, 128, account(128, 2), 2);\n'
         '      result = altered.get_wrapped_dict_root();', [9], 44),
    ]
    for label, file, old, new, cases, expected in controls:
        original = originals[file]
        before, after = old.encode(), new.encode()
        if original.count(before) != 1:
            raise RuntimeError('nonunique mutation anchor: ' + label)
        mutant = original.replace(before, after)
        control = {'label': label, 'source': file, 'from': old, 'to': new,
                   'offset': original.index(before), 'original_sha256': sha(original),
                   'committed_source': blobs[file], 'copy_before_sha256': sha(original),
                   'mutant_sha256': sha(mutant), 'expected_exit': expected, 'cases': cases}
        report['controls'].append(control)
        paths[file].write_bytes(original)
        assert paths[file].read_bytes() == subprocess.check_output(
            ['git', 'show', base_commit + ':' + blobs[file]['path']], cwd=repo)
        assert sha(paths[file].read_bytes()) == blobs[file]['blob_sha256']
        paths[file].write_bytes(mutant)
        try:
            configure(label + '-configure', file)
            build(label + '-build')
            dependencies(label + '-dependencies', file)
            control['compiled'] = True
            run(label, cases, expected)
            control['behavior_confirmed'] = True
        finally:
            paths[file].write_bytes(original)
            restored = paths[file].read_bytes()
            control['restored_sha256'] = sha(restored)
            control['restore_audit_sha256'] = sha(restored.replace(before, after))
            assert restored == original
            assert control['restore_audit_sha256'] == control['mutant_sha256']
            paths[file].unlink()
            control['copy_discarded'] = not paths[file].exists()
            assert (repo / blobs[file]['path']).read_bytes() == original
            record()
        configure(label + '-restored-configure')
        build(label + '-restored-build')
        dependencies(label + '-restored-dependencies')
        run(label + '-restored', cases, 0)
    run('final', range(16), 0)
    for file, original in originals.items():
        location = repo / ('crypto/block' if file.endswith('.h') else 'crypto/test') / file
        assert location.read_bytes() == original
    report['original_source_files_unchanged'] = True
    report['complete'] = True
    record()
    print('PASS: 16 cases, 10 isolated controls, restored sources; review pending')


if __name__ == '__main__':
    main()
