#!/usr/bin/env python3
"""Measure partial-old-state acceptance against committed sources."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    for name in ('build', 'work', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    args.work.mkdir(parents=True, exist_ok=False)
    args.output.mkdir(parents=True, exist_ok=False)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
    target = 'test-workchain-i13-usage-acceptance'
    relative = 'crypto/test/' + target + '.cpp'
    original = subprocess.check_output(['git', 'show', commit + ':' + relative], cwd=repo)
    assert (repo / relative).read_bytes() == original
    inventory = {}
    for path in (relative, 'crypto/test/test-workchain-i13-acceptance.cpp',
                 'crypto/block/workchain-storage-overlay.h', 'crypto/block/workchain-account-dictionary.h',
                 'crypto/block/workchain-account-access.h', 'crypto/vm/excno.hpp'):
        data = subprocess.check_output(['git', 'show', commit + ':' + path], cwd=repo)
        assert (repo / path).read_bytes() == data
        inventory[path] = {'commit': commit, 'blob_sha256': sha(data), 'git_blob_oid':
                          subprocess.check_output(['git', 'rev-parse', commit + ':' + path], cwd=repo, text=True).strip()}
    report = {'schema': 1, 'base_commit': commit, 'source_inventory': inventory,
              'runner_sha256': sha(Path(__file__).read_bytes()), 'events': [], 'controls': [],
              'scope': 'Three private storage-overlay cases, each with two available and four pruned old account bodies. '
                       'No activation, full admitted-engine/replay or universal independence claim. '
                       'Fixture metadata paths are exposed before proof extraction, without loading unused bodies. '
                       'Pruning is deliberately test-constructed to check non-dependence; this establishes no production '
                       'VmVirtError classification. Forbidden candidate pruned structure is CandidateInvalid; missing '
                       'authenticated local state is LocalUnavailable. Exception type alone cannot distinguish their sources.'}
    copied = args.work / (target + '.cpp')

    def save():
        (args.output / 'measurement.json').write_text(json.dumps(report, indent=2) + '\n')

    def command(label, argv):
        proc = subprocess.run([str(a) for a in argv], cwd=repo, capture_output=True)
        e = {'label': label, 'command': [str(a) for a in argv], 'exit': proc.returncode}
        for stream in ('stdout', 'stderr'):
            data = getattr(proc, stream)
            (args.output / (label + '.' + stream + '.log')).write_bytes(data)
            e[stream + '_sha256'] = sha(data)
        report['events'].append(e)
        save()
        return proc.returncode

    def build(label, mutant=False):
        status = command(label + '-configure', ['cmake', '-S', repo, '-B', args.build, '-G', 'Ninja',
                         '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_PROJECT_TOS_INCLUDE=' + str(repo /
                         'crypto/test/workchain-i13-usage-acceptance.cmake'),
                         '-DI13_USAGE_SOURCE=' + (str(copied) if mutant else ''),
                         '-DTOS_UNO_CRYPTO_PROTOTYPE_TESTS=OFF'])
        assert status == 0
        status = command(label + '-build', ['cmake', '--build', args.build, '--target', target, '-j32'])
        if status != 0:
            raise RuntimeError('build failure is not behavioral evidence')
        object_path = str(copied).lstrip('/') if mutant else relative
        assert command(label + '-dependencies', ['ninja', '-C', args.build, '-t', 'deps',
                       'CMakeFiles/' + target + '.dir/' + object_path + '.o']) == 0
        deps = (args.output / (label + '-dependencies.stdout.log')).read_text()
        for header in ('workchain-storage-overlay.h', 'workchain-account-dictionary.h', 'workchain-account-access.h'):
            assert str(repo / 'crypto/block' / header) in deps
        assert str(repo / 'crypto/test/test-workchain-i13-acceptance.cpp') in deps
        assert str(copied if mutant else repo / relative) in deps
        if not mutant:
            assert str(copied) not in deps

    def run(label, expected):
        for scenario in range(3):
            status = command(label + '-case-' + str(scenario), [args.build / target, str(scenario)])
            assert status == expected, (label, scenario, expected, status)

    build('baseline')
    run('baseline', 0)
    call = 'limited = overlay(f, tracked_partial, selected);'
    full = 'auto complete = overlay(f, proof_builder.root(), selected);'
    controls = [
        ('bypass-pruning', 'auto partial = vm::MerkleProof::virtualize(proof).move_as_ok();',
         'auto partial = f.root;', 51),
        ('load-missing-body', call,
         'auto missing = vm::load_cell_slice(unavailable.front()); (void)missing;\n    ' + call, 52),
        ('bypass-partial-input', call, 'limited = overlay(f, f.root, selected);', 53),
        ('remove-read-observer', 'if (cell.get_hash() == body->get_hash()) observed.insert(id);',
         'if (false) observed.insert(id);', 53),
        ('change-account-root-oracle', full,
         full + '\n  complete.accounts = vm::CellBuilder().store_long(1, 1).finalize();', 55),
        ('change-block-root-oracle', full,
         full + '\n  complete.account_blocks = vm::CellBuilder().store_long(1, 1).finalize();', 58),
        ('change-block-bytes-oracle', 'auto full_blocks = vm::std_boc_serialize(complete.account_blocks).move_as_ok();',
         'auto full_blocks = vm::std_boc_serialize(vm::CellBuilder().store_long(1, 1).finalize()).move_as_ok();', 59),
        ('rehydrate-returned-unread-bodies',
         'vm::AugmentedDictionary next(vm::load_cell_slice_ref(limited.accounts), 256, block::tlb::aug_ShardAccounts);',
         'limited.accounts = complete.accounts;\n  '
         'vm::AugmentedDictionary next(vm::load_cell_slice_ref(limited.accounts), 256, block::tlb::aug_ShardAccounts);', 56),
    ]
    for label, old, new, expected in controls:
        before, after = old.encode(), new.encode()
        assert original.count(before) == 1
        copied.write_bytes(original)
        assert sha(copied.read_bytes()) == inventory[relative]['blob_sha256']
        mutant = original.replace(before, after)
        control = {'label': label, 'source': relative, 'committed_source': inventory[relative],
                   'from': old, 'to': new, 'offset': original.index(before), 'original_sha256': sha(original),
                   'copy_before_sha256': sha(copied.read_bytes()), 'mutant_sha256': sha(mutant),
                   'cases': [0, 1, 2], 'expected_exit': expected}
        report['controls'].append(control)
        copied.write_bytes(mutant)
        try:
            build(label, True)
            control['compiled'] = True
            run(label, expected)
            control['behavior_confirmed'] = True
        finally:
            copied.write_bytes(original)
            restored = copied.read_bytes()
            control['restored_sha256'] = sha(restored)
            control['restore_audit_sha256'] = sha(restored.replace(before, after))
            assert restored == original
            assert control['restore_audit_sha256'] == control['mutant_sha256']
            copied.unlink()
            control['copy_discarded'] = not copied.exists()
            save()
        build(label + '-restored')
        run(label + '-restored', 0)
    run('final', 0)
    for path, meta in inventory.items():
        assert sha((repo / path).read_bytes()) == meta['blob_sha256']
    report['original_source_files_unchanged'] = True
    report['complete'] = True
    save()
    print('PASS: three partial-state cases, eight compiled controls, restore audits; review pending')


if __name__ == '__main__':
    main()
