#!/usr/bin/env python3
"""Archive source-bound, single-copy construction-isolation controls."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--build', required=True, type=Path)
    p.add_argument('--work', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    repo = Path(__file__).resolve().parents[2]
    for path in (args.work, args.output):
        path.mkdir(parents=True, exist_ok=False)
    shadow = args.work / 'include/block'
    shadow.mkdir(parents=True)
    oracle = args.output / 'oracles'
    oracle.mkdir()
    cpp = 'test-workchain-construction-isolation.cpp'
    core = 'workchain-candidate-construction.h'
    payout = 'workchain-payout-overlay.h'
    imports = 'workchain-import-evidence.h'
    queue = 'workchain-outbound-queues.h'
    names = [cpp, core, payout, imports, queue, 'workchain-construction-observer.h']
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
    originals, copies, bindings = {}, {}, {}
    for name in names:
        rel = 'crypto/' + ('test/' if name.endswith('.cpp') else 'block/') + name
        data = (repo / rel).read_bytes()
        blob = subprocess.check_output(['git', 'show', commit + ':' + rel], cwd=repo)
        assert data == blob, 'working source differs from committed blob: ' + rel
        originals[name] = data
        copies[name] = args.work / name if name.endswith('.cpp') else shadow / name
        bindings[name] = {'commit': commit, 'path': rel, 'blob_sha256': sha(blob),
            'git_blob_oid': subprocess.check_output(['git', 'rev-parse', commit + ':' + rel], cwd=repo, text=True).strip()}
    report = {'schema': 1, 'base_commit': commit, 'runner_sha256': sha(Path(__file__).read_bytes()),
        'scope': 'Private candidate context with real Native payout/import/queue artifacts. '
        '23 construction positions; no storage/recovery or consensus-authority claim. '
        'The same-block reader consumes the actual context snapshot. Live collator consumer coverage, '
        'full collator processing metadata and D31 integration remain unestablished. '
        'Frozen oracles calibrate isolation and supplied-value preservation, not independent Native semantics. '
        'No activation or I13e acceptance claimed.',
        'events': [], 'controls': [], 'sources': bindings}
    def save():
        (args.output / 'measurement.json').write_text(json.dumps(report, indent=2) + '\n')
    def command(label, argv):
        result = subprocess.run(list(map(str, argv)), cwd=repo, capture_output=True)
        for channel in ('stdout', 'stderr'):
            (args.output / (label + '.' + channel + '.log')).write_bytes(getattr(result, channel))
        report['events'].append({'label': label, 'argv': list(map(str, argv)), 'exit': result.returncode,
            'stdout_sha256': sha(result.stdout), 'stderr_sha256': sha(result.stderr)})
        save()
        return result
    def config(label, name=None):
        source = str(copies[name]) if name == cpp else ''
        inc = str(shadow.parent) if name and name != cpp else ''
        result = command(label, ['cmake', '-S', repo, '-B', args.build, '-G', 'Ninja',
            '-DCMAKE_BUILD_TYPE=Release',
            '-DCMAKE_PROJECT_TOS_INCLUDE=' + str(repo / 'crypto/test/workchain-construction-isolation.cmake'),
            '-DCONSTRUCTION_ISOLATION_SOURCE=' + source, '-DCONSTRUCTION_ISOLATION_HEADER_DIR=' + inc,
            '-DTOS_UNO_CRYPTO_PROTOTYPE_TESTS=OFF'])
        assert result.returncode == 0, 'configure failed: ' + label
    def build(label):
        result = command(label, ['cmake', '--build', args.build, '--target', 'test-workchain-construction-isolation', '-j32'])
        assert result.returncode == 0, 'build failure is not behavior evidence: ' + label
    def deps(label, name=None):
        obj = 'CMakeFiles/test-workchain-construction-isolation.dir/'
        obj += str(copies[cpp]).lstrip('/') + '.o' if name == cpp else 'crypto/test/' + cpp + '.o'
        result = command(label, ['ninja', '-C', args.build, '-t', 'deps', obj])
        assert result.returncode == 0
        text = result.stdout.decode()
        for header in names[1:]:
            expected = copies[header] if name == header else repo / bindings[header]['path']
            assert str(expected) in text, 'missing actual dependency: ' + str(expected)
            if name != header:
                assert str(copies[header]) not in text, 'shadow leaked into normal build'
    def check_oracles():
        for name, digest in report['oracle_sha256'].items():
            assert sha((oracle / name).read_bytes()) == digest, 'oracle drift: ' + name
    def runs(label, cases, expected):
        for case in cases:
            check_oracles()
            result = command(label + '-' + str(case), [args.build / 'test-workchain-construction-isolation', case, oracle])
            check_oracles()
            assert result.returncode == expected, f'{label}/{case}: expected {expected}, got {result.returncode}'
            if expected == 82:
                observation = json.loads(result.stdout)
                assert observation['intermediate_state'] == 1 and observation['intermediate_messages'] == 1
                assert observation['final_state_changed'] == 1 and observation['final_messages_changed'] == 1
            if expected in (101, 102):
                observation = json.loads(result.stdout)
                assert observation['final_state_changed'] == 0 and observation['final_messages_changed'] == 0
                assert observation['final_snapshot_identity_changed'] == 1
                assert observation['intermediate_snapshot_identity'] == (1 if expected == 102 else 0)
    config('baseline-configure')
    build('baseline-build')
    deps('baseline-dependencies')
    frozen = command('freeze-oracles', [args.build / 'test-workchain-construction-isolation', 'freeze', oracle])
    assert frozen.returncode == 0
    report['oracle_sha256'] = {f.name: sha(f.read_bytes()) for f in sorted(oracle.iterdir())}
    assert set(report['oracle_sha256']) == {'before.state', 'before.messages', 'after.state', 'after.messages'}
    runs('baseline', range(34), 0)
    controls = [
        ('direct-live-stage', core,
         'auto status = observe_workchain_construction(observer, point.stage, point.occurrence);',
         'if (point.stage == WorkchainConstructionStage::ValueFlowFreeze) current_ = std::make_shared<const WorkchainCandidateContents>(draft);\n'
         '      auto status = observe_workchain_construction(observer, point.stage, point.occurrence);', [18], 82),
        ('direct-live-before-install', core,
         'TRY_STATUS(checkpoint({WorkchainConstructionStage::BeforeCandidateInstall, 0}));',
         'current_ = next;\n    TRY_STATUS(checkpoint({WorkchainConstructionStage::BeforeCandidateInstall, 0}));', [23], 82),
        ('install-after-builder-failure', core, 'TRY_STATUS(build(*before, draft, checkpoint));',
         'auto failed = build(*before, draft, checkpoint);\n    if (failed.is_error()) { current_ = std::make_shared<const WorkchainCandidateContents>(draft); return failed; }', [18], 83),
        ('omit-successful-install', core, 'current_ = std::move(next);', '(void)next;', [0], 86),
        ('omit-successful-messages', core,
         'auto next = std::make_shared<const WorkchainCandidateContents>(draft);',
         'draft.pending_messages = before->pending_messages;\n    auto next = std::make_shared<const WorkchainCandidateContents>(draft);', [0], 87),
        ('forget-observed-failure', core, 'if (status.is_error()) observed_failure = status.clone();', '(void)status;', [25], 94),
        ('omit-predecessor-check', core,
         'if (current_ != expected_predecessor) return td::Status::Error("candidate predecessor differs from prepared input");',
         '(void)expected_predecessor;', [26], 95),
        ('allow-reentrant-construction', core,
         'if (constructing_) return td::Status::Error("candidate construction is already active");',
         '(void)constructing_;', [27], 96),
        ('normalize-submitted-count', core,
         'auto next = std::make_shared<const WorkchainCandidateContents>(draft);',
         'draft.committed_batch_count = 1;\n    auto next = std::make_shared<const WorkchainCandidateContents>(draft);', [28], 97),
        ('retain-mutable-message-alias', core, 'const std::vector<NewOutMsg> messages_;',
         'const std::vector<NewOutMsg>& messages_;', [29], 98),
        ('omit-root-presence', core, 'if (root.is_null())', 'if (false)', [30], 99),
        ('omit-message-identity-presence', core, 'if (draft.batch_identity.is_null() || !draft.pending_messages)',
         'if (false)', [31, 32], 103),
        ('leave-construction-active', core, '~Reset() { value = false; }', '~Reset() {}', [24], 100),
        ('omit-state-observation', cpp, 'state_seen |= observe_state()!=oracle_before_state;', '(void)observe_state;', [0], 75),
        ('omit-message-observation', cpp, 'messages_seen |= observe_messages()!=oracle_before_messages;', '(void)observe_messages;', [0], 74),
        ('alter-before-oracle-reader', cpp, 'const auto oracle_before_state=read(dir+"/before.state");',
         'const auto oracle_before_state=read(dir+"/before.state")+"drift";', [0], 90),
    ]
    controls.extend([
        ('replace-live-snapshot-with-identical-bytes', core,
         'auto status = observe_workchain_construction(observer, point.stage, point.occurrence);',
         'if (point.stage == WorkchainConstructionStage::ParticipantFinalize) current_ = std::make_shared<const WorkchainCandidateContents>(*before);\n'
         '      auto status = observe_workchain_construction(observer, point.stage, point.occurrence);', [1], 102),
        ('replace-failed-snapshot-with-identical-bytes', core, 'TRY_STATUS(build(*before, draft, checkpoint));',
         'auto failed = build(*before, draft, checkpoint);\n    if (failed.is_error()) { current_ = std::make_shared<const WorkchainCandidateContents>(draft); return failed; }', [1], 101),
        ('ignore-ordinary-builder-failure', core, 'TRY_STATUS(build(*before, draft, checkpoint));',
         'auto ignored = build(*before, draft, checkpoint); (void)ignored;', [33], 71),
    ])
    for stage in ('ParticipantFinalize', 'AccountBlockStage', 'AccountRootStage'):
        controls.append(('omit-' + stage, payout,
            f'TRY_STATUS(observe_workchain_construction(observer, WorkchainConstructionStage::{stage}, i));',
            '(void)observer;', [0], 76))
    controls.append(('omit-inbound-stage', imports,
        'TRY_STATUS(observe_workchain_construction(observer, WorkchainConstructionStage::InboundStage,\n'
        '        static_cast<std::size_t>(&root - envelopes.data())));', '(void)observer;', [0], 76))
    for stage in ('OutboundDescriptorStage', 'OutboundQueueStage'):
        controls.append(('omit-' + stage, queue,
            f'TRY_STATUS(observe_workchain_construction(observer, WorkchainConstructionStage::{stage},\n'
            '        static_cast<std::size_t>(&item - outputs.data())));', '(void)observer;', [0], 76))
    for stage in ('ValueFlowFreeze', 'CoverageFreeze', 'ShardUpdateBuild', 'FinalBudgetCheck'):
        controls.append(('omit-' + stage, cpp, f'TRY_STATUS(probe({{Stage::{stage},0}}));',
            '(void)probe;', [0], 76))
    for label, name, before, after, cases, expected in controls:
        data = originals[name]
        old, new = before.encode(), after.encode()
        assert data.count(old) == 1, 'nonunique source anchor: ' + label
        mutant = data.replace(old, new)
        control = {'label': label, 'committed_source': bindings[name], 'from': before, 'to': after,
            'offset': data.index(old), 'original_sha256': sha(data), 'copy_before_sha256': sha(data),
            'mutant_sha256': sha(mutant), 'cases': cases, 'expected_exit': expected}
        report['controls'].append(control)
        copies[name].write_bytes(data)
        assert copies[name].read_bytes() == subprocess.check_output(['git', 'show', commit + ':' + bindings[name]['path']], cwd=repo)
        copies[name].write_bytes(mutant)
        try:
            config(label + '-configure', name)
            build(label + '-build')
            control['compiled'] = True
            deps(label + '-dependencies', name)
            runs(label, cases, expected)
            control['behavior_confirmed'] = True
        finally:
            copies[name].write_bytes(data)
            restored = copies[name].read_bytes()
            control['restored_sha256'] = sha(restored)
            control['restore_audit_sha256'] = sha(restored.replace(old, new))
            assert restored == data and control['restore_audit_sha256'] == control['mutant_sha256']
            copies[name].unlink()
            control['copy_discarded'] = not copies[name].exists()
            assert (repo / bindings[name]['path']).read_bytes() == data
            save()
        config(label + '-restored-configure')
        build(label + '-restored-build')
        deps(label + '-restored-dependencies')
        runs(label + '-restored', cases, 0)
        print('restored:', label, flush=True)
    runs('final', range(34), 0)
    missing = command('missing-oracle-dependency', [args.build / 'test-workchain-construction-isolation', 0, args.work / 'absent'])
    assert missing.returncode == 92
    check_oracles()
    assert all((repo / bindings[name]['path']).read_bytes() == originals[name] for name in names)
    report['original_source_files_unchanged'] = True
    report['complete'] = True
    save()
    print(f'PASS: 34 private cases, {len(controls)} isolated controls; coordinator review pending')


if __name__ == '__main__':
    main()
