import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

repo = Path('/home/tomi/tos')
build = Path('/tmp/uno-coverage-build')
out = Path(tempfile.mkdtemp(prefix='uno-coverage-controls-'))
header = 'crypto/block/workchain-coverage.h'
phase = 'crypto/block/workchain-read-phase.h'
test = 'crypto/test/test-workchain-coverage.cpp'
driver = 'crypto/test/workchain-coverage.py'
files = [header, phase, test, driver, 'crypto/test/workchain-coverage.cmake']
original = {name: (repo / name).read_bytes() for name in files}
sha = lambda data: hashlib.sha256(data).hexdigest()
records = []

def command(name, argv):
    result = subprocess.run(argv, cwd=repo, capture_output=True)
    (out / (name + '.stdout.log')).write_bytes(result.stdout)
    (out / (name + '.stderr.log')).write_bytes(result.stderr)
    return result

def patch(path, before, after):
    current = (repo / path).read_text()
    if current.count(before) != 1:
        raise RuntimeError('patch source count differs')
    changed = current.replace(before, after)
    text = '*** Begin Patch\n*** Update File: ' + str(repo / path) + '\n@@\n'
    text += ''.join('-' + line + '\n' for line in current.splitlines())
    text += ''.join('+' + line + '\n' for line in changed.splitlines())
    text += '*** End Patch\n'
    result = subprocess.run(['apply_patch'], input=text.encode(), capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr.decode())

controls = [
    ('delta-comparison', header, 'if (delta != writes) return failure(WorkchainCoverageReason::DeltaMismatch);',
     'if (false) return failure(WorkchainCoverageReason::DeltaMismatch);', 'coverage.delta_isolated', []),
    ('participant-comparison', header, 'if (participants != writes) return failure(WorkchainCoverageReason::ParticipantMismatch);',
     'if (false) return failure(WorkchainCoverageReason::ParticipantMismatch);', 'coverage.participant_isolated', []),
    ('later-subtree', header,
     'delta(old.child(true, before), next.child(true, after), before, after, depth + 1, key, limit, keys);',
     '(void)after; // controlled omission of the right subtree', 'delta.later_isolated', ['later']),
    ('whole-entry', header, '!old.whole_value->contents_equal(*next.whole_value)',
     '!(old.whole_value->prefetch_ulong(5) == next.whole_value->prefetch_ulong(5) && old.value->prefetch_ref()->get_hash() == next.value->prefetch_ref()->get_hash())', 'delta.metadata.exact', []),
    ('leaf-augmentation', header, '!old.whole_value->contents_equal(*next.whole_value)',
     '!old.value->contents_equal(*next.value)', 'delta.includes_leaf_extra', []),
    ('key-bound', header, 'if (keys.size() >= limit) {', 'if (false) {', 'delta.bound.before_append', []),
    ('participants-later', header,
     'participants(edge.child(true, reader), reader, depth + 1, key, limit, keys);',
     '(void)reader; // controlled omission of a later physical participant', 'participants.physical_later_account', []),
    ('pruned-source', header,
     '          fail(source == WorkchainCoverageSource::ReceivedCandidate ? object : WorkchainCoverageObject::AuthenticatedState,\n               WorkchainCoverageReason::ForbiddenPruning);',
     '          fail(object,\n               WorkchainCoverageReason::ForbiddenPruning);', 'delta.pruned.source', []),
    ('acquired-claim', header,
     'compare_workchain_coverage(changed, participants, writes, object)',
     'compare_workchain_coverage(changed, participants, writes, source == WorkchainCoverageSource::AcquiredView ? WorkchainCoverageObject::HostRebuilt : object)',
     'final_audit.late_mutation', []),
    ('provider-provenance', header,
     'throw Stop{{WorkchainBatchScanDisposition::LocalUnavailable, reason}};',
     'throw Stop{{WorkchainBatchScanDisposition::CandidateInvalid, reason}};', 'provider.local_not_candidate', []),
    ('footprint', phase, '!cell.get_tree_node().empty() || !admitted.count(cell.get_hash())',
     '!cell.get_tree_node().empty() /* footprint omitted */', 'phase.swallowed_sticky', []),
    ('sticky', phase, 'if (forbidden) return {WorkchainReadPhaseReason::OutsideFootprint, std::move(status), attempts};',
     'if (false) return {WorkchainReadPhaseReason::OutsideFootprint, std::move(status), attempts};', 'phase.swallowed_sticky', []),
    ('message-only', phase, 'if (status.is_error()) return {WorkchainReadPhaseReason::CallbackFailure, std::move(status), attempts};',
     'if (status.code() != 0) return {WorkchainReadPhaseReason::CallbackFailure, std::move(status), attempts};', 'phase.message_only_error', []),
    ('callback-exception', phase, 'exception = true;', 'exception = false; // omit callback failure', 'phase.exception', []),
    ('proof-tracking', test, 'auto selected = observed.prefetch_ref(0);',
     'auto selected = observation ? left : observed.prefetch_ref(0);', 'proof.observation_bytes_equal', []),
    ('proof-tracking-both', test, 'auto tracked = vm::UsageCell::create(root, tree->root_ptr());',
     'auto tracked = root;', 'proof.used_path_present', []),
    ('completion-marker', test, 'std::cout << "coverage.completed\\n";',
     'std::cout << "";', 'incomplete coverage:', None),
    ('registered-driver', driver, 'def main():', 'def main():\n    raise RuntimeError("forced registered driver failure")',
     'forced registered driver failure', None),
]

if len(sys.argv) == 2:
    controls = controls[next(i for i, item in enumerate(controls) if item[0] == sys.argv[1]):]
for name, path, before, after, _, _ in controls:
    if original[path].decode().count(before) != 1 or after in original[path].decode():
        raise RuntimeError('nonunique mutation before any edit: ' + name)

try:
    for name, path, before, after, expected, args in controls:
        raw = original[path]
        if raw.decode().count(before) != 1 or after in raw.decode():
            raise RuntimeError('nonunique mutation: ' + name)
        mutant = raw.decode().replace(before, after).encode()
        patch(path, before, after)
        try:
            if (repo / path).read_bytes() != mutant:
                raise RuntimeError('mutant bytes differ: ' + name)
            built = command(name + '.compile', ['cmake', '--build', str(build), '--target', 'test-workchain-coverage', '-j32'])
            if built.returncode:
                raise RuntimeError('compilation failure is not behavioral evidence: ' + name)
            binary_hash = sha((build / 'test-workchain-coverage').read_bytes())
            if args is None:
                argv = ['ctest', '--test-dir', str(build), '-R', '^test-workchain-coverage-gates$', '--output-on-failure',
                        '--output-junit', str(out / (name + '.xml'))]
            else:
                argv = [str(build / 'test-workchain-coverage')] + args
            run = command(name + '.run', argv)
            if run.returncode == 0 or expected.encode() not in run.stdout + run.stderr:
                raise RuntimeError('wrong or absent failure: ' + name)
            if args is None:
                import xml.etree.ElementTree as ET
                tests = list(ET.parse(out / (name + '.xml')).iter('testcase'))
                if len(tests) != 1 or tests[0].get('status') != 'fail' or tests[0].find('failure') is None:
                    raise RuntimeError('not a real CTest failure: ' + name)
            record = dict(name=name, path=path, before=before, after=after,
                          original_sha256=sha(raw), recorded_mutant_sha256=sha((repo / path).read_bytes()),
                          reconstructed_mutant_sha256=sha(mutant), mutant_binary_sha256=binary_hash,
                          expected_assertion=expected, exit_code=run.returncode, argv=argv)
        finally:
            patch(path, after, before)
            if any((repo / f).read_bytes() != data for f, data in original.items()):
                raise RuntimeError('restoration mismatch')
            restored = command(name + '.restore-build', ['cmake', '--build', str(build), '--target', 'test-workchain-coverage', '-j32'])
            if restored.returncode:
                raise RuntimeError('restored build failed: ' + name)
            positive = command(name + '.restored-run', [str(build / 'test-workchain-coverage')])
            if positive.returncode or positive.stdout != b'coverage.completed\n':
                raise RuntimeError('restored positive failed: ' + name)
        record['restored_sha256'] = sha((repo / path).read_bytes())
        record['restored_binary_sha256'] = sha((build / 'test-workchain-coverage').read_bytes())
        record['explicit_rebuild_targets'] = ['test-workchain-coverage']
        records.append(record)
        (out / 'records.json').write_text(json.dumps(records, indent=2) + '\n')
        print(name + ': behavioral failure and byte-exact restored pass', flush=True)
finally:
    (out / 'source-hashes.json').write_text(json.dumps({f: sha(raw) for f, raw in original.items()}, indent=2) + '\n')
    print('artifacts: ' + str(out), flush=True)
