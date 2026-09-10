import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

repo = Path('/home/tomi/tos')
out = Path(tempfile.mkdtemp(prefix='uno-account-scope-controls-'))
paths = ['crypto/block/workchain-block-execution.h',
         'crypto/block/workchain-block-execution.cpp',
         'crypto/test/test-workchain-settlement-continuation.cpp']
original = {p: (repo / p).read_bytes() for p in paths}
sha = lambda data: hashlib.sha256(data).hexdigest()
build = ['cmake', '--build', 'build', '--target',
         'test-workchain-settlement-continuation', 'test-tos-collator', '-j32']
binary = repo / 'build/test-workchain-settlement-continuation'
patcher = subprocess.check_output(['which', 'apply_patch'], text=True).strip()
def run(command, name):
    with (out / (name + '.stdout')).open('wb') as stdout, (out / (name + '.stderr')).open('wb') as stderr:
        return subprocess.run(command, cwd=repo, stdout=stdout, stderr=stderr).returncode
def patch(before, after):
    body = '\n'.join('-' + line for line in before.splitlines()) + '\n'
    body += '\n'.join('+' + line for line in after.splitlines())
    subprocess.run([patcher], input='*** Begin Patch\n*** Update File: ' + str(repo / paths[1]) +
                   '\n@@\n' + body + '\n*** End Patch\n', text=True, check=True, capture_output=True)
controls = [
    ('singleton-fallback', '  if (scope != WorkchainExecutionScope::AccountBatch) {',
     '  if (scope == WorkchainExecutionScope::BlockTransition) {\n'
     '    return validate_workchain_candidate_scope(candidate.candidate(), scope);\n'
     '  }\n  if (scope != WorkchainExecutionScope::AccountBatch) {', 'scope.account_not_singleton'),
    ('missing-candidate', '  if (candidate.candidate().is_null()) {',
     '  if (false && candidate.candidate().is_null()) {', 'scope.missing_candidate'),
    ('missing-declarations', '  if (candidate.declarations().is_null()) {',
     '  if (false && candidate.declarations().is_null()) {', 'scope.missing_declarations')]
print(out, flush=True)
assert run([str(binary)], 'baseline') == 0
records = []
for name, before, after, assertion in controls:
    assert all((repo / p).read_bytes() == data for p, data in original.items())
    assert original[paths[1]].count(before.encode()) == 1
    record = dict(name=name, path=paths[1], before=before, after=after, expected_assertion=assertion,
                  base_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip(),
                  original_sha256={p: sha(data) for p, data in original.items()},
                  rebuild_command=build, actual_executables=[str(binary), str(repo / 'build/test-tos-collator')])
    try:
        patch(before, after)
        assert (repo / paths[1]).read_bytes() == original[paths[1]].replace(before.encode(), after.encode())
        record['mutant_sha256'] = sha((repo / paths[1]).read_bytes())
        record['build_exit'] = run(build, name + '.build')
        assert record['build_exit'] == 0
        record['mutant_binary_sha256'] = sha(binary.read_bytes())
        record['run_exit'] = run([str(binary)], name + '.run')
        assert record['run_exit'] == 1
        assert (out / (name + '.run.stderr')).read_text().strip() == assertion
    finally:
        if (repo / paths[1]).read_bytes() != original[paths[1]]:
            patch(after, before)
        assert all((repo / p).read_bytes() == data for p, data in original.items())
        record['restored_sha256'] = {p: sha((repo / p).read_bytes()) for p in paths}
        record['restore_build_exit'] = run(build, name + '.restore-build')
        assert record['restore_build_exit'] == 0
        record['restored_binary_sha256'] = sha(binary.read_bytes())
        record['restored_run_exit'] = run([str(binary)], name + '.restored-run')
        assert record['restored_run_exit'] == 0
        (out / (name + '.json')).write_text(json.dumps(record, indent=2) + '\n')
    records.append(record)
    print(name + ': exact assertion failed, source restored, both targets rebuilt, positive run passed', flush=True)
(out / 'restore-audit.json').write_text(json.dumps(records, indent=2) + '\n')
