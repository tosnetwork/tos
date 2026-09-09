#!/usr/bin/env python3
"""Remove only the Counter business predicate in a committed-source copy."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--build', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
a = p.parse_args()
repo = Path(__file__).resolve().parents[2]
build = a.build.resolve()
a.out.mkdir(parents=True, exist_ok=False)
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
source = 'crypto/test/workchain-counter-engine.h'
translation = 'crypto/test/test-workchain-block.cpp'
original = subprocess.check_output(['git', 'show', f'{commit}:{source}'], cwd=repo)
unit = subprocess.check_output(['git', 'show', f'{commit}:{translation}'], cwd=repo)
assert (repo / source).read_bytes() == original and (repo / translation).read_bytes() == unit
before = 'if (shell.parameters->get_hash() != vm::CellBuilder().finalize()->get_hash()) {'
after = 'if (false && shell.parameters->get_hash() != vm::CellBuilder().finalize()->get_hash()) {'
assert original.count(before.encode()) == 1
mutant = original.replace(before.encode(), after.encode())
sha = lambda b: hashlib.sha256(b).hexdigest()
def run(name, cmd, cwd=build):
    r = subprocess.run(list(map(str, cmd)), cwd=cwd, capture_output=True)
    (a.out / (name + '.stdout.log')).write_bytes(r.stdout)
    (a.out / (name + '.stderr.log')).write_bytes(r.stderr)
    return r
baseline = run('baseline', [build / 'test-workchain-block', '--filter', 'CounterConfigurationEnvelope'])
assert baseline.returncode == 0 and b'1 test(s) passed' in baseline.stdout + baseline.stderr
with tempfile.TemporaryDirectory(prefix='uno-business-copy-') as temporary:
    temp = Path(temporary)
    header = temp / Path(source).name
    cpp = temp / Path(translation).name
    header.write_bytes(original)
    assert header.read_bytes() == original
    cpp.write_bytes(unit)
    header.write_bytes(mutant)
    entry = next(e for e in json.loads((build / 'compile_commands.json').read_text()) if Path(e['file']) == repo / translation)
    command = shlex.split(entry['command'])
    old_object = command[command.index('-o') + 1]
    obj = temp / Path(old_object).name
    command[command.index('-o') + 1] = str(obj)
    command = [str(cpp) if x == str(repo / translation) else x for x in command]
    command += ['-I', str((repo / source).parent)]
    assert run('compile', command, Path(entry['directory'])).returncode == 0
    line = subprocess.check_output(['ninja', '-C', str(build), '-t', 'commands', 'test-workchain-block'], text=True).splitlines()[-1]
    tokens = shlex.split(line)
    assert tokens[:2] == [':', '&&'] and tokens[-2:] == ['&&', ':']
    link = tokens[2:-2]
    binary = temp / 'test-workchain-block'
    link[link.index('-o') + 1] = str(binary)
    assert old_object in link
    link = [str(obj) if x == old_object else x for x in link]
    assert run('link', link).returncode == 0
    failed = run('mutant', [binary, '--filter', 'CounterConfigurationEnvelope'])
    assert failed.returncode != 0 and b'1127' in failed.stdout + failed.stderr
    header.write_bytes(original)
    restored = header.read_bytes()
    assert restored == original and sha(restored.replace(before.encode(), after.encode())) == sha(mutant)
    report = {'commit': commit, 'source': source, 'translation_unit': translation, 'translation_unit_sha256': sha(unit),
              'from': before, 'to': after, 'original_sha256': sha(original), 'copy_before_sha256': sha(original),
              'mutant_sha256': sha(mutant), 'restored_sha256': sha(restored),
              'restore_audit_sha256': sha(restored.replace(before.encode(), after.encode())),
              'compile_command': command, 'link_command': link, 'failure_identity': 1127,
              'scope': 'Valid framing is asserted before the nonempty business rejection. The baseline reads the real header; only the measurement binary reads the copy.'}
restore = ['cmake', '--build', build, '--target', 'test-workchain-block', '-j32']
assert run('explicit-restored-target', restore).returncode == 0
assert run('restored', [build / 'test-workchain-block', '--filter', 'CounterConfigurationEnvelope']).returncode == 0
report['restored_target_command'] = list(map(str, restore))
report['source_unchanged'] = (repo / source).read_bytes() == original and (repo / translation).read_bytes() == unit
assert report['source_unchanged']
(a.out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: isolated nonempty-business predicate control 1127')
