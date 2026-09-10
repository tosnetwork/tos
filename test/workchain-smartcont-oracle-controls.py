#!/usr/bin/env python3
"""Measure the registered regression oracle using an isolated interpreted fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import xml.etree.ElementTree as ET

p = argparse.ArgumentParser()
p.add_argument('--build', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
a = p.parse_args()
a.build = a.build.resolve()
a.out = a.out.resolve()
a.out.mkdir(parents=True, exist_ok=False)
repo = Path(__file__).resolve().parents[1]
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
sha = lambda b: hashlib.sha256(b).hexdigest()
report = {'commit': commit, 'commands': [], 'scope': 'An unchanged test translation unit is compiled at an isolated source path. Only the interpreted genesis fixture is mutated. The registered CTest arguments retain the regression oracle; output and answer paths are isolated.'}

def run(name, command, cwd=None, env=None):
    result = subprocess.run(command, cwd=cwd or a.build, env=env, capture_output=True)
    (a.out / (name + '.stdout.log')).write_bytes(result.stdout)
    (a.out / (name + '.stderr.log')).write_bytes(result.stderr)
    report['commands'].append({'name': name, 'argv': command, 'cwd': str(cwd or a.build), 'exit': result.returncode})
    (a.out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return result

source = 'crypto/smartcont/gen-zerostate.fif'
original = subprocess.check_output(['git', 'show', f'{commit}:{source}'], cwd=repo)
assert (repo/source).read_bytes() == original
before, after = b'16 capCreateStats', b'17 capCreateStats'
assert original.count(before) == 1
mutant = original.replace(before, after)
copy_root = a.out / 'source'
(copy_root/'crypto/test').mkdir(parents=True)
(copy_root/'crypto/smartcont').mkdir()
(copy_root/'test').symlink_to(repo/'test', target_is_directory=True)
(copy_root/'crypto/fift').symlink_to(repo/'crypto/fift', target_is_directory=True)
for entry in (repo/'crypto/smartcont').iterdir():
    target = copy_root/'crypto/smartcont'/entry.name
    if entry.name == 'gen-zerostate.fif':
        target.write_bytes(original)
    else:
        target.symlink_to(entry, target_is_directory=entry.is_dir())
cpp = 'crypto/test/test-smartcont.cpp'
cpp_bytes = subprocess.check_output(['git','show',f'{commit}:{cpp}'], cwd=repo)
assert (repo/cpp).read_bytes() == cpp_bytes
(copy_root/cpp).write_bytes(cpp_bytes)
report['translation_unit_sha256'] = sha(cpp_bytes)
entries = json.loads((a.build/'compile_commands.json').read_text())
entry = next(x for x in entries if Path(x['file']).resolve() == repo/cpp)
args = shlex.split(entry['command'])
args[args.index('-o')+1] = str(a.out/'smartcont.o')
args[args.index('-c')+1] = str(copy_root/cpp)
args.extend(['-I'+str(repo/'crypto/test')])
assert run('compile', args, Path(entry['directory'])).returncode == 0
link_line = subprocess.check_output(['ninja','-t','commands','test-smartcont'],cwd=a.build,text=True).splitlines()[-1]
link = shlex.split(link_line.split('&&')[1].strip())
obj = 'CMakeFiles/test-smartcont.dir/crypto/test/test-smartcont.cpp.o'
assert link.count(obj) == 1
link[link.index(obj)] = str(a.out/'smartcont.o')
link[link.index('-o')+1] = str(a.out/'test-smartcont')
assert run('link', link).returncode == 0
report['binary_sha256'] = sha((a.out/'test-smartcont').read_bytes())
registered = json.loads(subprocess.check_output(['ctest','--show-only=json-v1'],cwd=a.build))
command = next(t['command'] for t in registered['tests'] if t['name'] == 'test-smartcont')
assert command[command.index('--regression')+1] == str(repo/'test/regression-tests.ans')
report['registered_command'] = command
answers = a.out/'regression-tests.ans'
answers.write_bytes((repo/'test/regression-tests.ans').read_bytes())
report['answers_sha256'] = sha(answers.read_bytes())
command[0] = str(a.out/'test-smartcont')
command[command.index('--regression')+1] = str(answers)
# Preserve the registered selection and add a conjunctive filter for this calibration.
command.extend(['--filter','GenZerostateFiftRegression','--verbosity','0'])
ctest = a.out/'ctest'
ctest.mkdir()
quote = lambda s: '"'+s.replace('\\','\\\\').replace('"','\\"')+'"'
(ctest/'CTestTestfile.cmake').write_text('add_test(test-smartcont '+ ' '.join(map(quote,command))+')\n')
env = dict(os.environ, TOS_CREATE_STATE_BINARY=str(a.build/'crypto/create-state'))
ctest_command = ['ctest','-R','^test-smartcont$','--output-on-failure','--output-junit','result.xml']
def check(name, success):
    result = run(name, ctest_command, ctest, env)
    junit = (ctest/'result.xml').read_bytes()
    (a.out/(name+'.xml')).write_bytes(junit)
    cases = ET.fromstring(junit).findall('.//testcase')
    assert len(cases) == 1 and cases[0].find('skipped') is None
    assert (result.returncode == 0) == success
    assert (cases[0].find('failure') is None) == success

check('baseline', True)
fixture = copy_root/source
assert fixture.read_bytes() == original
fixture.write_bytes(mutant)
# The changed configuration must remain executable without the answer comparison.
plain = [str(a.out/'test-smartcont'),'--filter','GenZerostateFiftRegression','--verbosity','0']
assert run('mutant-without-oracle', plain, ctest, env).returncode == 0
check('mutant-with-oracle', False)
wa = answers.with_suffix('.cache')/'WA'
assert wa.is_file()
expected = next(line.split()[1] for line in answers.read_text().splitlines() if line.startswith('Test_Toslib_GenZerostateFiftRegression_default '))
assert sha(wa.read_bytes()) != expected
report['wrong_answer_sha256'] = sha(wa.read_bytes())
report['expected_answer_sha256'] = expected
fixture.write_bytes(original)
assert fixture.read_bytes() == original and (repo/source).read_bytes() == original
report['control'] = {'source': source, 'from': before.decode(), 'to': after.decode(), 'original_sha256': sha(original), 'copy_before_sha256': sha(original), 'mutant_sha256': sha(mutant), 'restored_sha256': sha(fixture.read_bytes()), 'restore_audit_sha256': sha(fixture.read_bytes().replace(before,after))}
check('restored', True)
# Fift is interpreted, but explicitly rebuild every native executable this test invokes.
assert run('restored-native-targets', ['cmake','--build',str(a.build),'--target','test-smartcont','create-state','-j32']).returncode == 0
report['restored_targets'] = ['test-smartcont', 'create-state']
(a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: valid changed genesis is green without oracle, failed CTest with oracle, restored green')
