import hashlib
import json
from pathlib import Path
import shlex
import subprocess
root = Path('/home/tomi/tos')
build = root / 'build'
out = Path('/tmp/uno-c1-wrap-control-20260909')
out.mkdir(exist_ok=False)
lines = subprocess.check_output(['ninja', '-t', 'commands', 'test-workchain-proof-backend'], cwd=build, text=True).splitlines()
lines = [line for line in lines if ' -o test-workchain-proof-backend ' in line]
assert len(lines) == 1
parts = shlex.split(lines[0])
assert parts[:2] == [':','&&'] and parts[-2:] == ['&&',':']
original = parts[2:-2]
position = original.index('--wrap=uno_crypto_verify_v2')
assert original[position-1] == '-Xlinker'
mutant = original[:position-1] + original[position+1:]
def run(command, name, cwd=build):
    with (out/name).open('w') as stream:
        result = subprocess.run(command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT)
    return result.returncode
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
record = {'production_source_sha256': {p: sha(root/p) for p in ['crypto/block/workchain-proof-work.h','crypto/block/workchain-proof-backend.cpp']},
          'test_source_sha256': sha(root/'crypto/test/test-workchain-proof-backend.cpp'), 'stages': []}
for stage, argv in [('baseline', original), ('without-wrap', mutant), ('restored', original)]:
    command = list(argv)
    executable = out/stage
    command[command.index('-o')+1] = str(executable)
    link_exit = run(command, stage+'-link.log')
    item = {'stage': stage, 'link_command': command, 'link_exit': link_exit}
    if link_exit == 0:
        item['binary_sha256'] = sha(executable)
        item['runtime_exit'] = run([str(executable),str(root/'uno/crypto/fixtures/balance-kernel-v2.txt')], stage+'-run.log')
    record['stages'].append(item)
    (out/'control.json').write_text(json.dumps(record,indent=2)+'\n')
    if stage != 'without-wrap':
        assert link_exit == 0 and item['runtime_exit'] == 0
    else:
        assert link_exit == 0, 'link failure is not the required runtime control'
        assert item['runtime_exit'] != 0, 'missing wrapper silently passed'
        assert 'real backend positive witness missing' in (out/(stage+'-run.log')).read_text()
assert record['stages'][0]['binary_sha256'] == record['stages'][2]['binary_sha256']
assert record['production_source_sha256'] == {p:sha(root/p) for p in record['production_source_sha256']}
print(json.dumps(record,indent=2))
