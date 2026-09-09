import json
from pathlib import Path
import shlex
import subprocess
build = Path('/home/tomi/tos/build')
lines = subprocess.check_output(['ninja', '-t', 'commands', 'test-workchain-proof-contracts'], cwd=build, text=True).splitlines()
lines = [l for l in lines if ' -c ' in l and l.endswith('/crypto/test/test-workchain-proof-contracts.cpp')]
assert len(lines) == 1
command = shlex.split(lines[0])
for flag in ['-o', '-MF', '-MT']:
    index = command.index(flag)
    del command[index:index+2]
command.remove('-MD')
command.remove('-c')
command[-1] = '/tmp/uno-c1-private-access.cpp'
command += ['-fsyntax-only']
records = []
for define in [None, 'ATTEMPT_CONSTRUCTION', 'ATTEMPT_MINT', 'ATTEMPT_RAW_BACKEND']:
    label = define or 'positive'
    argv = command + ([] if define is None else ['-D' + define])
    log = Path('/tmp/uno-c1-' + label + '.log')
    with log.open('w') as f:
        result = subprocess.run(argv, cwd=build, stdout=f, stderr=subprocess.STDOUT)
    data = log.read_text()
    if define is None:
        assert result.returncode == 0, data
    else:
        assert result.returncode != 0 and 'private' in data, data
    records.append({'define': define, 'command': argv, 'exit': result.returncode, 'log': str(log)})
Path('/tmp/uno-c1-private-access-record.json').write_text(json.dumps(records, indent=2) + '\n')
print([(r['define'], r['exit']) for r in records])
