import hashlib
import json
import pathlib
import subprocess
import sys

record = json.loads(pathlib.Path('/home/tomi/tos-m2/doc/measurements/uno-m1-disposal-predecessor/measurement.json').read_text())
argv = record['events'][-1]['argv']
binary = pathlib.Path(argv[0])
assert hashlib.sha256(binary.read_bytes()).hexdigest() == record['binary_sha256']
mode = sys.argv[1]
symbols = subprocess.check_output(['nm', str(binary)], text=True)
symbol = next(line.split()[-1] for line in symbols.splitlines()
              if line.split()[-1].startswith('_ZN5block30plan_workchain_native_disposal')
              and ' W ' in line and not line.split()[-1].endswith('Ev'))
command = ['gdb', '-q', '-batch', '-ex', 'set pagination off',
           '-ex', 'break *' + symbol + '+0x82', '-ex', 'run',
           '-ex', 'printf "OBSERVED_STD_FIRST_FRAC=%u MC_FIRST_FRAC=%u\\n", *(unsigned int*)($r14+0x24), *(unsigned int*)($r14+0x4c)',
           '-ex', 'x/2i $pc']
if mode == 'initialize':
    command += ['-ex', 'set $uninitialized = *(unsigned int*)($r14+0x4c)',
                '-ex', 'set *(unsigned int*)($r14+0x4c) = 0',
                '-ex', 'delete 1', '-ex', 'python exec(' + repr(
                    'class Repair(gdb.Breakpoint):\n'
                    ' def stop(self):\n'
                    '  if int(gdb.parse_and_eval("*(unsigned int*)($r14+0x4c)")) == int(gdb.parse_and_eval("$uninitialized")):\n'
                    '   gdb.write("REPLACE_SAME_UNINITIALIZED_COPY\\n")\n'
                    '   gdb.execute("set *(unsigned int*)($r14+0x4c) = 0")\n'
                    '  return False\n'
                    'Repair("*' + symbol + '+0x82")') + ')']
else:
    command += ['-ex', 'disable 1']
command += ['-ex', 'continue', '--args'] + argv
result = subprocess.run(command, capture_output=True)
for stream in ('stdout', 'stderr'):
    pathlib.Path('/tmp/uno-disposal-gdb-' + mode + '.' + stream + '.log').write_bytes(getattr(result, stream))
print(result.stdout.decode()[-4500:])
print(result.stderr.decode()[-1800:])
assert hashlib.sha256(binary.read_bytes()).hexdigest() == record['binary_sha256']
