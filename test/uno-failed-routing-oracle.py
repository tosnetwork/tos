#!/usr/bin/env python3
"""Partial Failed oracle control: accepted Native fee routing, not all eleven contracts.

Observation: actual accepted custody/coordinator balances and transaction fees.
Path: real prepare -> wc0 rich bounce -> registered Failed producer + validator.
Only FAILED_COST_ROUTING is removed in a temporary test-source copy. The real
producer mutation remains. Shared source and B's contract are never edited.
"""
import argparse
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True, type=Path)
    args = parser.parse_args()
    build = args.build.resolve()
    repo = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='uno-failed-routing-oracle-'))
    print(f'EVIDENCE_DIRECTORY:{work}', flush=True)
    source = repo / 'test/test-m3-live.cpp'
    entries = json.loads((build / 'compile_commands.json').read_text())
    entries = [e for e in entries if Path(e['file']).resolve() == source]
    if len(entries) != 1:
        raise RuntimeError('expected exactly one live compilation command')
    shadow = work / 'test'
    shutil.copytree(repo / 'test', shadow)
    header = shadow / 'm5-live-failed.h'
    original = header.read_text()
    start = original.index('  if (!correct_routing)\n')
    end = original.index('  CHECK(correct_routing);', start) + len('  CHECK(correct_routing);')
    header.write_text(original[:start] + '  (void)correct_routing; // isolated oracle removal' + original[end:])
    command = shlex.split(entries[0]['command'])
    obj = work / 'oracle-removed.o'
    command[command.index(str(source))] = str(shadow / source.name)
    command[command.index('-o') + 1] = str(obj)
    with (work / 'build.log').open('w') as log:
        subprocess.run(command, cwd=build, stdout=log, stderr=log, check=True)
        link = subprocess.check_output(['ninja', '-t', 'commands', 'test-m3-live'], cwd=build, text=True).splitlines()[-1]
        tokens = shlex.split(link)
        if tokens[:2] != [':', '&&'] or tokens[-2:] != ['&&', ':']:
            raise RuntimeError('unrecognized live link command')
        tokens = tokens[2:-2]
        old_obj = 'CMakeFiles/test-m3-live.dir/test/test-m3-live.cpp.o'
        if tokens.count(old_obj) != 1:
            raise RuntimeError('live object missing from link command')
        tokens[tokens.index(old_obj)] = str(obj)
        binary = work / 'oracle-removed'
        tokens[tokens.index('-o') + 1] = str(binary)
        subprocess.run(tokens, cwd=build, stdout=log, stderr=log, check=True)
    for label, extra, expected in (
            ('enabled', [], 0),
            ('removed', ['--failed-routing-binary', str(binary)], 1),
            ('restored', [], 0)):
        with (work / f'{label}.log').open('w') as log:
            result = subprocess.run(['python3', str(repo / 'test/uno-m3-live.py'),
                                     '--build', str(build), '--failed-routing-probe', *extra],
                                    stdout=log, stderr=log)
        output = (work / f'{label}.log').read_text()
        if result.returncode != expected or 'FAILED_ROUTING_PROBE' not in output:
            raise RuntimeError(f'{label}: designated path missing or wrong exit {result.returncode}')
        if label == 'removed':
            if 'FAILED_ORACLE_MISSING:FAILED_COST_ROUTING' not in output or 'exit=0' not in output:
                raise RuntimeError('oracle removal failed for an unrelated reason')
        print(f'{label}: driver exit={result.returncode}', flush=True)
    print('FAILED_ORACLE_PARTIAL:FAILED_COST_ROUTING; full oracle-control NOT_READY')


if __name__ == '__main__':
    main()
