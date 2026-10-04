#!/usr/bin/env python3
"""Require version-boundary regressions to detect early and late activation."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]

def run(command, output):
    with output.open('w') as stream:
        result = subprocess.run([str(x) for x in command], cwd=ROOT,
                                stdout=stream, stderr=subprocess.STDOUT)
    return result.returncode, output.read_text()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--scenarios', type=Path, required=True)
    parser.add_argument('--rust-results', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build, out = args.build.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    targets = ['test-poseidon2', 'test-pq-falcon512-parity']
    headers = {name: (ROOT / name).read_text() for name in
               ['crypto/vm/poseidon2ops.h', 'crypto/vm/pqops.h']}
    cases = [
        ('path7', 'crypto/vm/poseidon2ops.h', 'poseidon2_path7_min_version',
         'PATH7 was accepted before version 16', 'PATH7 must reach operand validation at version 16'),
        ('poseidon2', 'crypto/vm/poseidon2ops.h', 'poseidon2_min_version',
         'was accepted at version 15', 'an opcode was refused at version 16'),
        ('falcon', 'crypto/vm/pqops.h', 'pq_falcon512_min_version',
         'execution divergence', 'execution divergence'),
    ]
    reports = []
    def compile(label):
        code, _ = run(['cmake', '--build', build, '--target', *targets, '-j', '4'],
                      out / (label + '-build.log'))
        if code:
            raise RuntimeError('build failed; this is not mutation evidence: ' + label)
    def check_falcon(label):
        result_path = out / (label + '-cpp.tsv')
        code, _ = run([build / 'crypto/pq/test-pq-falcon512-parity', args.scenarios.resolve()], result_path)
        if code:
            raise RuntimeError('parity driver failed before comparison')
        return run([sys.executable, ROOT / 'test/pq-falcon512/compare.py',
                    args.scenarios.resolve(), result_path, args.rust_results.resolve(),
                    '--out', out / (label + '-parity.json')], out / (label + '.log'))
    try:
        for name, header, constant, early_failure, late_failure in cases:
            for version, expected in [(15, early_failure), (17, late_failure)]:
                label = name + '-' + str(version)
                path = ROOT / header
                needle = constant + ' = 16'
                if headers[header].count(needle) != 1:
                    raise RuntimeError('mutation anchor must occur once')
                path.write_text(headers[header].replace(needle, constant + ' = ' + str(version)))
                compile(label)
                if name == 'falcon':
                    code, log = check_falcon(label)
                else:
                    code, log = run([build / 'crypto/test-poseidon2'], out / (label + '.log'))
                if code == 0 or expected not in log:
                    raise RuntimeError('mutation did not trip the intended assertion: ' + label)
                reports.append({'mutation': label, 'detected': True, 'exit': code,
                                'assertion': expected})
                path.write_text(headers[header])
    finally:
        for name, text in headers.items():
            (ROOT / name).write_text(text)
        compile('restored')
    code, _ = run([build / 'crypto/test-poseidon2'], out / 'restored-poseidon2.log')
    if code:
        raise RuntimeError('restored Poseidon2 baseline is not green')
    code, _ = check_falcon('restored-falcon')
    if code:
        raise RuntimeError('restored Falcon baseline is not green')
    result = {'passed': True, 'mutations': reports, 'restored_green': True}
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))

if __name__ == '__main__':
    main()
