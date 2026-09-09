#!/usr/bin/env python3
"""Reconstruct each declared mutant from repository bytes (or a specified commit)."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

directory = Path(__file__).resolve().parent
repository = directory.parents[2]
commit = sys.argv[1] if len(sys.argv) == 2 else None


def source(path):
    if commit is not None:
        return subprocess.check_output(['git', 'show', f'{commit}:{path}'], cwd=repository)
    return (repository / path).read_bytes()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(value, reason):
    if not value:
        raise ValueError(reason)


specs = json.loads((directory / 'spec.json').read_text())
require(len(specs) == 9, 'expected nine controls')
require({p.name for p in directory.iterdir() if p.is_dir() and p.name != 'final'} ==
        {s['id'] for s in specs}, 'orphan or missing control directory')
for spec in specs:
    evidence = directory / spec['id']
    record = json.loads((evidence / 'audit.json').read_text())
    original = source(spec['path'])
    before, after = spec['from'].encode(), spec['to'].encode()
    require(original.count(before) == 1 and original.count(after) == 0,
            f"{spec['id']}: unique original and absent mutant anchor required")
    require(sha(original) == record['original_sha256'] == record['restored_sha256'],
            f"{spec['id']}: original/restored hash mismatch")
    require(sha(original.replace(before, after, 1)) == record['recorded_mutant_sha256'] ==
            record['reconstructed_mutant_sha256'], f"{spec['id']}: mutant reconstruction mismatch")
    for path, expected in record['repository_source_hashes'].items():
        require(sha(source(path)) == expected, f'{path}: source changed')
    require(record['original_binary_sha256'] == record['restored_binary_sha256'],
            f"{spec['id']}: binary not restored")
    for phase in ('mutant', 'restored'):
        tests = list(ET.parse(evidence / (phase + '.xml')).iter('testcase'))
        failed = phase == 'mutant'
        require(len(tests) == 1 and tests[0].get('status') == ('fail' if failed else 'run'),
                f"{spec['id']}: wrong JUnit count/status")
        require(tests[0].find('skipped') is None and
                (tests[0].find('failure') is not None) == failed,
                f"{spec['id']}: skip or wrong result")
        if failed:
            require(spec['failure'] in ''.join(tests[0].itertext()),
                    f"{spec['id']}: missing failure identity")
    print(f"{spec['id']}: reconstructed and restored; actual Failed then passed")
