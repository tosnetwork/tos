#!/usr/bin/env python3
"""Reconstruct mutations from working bytes or an explicitly named commit."""
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
    return (subprocess.check_output(['git', 'show', f'{commit}:{path}'], cwd=repository)
            if commit is not None else (repository / path).read_bytes())


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(value, reason):
    if not value:
        raise ValueError(reason)


specs = json.loads((directory / 'spec.json').read_text())
require(len(specs) == 27, 'expected twenty-seven controls')
require({p.name for p in directory.iterdir() if p.is_dir() and p.name != 'final'} ==
        {s['id'] for s in specs}, 'orphan or missing control directory')
for spec in specs:
    evidence = directory / spec['id']
    record = json.loads((evidence / 'audit.json').read_text())
    original = source(spec['path'])
    before, after = spec['from'].encode(), spec['to'].encode()
    require(original.count(before) == 1 and original.count(after) == 0, f"{spec['id']}: anchors")
    require(sha(original) == record['original_sha256'] == record['restored_sha256'],
            f"{spec['id']}: original/restored mismatch")
    require(sha(original.replace(before, after, 1)) == record['recorded_mutant_sha256'] ==
            record['reconstructed_mutant_sha256'], f"{spec['id']}: mutation mismatch")
    for path, expected in record['repository_source_hashes'].items():
        require(sha(source(path)) == expected, f'{path}: source changed')
    require(record['original_binary_sha256'] == record['restored_binary_sha256'],
            f"{spec['id']}: restored binary differs")
    if spec['path'] != 'crypto/test/workchain-batch-scan.py':
        require(record['mutant_binary_sha256'] != record['original_binary_sha256'],
                f"{spec['id']}: changed source absent from binary")
    for phase in ('original', 'mutant', 'restored'):
        tests = list(ET.parse(evidence / (phase + '.xml')).iter('testcase'))
        failed = phase == 'mutant'
        require(len(tests) == 1 and tests[0].get('status') == ('fail' if failed else 'run'),
                f"{spec['id']}: wrong JUnit count/status")
        require(tests[0].find('skipped') is None and
                (tests[0].find('failure') is not None) == failed, f"{spec['id']}: skip/wrong result")
        if failed:
            require(spec['failure'] in ''.join(tests[0].itertext()), f"{spec['id']}: failure identity")
    print(f"{spec['id']}: reconstructed mutant, exact restore, explicit rebuild and Failed/pass")

compiled = json.loads((directory / 'final/source-required.json').read_text())
header = source('crypto/block/workchain-batch-scan.h')
require(sha(header) == compiled['header_sha256'] == compiled['mutation']['restored_sha256'],
        'compile control: header/restore mismatch')
require(sha(source('crypto/test/test-workchain-batch-scan.cpp')) == compiled['test_sha256'],
        'compile control: test mismatch')
before = compiled['mutation']['from'].encode()
after = compiled['mutation']['to'].encode()
require(header.count(before) == 1 and header.count(after) == 0, 'compile control: anchors')
require(sha(header.replace(before, after, 1)) == compiled['mutation']['recorded_mutant_sha256'] ==
        compiled['mutation']['reconstructed_mutant_sha256'], 'compile control: mutant mismatch')
runs = compiled['runs']
require([r['name'] for r in runs] == ['source-explicit', 'source-omitted', 'default-original',
                                    'default-added', 'default-restored'], 'compile control: phases')
require([r['exit'] == 0 for r in runs] == [True, False, True, False, True],
        'compile control: results')
require('expected 4, have 3' in (directory / 'final/source-omitted.stderr.log').read_text(),
        'compile control: missing-argument diagnostic')
require('source.must_be_explicit' in (directory / 'final/default-added.stderr.log').read_text(),
        'compile control: default assertion diagnostic')
print('source-required: explicit/omitted and default-added/restored compile evidence verified')
