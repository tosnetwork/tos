#!/usr/bin/env python3
"""Reconstruct the five final source mutations without modifying the tree."""
import hashlib
import json
from pathlib import Path

here = Path(__file__).resolve().parent
repo = here.parents[2]
records = json.loads((here / 'final-controls/restore-audit.json').read_text())
assert len(records) == 5
sha = lambda data: hashlib.sha256(data).hexdigest()
for row in records:
    for path, expected in row['original_sha256'].items():
        assert sha((repo/path).read_bytes()) == expected, path
        assert row['restored_sha256'][path] == expected, path
    source = (repo/row['path']).read_bytes()
    before, after = row['before'].encode(), row['after'].encode()
    assert source.count(before) == 1 and source.count(after) == 0, row['name']
    assert sha(source.replace(before, after)) == row['mutant_sha256'], row['name']
    assert row['build_exit'] == row['restore_build_exit'] == row['restored_run_exit'] == 0
    assert row['run_exit'] == 1
    assert row['expected_assertion'] in (here/'final-controls'/f"{row['name']}.run.stderr").read_text()
    for phase in ['build', 'restore-build']:
        assert json.loads((here/'final-controls'/f"{row['name']}.{phase}.forced-objects.json").read_text())
print('5/5 final source mutations reconstructed; all seven source hashes restored')
