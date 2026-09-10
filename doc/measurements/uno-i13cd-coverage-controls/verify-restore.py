#!/usr/bin/env python3
"""Reconstruct recorded mutations against the checked-out final sources."""
import hashlib
import json
from pathlib import Path

here = Path(__file__).resolve().parent
repository = here.parents[2]
audit = json.loads((here / 'restore-audit.json').read_text())
sha = lambda raw: hashlib.sha256(raw).hexdigest()
for path, digest in audit['source_sha256'].items():
    if sha((repository / path).read_bytes()) != digest:
        raise RuntimeError('final source differs: ' + path)
records = audit['records']
if len(records) != audit['controls'] or len({r['name'] for r in records}) != audit['controls']:
    raise RuntimeError('missing or duplicate control')
for record in records:
    raw = (repository / record['path']).read_bytes()
    before, after = record['before'].encode(), record['after'].encode()
    if raw.count(before) != 1 or raw.count(after) != 0:
        raise RuntimeError('replacement does not match: ' + record['name'])
    if sha(raw) != record['original_sha256'] or sha(raw) != record['restored_sha256']:
        raise RuntimeError('restore differs: ' + record['name'])
    reconstructed = sha(raw.replace(before, after))
    if reconstructed != record['recorded_mutant_sha256'] or reconstructed != record['reconstructed_mutant_sha256']:
        raise RuntimeError('mutant differs: ' + record['name'])
print(f"{len(records)}/{audit['controls']} mutations reconstructed against checked-out source; byte-exact restoration")
