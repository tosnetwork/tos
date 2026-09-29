#!/usr/bin/env python3
"""Require each native contract test to fail after a compiled behavioral mutation."""
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'crates/health-core/src/native.rs'
ENV = dict(os.environ, CARGO_INCREMENTAL='0', CARGO_BUILD_PIPELINING='false')
CASES = [
    ('exact-generation', 'exact_pairing_rejects_changed_generation_and_content',
     '|| self.generation.0 != exact_u64(generation).map_err(str::to_owned)?', '|| false'),
    ('content-hash', 'exact_pairing_rejects_changed_generation_and_content',
     'if canonical_hash(&self.payload)? != self.content_hash', 'if false'),
    ('required-nullable', 'required_nullable_and_unknown_fields_are_enforced',
     '#[serde(deserialize_with = "required_nullable")]\n    pub pq_sign:', 'pub pq_sign:'),
    ('source-age', 'age_and_quality_cannot_be_fabricated',
     'self.source_age_ms.is_none_or(|age| age > 30_000)', 'false'),
    ('quality', 'age_and_quality_cannot_be_fabricated',
     'if complete != self.quality.instrumentation_complete', 'if false'),
    ('immutable-metadata', 'immutable_identity_excludes_only_receipt_and_age',
     'canonical_hash(&value)\n', 'canonical_hash(&value.payload)\n'),
]
def run(name):
    return subprocess.run(['cargo', 'test', '--locked', '-p', 'tos-health-core',
                           '--test', 'native_contract', name, '--', '--exact'],
                          cwd=ROOT, env=ENV, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)
original = SOURCE.read_text()
try:
    for label, name, old, new in CASES:
        SOURCE.write_text(original)
        baseline = run(name)
        if baseline.returncode or '1 passed' not in baseline.stdout:
            raise RuntimeError(f'{label}: baseline failed\n{baseline.stdout}')
        if original.count(old) != 1:
            raise RuntimeError(f'{label}: mutation target is not unique')
        SOURCE.write_text(original.replace(old, new))
        result = run(name)
        if result.returncode == 0 or f'{name} ... FAILED' not in result.stdout:
            raise RuntimeError(f'{label}: no compiled assertion failure\n{result.stdout}')
        print(f'{label}: compiled mutant killed', flush=True)
finally:
    SOURCE.write_text(original)
result = subprocess.run(['cargo', 'test', '--locked', '-p', 'tos-health-core', '--test', 'native_contract'], cwd=ROOT, env=ENV, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
if result.returncode:
    raise RuntimeError(result.stdout)
print('native contract source restored')
