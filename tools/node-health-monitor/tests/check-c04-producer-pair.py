#!/usr/bin/env python3
"""Independent JSON-schema/hash check of indexed native C++ v2 pair bytes."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--pair-dir', required=True, type=Path)
parser.add_argument('--edge-snapshot', required=True, type=Path)
parser.add_argument('--native-binary', type=Path)
args = parser.parse_args()
formats = FormatChecker()
@formats.checks('uint64')
def exact_u64(value):
    return isinstance(value, str) and re.fullmatch(r'0|[1-9][0-9]{0,19}', value) is not None and int(value) <= 2**64-1

def validator(name):
    schema = json.loads((ROOT/'contracts'/name).read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=formats)

source_validator = validator('source-envelope.schema.json')
edge_validator = validator('edge-snapshot.schema.json')
pairs = sorted(args.pair_dir.glob('*.prom'))
assert {'success-1', 'success-2', 'success-3'}.issubset({path.stem for path in pairs})
index_path = args.pair_dir/'index.json'
indexed = {}
if index_path.exists():
    index = json.loads(index_path.read_bytes())
    assert re.fullmatch(r'[0-9a-f]{64}', index['binary_sha256'])
    indexed = {row['case']: row for row in index['pairs']}
    assert len(indexed) == len(index['pairs']) == len(pairs)
    assert set(indexed) == {path.stem for path in pairs}
    if args.native_binary:
        assert hashlib.sha256(args.native_binary.read_bytes()).hexdigest() == index['binary_sha256']
for body_path in pairs:
    source_bytes = body_path.with_suffix('.json').read_bytes()
    body = body_path.read_bytes()
    source = json.loads(source_bytes)
    source_validator.validate(source)
    assert source['source_version'] == 'native-core-v2'
    if body_path.stem.startswith('success-'):
        assert source['generation'] == body_path.stem.removeprefix('success-')
    assert body.endswith(b'# EOF\n') and len(body) == source['payload']['bytes']
    assert hashlib.sha256(body).hexdigest() == source['payload']['openmetrics_hash']
    canonical = json.dumps(source['payload'], sort_keys=True, separators=(',', ':')).encode()
    assert hashlib.sha256(canonical).hexdigest() == source['content_hash']
    if indexed:
        row = indexed[body_path.stem]
        assert row['source_sha256'] == hashlib.sha256(source_bytes).hexdigest()
        assert row['openmetrics_sha256'] == hashlib.sha256(body).hexdigest()
        assert row['source_bytes'] == len(source_bytes)
        assert row['body_bytes'] == len(body)
        assert row['generation'] == source['generation']
        assert row['process_epoch'] == source['process_epoch']
        assert row['source_epoch'] == source['source_epoch']
    bad = copy.deepcopy(source)
    bad['payload']['consensus']['sessions']['started'] = '18446744073709551616'
    assert not source_validator.is_valid(bad)
    bad = copy.deepcopy(source)
    bad['payload']['consensus']['actions'][1]['replay']['signed_record']['phases']['signed'] = '1'
    assert not source_validator.is_valid(bad)
    print(
        f'producer pair {body_path.stem}: source_sha256={hashlib.sha256(source_bytes).hexdigest()} '
        f'body_sha256={hashlib.sha256(body).hexdigest()} '
        'source schema, canonical hash and exact EOF body valid'
    )
edge = json.loads(args.edge_snapshot.read_bytes())
edge_validator.validate(edge)
assert sum(v['source_id'] == 'native_core' and v['source_version'] == 'native-core-v2' for v in edge['sources']) == 1
print('actual-pair edge snapshot schema valid')
print(f'producer index bound {len(indexed)} pairs; index_sha256={hashlib.sha256(index_path.read_bytes()).hexdigest()}'
      if indexed else 'UNINDEXED preliminary native pairs only')
