#!/usr/bin/env python3
"""Expand the frozen C01/C04 series tuples and verify their exact bounded union."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
evidence = root / 'evidence/c04-native-actions'
base_path = root / 'contracts/metric-manifest.json'
c04_path = evidence / 'metric-manifest.json'
base = json.loads(base_path.read_bytes())
c04 = json.loads(c04_path.read_bytes())
base_rows, new_rows = [], []

def row(name, labels):
    return {'name': name, 'labels': sorted([list(pair) for pair in labels])}

for family in base['families']:
    for values in family['allowed_tuples']:
        labels = list(zip(family['label_names'], values, strict=True))
        if family['semantic_type'] == 'histogram':
            for bucket in [*family['finite_buckets'], '+Inf']:
                base_rows.append(row(family['name'] + '_bucket', [*labels, ('le', str(bucket))]))
            for suffix in ['count', 'sum']:
                base_rows.append(row(family['name'] + '_' + suffix, labels))
        else:
            base_rows.append(row(family['name'], labels))
for descriptor in c04['tuples']:
    suffix = descriptor['suffix']
    new_rows.append(row(descriptor['name'] + ('_' + suffix if suffix else ''), descriptor['labels']))

encoded = lambda rows: [json.dumps(v, sort_keys=True, separators=(',', ':')) for v in rows]
assert len(base_rows) == base['computed_max_series'] == 107
assert len(new_rows) == c04['new_max_series'] == 142
assert len(set(encoded(base_rows))) == 107
assert len(set(encoded(new_rows))) == 142
assert not set(encoded(base_rows)) & set(encoded(new_rows))
union = sorted(base_rows + new_rows, key=lambda v: json.dumps(v, sort_keys=True))
assert len(union) == c04['union_max_series'] == 249
assert len(union) <= c04['profile_limit'] == 256
assert c04['profile_limit'] <= base['r4_global_core_max_series'] == 2048
receipt = {'base_manifest_sha256': hashlib.sha256(base_path.read_bytes()).hexdigest(),
           'c04_manifest_sha256': hashlib.sha256(c04_path.read_bytes()).hexdigest(),
           'base_series': 107, 'new_series': 142, 'union_series': 249,
           'profile_ceiling': 256, 'global_ceiling': 2048, 'expanded_union': union}
(evidence / 'metric-union.json').write_text(json.dumps(receipt, indent=2) + '\n')
print('C04_METRIC_UNION_PASS: 107 + 142 = 249 unique series <= 256 profile <= 2048 global')
