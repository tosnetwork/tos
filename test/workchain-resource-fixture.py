#!/usr/bin/env python3
"""Regenerate the bounded-policy test zerostate using production create-state.

Outputs are test fixtures, never deployment configuration. All inputs and raw
subprocess output are retained in the required, previously absent output folder.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--repo', type=Path, required=True)
p.add_argument('--create-state', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
a = p.parse_args()
a.repo = a.repo.resolve()
a.create_state = a.create_state.resolve()
a.out = a.out.resolve()
a.out.mkdir(parents=True, exist_ok=False)
source = (a.repo / 'crypto/smartcont/gen-zerostate.fif').read_text()
assert source.count('1 setglobalid') == 1, 'ambiguous production network discriminator'
script = a.out / 'genesis.fif'
script.write_text(source.replace('1 setglobalid', '-23901 setglobalid'))
# Public test keys from repeated-byte seeds 1..4, identical to the genesis
# installation control. No operator key or deployment path is read or written.
(a.out / 'validator-keys.pub').write_bytes(bytes.fromhex(
    '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c'
    '8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394'
    'ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1'
    'ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c'))
# Fixed public development wallet seeds prevent random key generation from
# obscuring a schema-only comparison. These keys are never production inputs.
(a.out / 'main-wallet.pk').write_bytes(bytes(range(32)))
(a.out / 'config-master.pk').write_bytes(bytes(range(32, 64)))
includes = ':'.join(map(str, (a.repo / 'crypto/fift/lib', a.create_state.parent / 'smartcont',
                               a.repo / 'crypto/smartcont')))
command = [str(a.create_state), '-I', includes, str(script)]
r = subprocess.run(command, cwd=a.out, capture_output=True,
                   env=dict(os.environ, SOURCE_DATE_EPOCH='1789434000'), timeout=120)
(a.out / 'stdout.log').write_bytes(r.stdout)
(a.out / 'stderr.log').write_bytes(r.stderr)
report = {'command': command, 'exit': r.returncode, 'source_date_epoch': 1789434000,
          'scope': 'Production genesis issuance, explicit test global ID; no block execution or network startup.'}
report['sha256'] = {str(f): hashlib.sha256(f.read_bytes()).hexdigest()
                    for f in [a.create_state, script, a.repo / 'crypto/block/block.tlb',
                              a.repo / 'crypto/block/create-state.cpp']}
(a.out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
assert r.returncode == 0, 'genesis generation failed; inspect retained output'
