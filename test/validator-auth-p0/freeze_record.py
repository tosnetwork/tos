"""Verify the noncircular frozen artifact set. Rewriting requires explicit review."""
import argparse
import hashlib
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
RECORD=ROOT/'doc/validator-auth-p0-freeze.json'
def hashes():
    paths=list((ROOT/'doc/validator-auth-p0').glob('*'))+list((ROOT/'test/validator-auth-p0').glob('*'))
    paths.append(ROOT/'.github/workflows/validator-auth-p0-profile.yml')
    paths.append(ROOT/'doc/validator-auth-p0-native-insertions.json')
    return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths) if p.is_file()}
def main(write):
    values=hashes()
    if write:
        record=dict(status='design-frozen-not-activated',version=1,revision=4,
          authorization='Owner explicitly requested design modification and freeze in the current task; max_validators fixed at 400.',
          source_base='73fdaf5746e6b84cb0f71f11d67a0bf0e579e80a',
          prior_review_head='23413e56814fbe709795e71e14897acb21d4c145',
          evidence='Validator P0 profile workflow must pass at the commit containing this exact artifact set. CI commit.txt binds the final source commit; no self-referential commit hash is embedded here.',
          approvals_pending=['independent protocol/security/client release approval','TIP revision publication','genesis/operator approval','production state, proof, service and multi-node integration','performance and recovery rehearsal'],
          artifact_sha256=values)
        RECORD.write_text(json.dumps(record,indent=2)+'\n')
    record=json.loads(RECORD.read_text())
    if record['artifact_sha256']!=values:raise ValueError('frozen artifact drift requires explicit review')
    print('PASS: frozen artifact set; activation approvals remain separate')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--write',action='store_true');main(p.parse_args().write)
