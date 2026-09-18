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
        # Amend the existing record: never reconstruct a shorter history. The
        # evidence_updates ledger (and implementation_evidence_update) records how
        # the frozen set reached its current state; it is preserved exactly, and a
        # single amendment entry naming this revision's artifact transitions is
        # appended only when the artifact set actually changed (so re-running is
        # idempotent). Only revision and artifact_sha256 are recomputed here.
        record=json.loads(RECORD.read_text())
        old=record.get('artifact_sha256',{})
        changed=[{'artifact':n,'previous_sha256':old[n],'sha256':values[n]}
                 for n in sorted(values) if n in old and old[n]!=values[n]]
        added=[{'artifact':n,'sha256':values[n]} for n in sorted(values) if n not in old]
        if changed or added:
            record.setdefault('evidence_updates',[]).append(dict(
              authorization=('Phase 1B A1 core proof-era freeze amendment '
                '(memo/Phase1B-CORE-FREEZE-AMENDMENT.md Rev 4 Final): '
                'block_signatures_validator_auth#13, tosNode.signatureSet.validatorAuth, '
                'pack_bytes(VAC1) typed ^AuthBytes, c0_block_finality_certificate_bytes=58291, '
                'era-aware BlockSignatures parser (issue 3), full-node historical verify '
                'semantics (issue 2); profile revision 5->6; historical #11/#12 unchanged.'),
              revision=6, artifacts=changed+added))
        record['revision']=6
        record['artifact_sha256']=values
        RECORD.write_text(json.dumps(record,indent=2)+'\n')
    record=json.loads(RECORD.read_text())
    if record['artifact_sha256']!=values:raise ValueError('frozen artifact drift requires explicit review')
    print('PASS: frozen artifact set; activation approvals remain separate')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--write',action='store_true');main(p.parse_args().write)
