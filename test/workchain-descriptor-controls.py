#!/usr/bin/env python3
"""Calibrate each shared descriptor encoder using isolated interpreted copies."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
p=argparse.ArgumentParser();p.add_argument('--create-state',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
repo=Path(__file__).resolve().parents[1];commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip();source='crypto/fift/lib/Workchain.fif';original=subprocess.check_output(['git','show',f'{commit}:{source}'],cwd=repo);assert (repo/source).read_bytes()==original
sha=lambda b:hashlib.sha256(b).hexdigest()
specs=[('basic-route','{ <b x{a6} s, 7 roll 32 u, 6 roll 8 u, 5 roll 8 u, 4 roll 8 u,\n  2 roll 16 u,','{ <b x{a6} s, 7 roll 32 u, 6 roll 8 u, 5 roll 8 u, 4 roll 8 u,\n  2 roll drop 0xe000 16 u,','uno-basic'),('extended-key','swap 32 i, 0 64 u, x{0} s,','swap drop -1 32 i, 0 64 u, x{0} s,','counter-extended')]
report={'commit':commit,'source':source,'controls':[],'scope':'Single Fift source substitutions. create-state interprets library on each invocation; no compiled binary contains the Fift mutation.'}
for name,before,after,expected in specs:
 assert original.count(before.encode())==1
 mutant=original.replace(before.encode(),after.encode())
 with tempfile.TemporaryDirectory(prefix='uno-descriptor-copy-') as directory:
  copy=Path(directory)/'Workchain.fif';copy.write_bytes(original);assert copy.read_bytes()==original;copy.write_bytes(mutant)
  command=['python3',str(repo/'test/workchain-descriptor-equivalence.py'),'--repo',str(repo),'--create-state',str(a.create_state),'--library',directory,'--out',str(a.out/name)]
  result=subprocess.run(command,capture_output=True);(a.out/(name+'.stdout.log')).write_bytes(result.stdout);(a.out/(name+'.stderr.log')).write_bytes(result.stderr)
  assert result.returncode!=0 and f'1221: descriptor bytes changed: {expected}'.encode() in result.stderr
  cases=json.loads((a.out/name/'report.json').read_text())['cases'];assert all(c['equal'] for c in cases[:-1]) and cases[-1]['name']==expected and not cases[-1]['equal']
  copy.write_bytes(original);assert copy.read_bytes()==original
  report['controls'].append({'name':name,'from':before,'to':after,'original_sha256':sha(original),'copy_before_sha256':sha(original),'mutant_sha256':sha(mutant),'restored_sha256':sha(copy.read_bytes()),'restore_audit_sha256':sha(copy.read_bytes().replace(before.encode(),after.encode())),'failing_case':expected,'command':command,'failure_identity':1221})
  (a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
assert (repo/source).read_bytes()==original
command=['python3',str(repo/'test/workchain-descriptor-equivalence.py'),'--repo',str(repo),'--create-state',str(a.create_state),'--out',str(a.out/'restored')];result=subprocess.run(command,capture_output=True);(a.out/'restored.stdout.log').write_bytes(result.stdout);(a.out/'restored.stderr.log').write_bytes(result.stderr);assert result.returncode==0
print('PASS: isolated a6 route and a7 selector controls, restored five-case comparison')
