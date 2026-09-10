#!/usr/bin/env python3
"""Calibrate prepared local decisions in a separate checkout; no live gate evidence."""
import argparse, hashlib, json, subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--repo',type=Path,required=True)
p.add_argument('--copy',type=Path,required=True)
p.add_argument('--build',type=Path,required=True)
p.add_argument('--out',type=Path,required=True)
a=p.parse_args(); a.out.mkdir(parents=True,exist_ok=False)
assert a.repo.resolve()!=a.copy.resolve()
path='crypto/test/prepared/workchain-validator-local-decisions.h'
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=a.repo,text=True).strip()
original=subprocess.check_output(['git','show',commit+':'+path],cwd=a.repo)
assert (a.repo/path).read_bytes()==original and (a.copy/path).read_bytes()==original
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=a.copy,text=True).strip()==commit
sha=lambda b:hashlib.sha256(b).hexdigest()
report={'source_commit':commit,'path':path,'original_sha256':sha(original),'scope':'Prepared, not connected. Local decisions with real scoped resolution only; no ValidateQuery actor, no live call-site evidence. Production gates unchanged.','controls':[]}
count=0
def run(label,cmd):
 global count
 count+=1
 r=subprocess.run(list(map(str,cmd)),capture_output=True)
 for stream in ('stdout','stderr'): (a.out/f'{count:03d}-{label}.{stream}').write_bytes(getattr(r,stream))
 return r
def ok(label,cmd):
 r=run(label,cmd)
 assert r.returncode==0,(label,r.returncode)
 return r
ok('configure',['cmake','-S',a.copy,'-B',a.build,'-DCMAKE_PROJECT_TOS_INCLUDE=crypto/test/workchain-validator-local-visitors.cmake'])
target='test-workchain-validator-local-visitors'; rebuild=['cmake','--build',a.build,'--target',target,'-j32']
fixture=a.copy/'crypto/test/workchain-bounded-zerostate.boc'
command=[a.build/target,fixture]
report.update(explicit_rebuild_command=list(map(str,rebuild)),actual_executables=[str(a.build/target)],fixture_sha256=sha(fixture.read_bytes()))
ok('baseline-build',rebuild)
for case in range(4): ok(f'baseline-{case}',command+[str(case)])
s=original.decode(); cut=s.index('inline td::Status ready(')
custom=s[:cut]; ready=s[cut:]
controls=[
 ('custom-answer',custom,custom.replace('        return false;','        return true;'),0,1311),
 ('custom-old-refusal',custom,custom.replace('        return false;','        return td::Status::Error(-7201, "prepared old refusal");'),0,1310),
 ('ready-old-refusal',ready,ready.replace('        return td::Status::OK();','        return td::Status::Error(-7201, "prepared old refusal");'),1,1320),
 ('custom-candidate-invalid',custom,custom.replace('return resolution.move_as_error();','return td::Status::Error(static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid), "misclassified local fault");'),2,1331),
 ('ready-candidate-invalid',ready,ready.replace('return resolution.move_as_error();','return td::Status::Error(static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid), "misclassified local fault");'),3,1341)]
for name,old,new,failed_case,identity in controls:
 assert old!=new and s.count(old)==1
 mutant=s.replace(old,new).encode(); results=[]
 try:
  (a.copy/path).write_bytes(mutant); ok(name+'-build',rebuild)
  for case in range(4):
   r=run(name+f'-{case}',command+[str(case)])
   ids=[json.loads(line)['failure_identity'] for line in r.stderr.decode().splitlines() if line.startswith('{"failure_identity":')]
   assert (r.returncode,ids)==((1,[identity]) if case==failed_case else (0,[])),(name,case,r.returncode,ids)
   results.append({'case':case,'exit':r.returncode,'failure_identities':ids})
 finally: (a.copy/path).write_bytes(original)
 ok(name+'-restored-build',rebuild)
 for case in range(4): ok(name+f'-restored-{case}',command+[str(case)])
 report['controls'].append({'name':name,'from':old,'to':new,'copy_before_sha256':sha(original),'mutant_sha256':sha(mutant),'restored_sha256':sha((a.copy/path).read_bytes()),'restore_audit_sha256':sha((a.copy/path).read_bytes().replace(old.encode(),new.encode())),'compile_exit':0,'results':results})
 (a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
assert (a.repo/path).read_bytes()==original
print('PASS: five isolated controls, four cases each, exact failure identities and restored rebuilds')
