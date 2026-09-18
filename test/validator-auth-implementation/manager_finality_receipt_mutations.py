#!/usr/bin/env python3
from __future__ import annotations
import argparse,difflib,hashlib,json,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];SOURCE=ROOT/'validator/auth/manager-finality-receipt.cpp'
MUT=[
('current-fallback','current_set_is_the_explicit_fallback','  if (auto value = verify(current))\n    return *value;','  if (false)\n    if (auto value = verify(current))\n      return *value;'),
('signed-weight','exact_final_receipt','        checked.ok(),\n        set->get_total_weight()};','        set->get_total_weight(),\n        set->get_total_weight()};'),
('total-weight','exact_final_receipt','        checked.ok(),\n        set->get_total_weight()};','        checked.ok(),\n        checked.ok()};'),
]
def run(cmd):return subprocess.run(cmd,capture_output=True,text=True,check=False,timeout=900)
def passing(r,n):return r.returncode==0 and r.stderr=='' and r.stdout.splitlines()[-1:]==[f'SUMMARY cases={n} passed={n}']
def named(r,c):return r.returncode==1 and r.stdout.splitlines()==[f'SETUP_OK {c}'] and r.stderr.splitlines()==[f'ASSERTION_FAILED {c}']
def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();b=a.build.resolve();folder=b/'test/validator-auth-implementation';src=folder/'mutated-manager-finality-receipt.cpp';bin=folder/'test-p0-manager-finality-receipt-mutant';a.out.mkdir(parents=True,exist_ok=True);orig=SOURCE.read_text();digest=hashlib.sha256(SOURCE.read_bytes()).hexdigest()
 def build():bin.unlink(missing_ok=True);r=run(['cmake','--build',str(b),'--target','test-p0-manager-finality-receipt-mutant','-j2']);return r.returncode==0 and bin.exists() and os.access(bin,os.X_OK)
 src.write_text(orig);assert build();ls=run([str(bin),'--list']);cases=ls.stdout.splitlines();n=len(cases);assert cases and passing(run([str(bin)]),n);records=[]
 try:
  for g,c,o,nw in MUT:
   if orig.count(o)!=1:raise RuntimeError('anchor '+g)
   changed=orig.replace(o,nw,1);src.write_text(changed);compiled=build();target=run([str(bin),c]) if compiled else None;others=run([str(bin),f'--exclude={c}']) if compiled else None;src.write_text(orig);rest=build() and passing(run([str(bin)]),n)
   rec=dict(guard=g,case=c,compiled=compiled,named_assertion_failed=bool(target and named(target,c)),other_cases_passed=bool(others and passing(others,n-1)),restored=rest,production_source_unchanged=hashlib.sha256(SOURCE.read_bytes()).hexdigest()==digest);records.append(rec);(a.out/'mutations.json').write_text(json.dumps(records,indent=2)+'\n')
   if not all(rec.values()):raise RuntimeError(g)
 finally:src.write_text(orig)
 return 0
if __name__=='__main__':
 try:sys.exit(main())
 except Exception as e:print('HARNESS_FAILURE',e,file=sys.stderr);sys.exit(2)
