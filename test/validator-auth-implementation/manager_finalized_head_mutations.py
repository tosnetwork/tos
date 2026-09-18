#!/usr/bin/env python3
"""Compile manager-finalized-head mutations and require named failures."""
from __future__ import annotations
import argparse, difflib, hashlib, json, os, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'validator/auth/manager-finalized-head.cpp'
MUTATIONS=[
 ('signed-weight-upgrade','same_block_may_accumulate_more_final_signatures',
  '    if (value.signed_weight > it->second.signed_weight)\n      it->second = value;',
  '    if (false && value.signed_weight > it->second.signed_weight)\n      it->second = value;'),
 ('verified-half','verified_only_publishes_nothing_new',
  '  if (!verified_.contains(id) || !applied_.contains(id))\n    return false;',
  '  if (!verified_.contains(id))\n    return false;'),
 ('applied-half','applied_only_publishes_nothing_new',
  '  if (!verified_.contains(id) || !applied_.contains(id))\n    return false;',
  '  if (!applied_.contains(id))\n    return false;'),
 ('applied-binding','applied_bytes_and_state_must_bind_exact_block',
  '  if (parsed.value() != expected)\n    return Error{"manager-finality-applied-binding"};',
  '  if (false && parsed.value() != expected)\n    return Error{"manager-finality-applied-binding"};'),
 ('monotonic-complete','a_later_complete_head_never_regresses',
  '    if (id.seqno() < latest_complete_->seqno())\n      return false;',
  '    if (false && id.seqno() < latest_complete_->seqno())\n      return false;'),
 ('exact-receipt','receipt_lookup_is_exact_block_only',
  '  auto it = verified_.find(block);',
  '  auto it = verified_.empty() ? verified_.end() : verified_.begin();'),
]
def invoke(cmd,log):
 r=subprocess.run(cmd,capture_output=True,text=True,check=False,timeout=900)
 log.write_text('$ '+' '.join(map(str,cmd))+f'\nexit_code={r.returncode}\n--- stdout ---\n'+r.stdout+'--- stderr ---\n'+r.stderr)
 return r
def pass_suite(r,n):
 lines=r.stdout.splitlines()
 return r.returncode==0 and r.stderr=='' and lines[-1:]==[f'SUMMARY cases={n} passed={n}'] and sum(x.startswith('CASE_PASS ') for x in lines)==n
def named(r,name):
 return r.returncode==1 and r.stdout.splitlines()==[f'SETUP_OK {name}'] and r.stderr.splitlines()==[f'ASSERTION_FAILED {name}']
def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--owner',type=Path,required=True);p.add_argument('--committee',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 build=a.build.resolve();folder=build/'test/validator-auth-implementation';mutant=folder/'mutated-manager-finalized-head.cpp';binary=folder/'test-p0-manager-finalized-head-mutant';a.out.mkdir(parents=True,exist_ok=True)
 original=SOURCE.read_text();digest=hashlib.sha256(SOURCE.read_bytes()).hexdigest()
 def compile(log):
  binary.unlink(missing_ok=True);r=invoke(['cmake','--build',str(build),'--target','test-p0-manager-finalized-head-mutant','-j2'],log);return r.returncode==0 and binary.exists() and os.access(binary,os.X_OK)
 mutant.write_text(original)
 if not compile(a.out/'baseline-build.log'):raise RuntimeError('baseline build')
 listed=invoke([str(binary),str(a.owner.resolve()),str(a.committee.resolve()),'--list'],a.out/'cases.log');cases=listed.stdout.splitlines();n=len(cases)
 baseline=invoke([str(binary),str(a.owner.resolve()),str(a.committee.resolve())],a.out/'baseline.log')
 if not cases or not pass_suite(baseline,n):raise RuntimeError('baseline suite')
 records=[]
 try:
  for guard,case,old,new in MUTATIONS:
   if original.count(old)!=1:raise RuntimeError('anchor '+guard)
   changed=original.replace(old,new,1);mutant.write_text(changed)
   (a.out/f'{guard}.diff').write_text(''.join(difflib.unified_diff(original.splitlines(True),changed.splitlines(True),fromfile=str(SOURCE),tofile=str(mutant))))
   compiled=compile(a.out/f'{guard}-build.log');nf=iso=False
   if compiled:
    nf=named(invoke([str(binary),str(a.owner.resolve()),str(a.committee.resolve()),case],a.out/f'{guard}-named.log'),case)
    iso=pass_suite(invoke([str(binary),str(a.owner.resolve()),str(a.committee.resolve()),f'--exclude={case}'],a.out/f'{guard}-others.log'),n-1)
   mutant.write_text(original);restored=compile(a.out/f'{guard}-restore-build.log') and pass_suite(invoke([str(binary),str(a.owner.resolve()),str(a.committee.resolve())],a.out/f'{guard}-restore.log'),n)
   rec=dict(guard=guard,case=case,compiled=compiled,named_assertion_failed=nf,other_cases_passed=iso,restored=restored,production_source_unchanged=hashlib.sha256(SOURCE.read_bytes()).hexdigest()==digest);records.append(rec);(a.out/'mutations.json').write_text(json.dumps(records,indent=2)+'\n')
   if not all(rec.values()):raise RuntimeError('mutation '+guard)
 finally: mutant.write_text(original)
 return 0
if __name__=='__main__':
 try:sys.exit(main())
 except Exception as e:print('HARNESS_FAILURE',e,file=sys.stderr);sys.exit(2)
