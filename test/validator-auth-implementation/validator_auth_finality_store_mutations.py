#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];SRC=ROOT/'validator/db/validator-auth-finality-store.cpp'
M=[
 ('persist','ValidatorAuthFinalityStore.round_trip_reopen_and_overwrite','auto status=kv.set(key(),value);','auto status=td::Status::OK();'),
 ('bound','ValidatorAuthFinalityStore.bound_refuses_without_replacing_last_good_value','if(value.empty()||value.size()>validator_auth_finality_journal_max_bytes)','if(false)'),
]
def run(cmd):return subprocess.run(cmd,capture_output=True,text=True,check=False,timeout=900)
def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();b=a.build.resolve();mut=b/'mutated-validator-auth-finality-store.cpp';binary=b/'test-validator-auth-finality-statedb-mutant';orig=SRC.read_text();a.out.mkdir(parents=True,exist_ok=True);records=[]
 try:
  for guard,case,old,new in M:
   if orig.count(old)!=1:raise RuntimeError('anchor '+guard)
   mut.write_text(orig.replace(old,new,1));binary.unlink(missing_ok=True);build=run(['cmake','--build',str(b),'--target','test-validator-auth-finality-statedb-mutant','-j2']);compiled=build.returncode==0 and binary.exists();res=run([str(binary),f'--gtest_filter={case}']) if compiled else None;killed=bool(res and res.returncode!=0);records.append(dict(guard=guard,compiled=compiled,killed=killed));(a.out/'mutations.json').write_text(json.dumps(records,indent=2)+'\n')
   if not(compiled and killed):raise RuntimeError(guard)
 finally:mut.write_text(orig)
 return 0
if __name__=='__main__':
 try:sys.exit(main())
 except Exception as e:print('HARNESS_FAILURE',e,file=sys.stderr);sys.exit(2)
