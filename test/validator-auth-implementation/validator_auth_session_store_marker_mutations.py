#!/usr/bin/env python3
from __future__ import annotations
import argparse,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SRC=ROOT/'validator/db/validator-auth-session-store-marker.cpp'
def run(cmd):return subprocess.run(cmd,capture_output=True,text=True,check=False,timeout=900)
def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);a=p.parse_args()
 b=a.build.resolve();mut=b/'mutated-validator-auth-session-store-marker.cpp';binary=b/'test-validator-auth-session-marker-mutant';orig=SRC.read_text()
 old='  auto status = kv.set(key(), value());';new='  auto status = td::Status::OK();'
 if orig.count(old)!=1:raise RuntimeError('anchor')
 try:
  mut.write_text(orig.replace(old,new,1));binary.unlink(missing_ok=True)
  c=run(['cmake','--build',str(b),'--target','test-validator-auth-session-marker-mutant','-j2'])
  if c.returncode!=0 or not binary.exists() or not os.access(binary,os.X_OK):raise RuntimeError('compile')
  r=run([str(binary),'--gtest_filter=ValidatorAuthSessionStoreMarker.absent_then_round_trip_reopen'])
  if r.returncode==0:raise RuntimeError('mutation survived')
 finally:mut.write_text(orig)
 print('PASS: session-store marker write is killed')
 return 0
if __name__=='__main__':
 try:sys.exit(main())
 except Exception as e:print('HARNESS_FAILURE',e,file=sys.stderr);sys.exit(2)
