#!/usr/bin/env python3
import os
import pathlib
import subprocess
import tempfile

ROOT=pathlib.Path(__file__).resolve().parents[3]
CASES=[
 ("source-inflight","metrics/source-admission.h","|| inflight_ ||","|| false ||","source-admission"),
 ("source-interval","metrics/source-admission.h","now < next_start_","false","source-admission"),
 ("snapshot-age","metrics/source-admission.h","now - completed_ <= max_cache_age_seconds","true","source-admission"),
 ("snapshot-byte-bound","metrics/source-admission.h","bytes <= max_snapshot_bytes","true","source-admission"),
 ("diagnostic-full","metrics/diagnostic-ring.h","count_ == capacity","false","diagnostic-ring"),
 ("pq-buckets","metrics/core-health.h","increment(buckets[success ? 0 : 1][bucket], 1);","increment(buckets[success ? 0 : 1][0], 1);","core-health"),
]
def compile_run(test,folder):
 binary=pathlib.Path(folder)/test
 result=subprocess.run([os.environ.get("CXX","c++"),"-std=c++20","-pthread","-I",str(ROOT),str(ROOT/"tools/node-health-monitor/tests/native"/(test+".cpp")),"-o",str(binary)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 if result.returncode: raise RuntimeError("mutant must compile: "+result.stdout)
 return subprocess.run([str(binary)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
with tempfile.TemporaryDirectory(prefix="tos-health-mutations-") as directory:
 for name,relative,original,replacement,test in CASES:
  if compile_run(test,directory).returncode:raise RuntimeError(name+": baseline failed")
  path=ROOT/relative;content=path.read_text()
  if content.count(original)!=1:raise RuntimeError(name+": anchor is not unique")
  try:
   path.write_text(content.replace(original,replacement));result=compile_run(test,directory)
  finally:path.write_text(content)
  if result.returncode==0 or b"Assertion" not in result.stdout:raise RuntimeError(name+": did not fail its assertion")
  print(name+": compiled mutant rejected",flush=True)
