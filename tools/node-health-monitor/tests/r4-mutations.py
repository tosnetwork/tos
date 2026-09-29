#!/usr/bin/env python3
"""Require each modified guard to compile and fail a specific behavioral assertion."""
import os
import json,pathlib,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
CASES=[
('canonical-integer','health-core','r4','wire.rs',"|| (value.len() > 1 && value.starts_with('0'))",'|| false','exact_uint64'),
('ipc-reserved','health-core','r4','wire.rs','|| u32_at(60) != 0','|| false','ipc_rejects_malformed_header'),
('original-age','health-core','r4','freshness.rs','return Ok(false);','self.accepted_ms = now; return Ok(false);','freshness_same_generation_does_not_renew'),
('conflict-quarantine','health-core','r4','freshness.rs','&& !self.conflicted','&& true','freshness_conflict_quarantines_epoch'),
('recovery-generations','health-core','r4','health_state.rs','v.generation <= old.generation','false','recovery_requires_distinct_good_and_hold'),
('recovery-epoch','health-core','r4','health_state.rs','|| changed_epoch','|| false','unknown_epoch_and_restart_reset_recovery'),
('histogram-series','health-core','r4','contracts.rs','finite_buckets.len().checked_add(3)','finite_buckets.len().checked_add(2)','sparse_histograms_count_all_series'),
('vote-order','health-core','r4','contracts.rs','phase != self.phase + 1','false','vote_order_and_replay_are_preserved'),
('diagnostic-json','health-core','r4','contracts.rs','if bytes.len() > 262_144 {','if false {','diagnostic_limits_are_independent'),
('diagnostic-decoded','health-core','r4','contracts.rs','if total > 65_536 {','if false {','diagnostic_limits_are_independent'),
('runtime-evidence','health-core','r4','contracts.rs','missing.push("runtime_acceptance_not_verified");','','production_placeholders_and_claims_do_not_pass'),
('watermark','health-services','durable','durable.rs','AND store_seq<=?4','AND (store_seq<=?4 OR 1=1)','immutable_sequence_survives_restart_and_late_arrival'),
('atomic-outbox','health-services','durable','durable.rs','if n >= self.max_outbox {','if false {','incident_and_outbox_commit_together'),
('native-period','health-services','native_cache','native_cache.rs','if Instant::now() < self.next_due {','if false {','thousand_cache_reads_never_call_native'),
('http-error-status','health-services','http','observability.rs','Some("INVALID_ARGUMENT") => StatusCode::BAD_REQUEST','Some("INVALID_ARGUMENT") => StatusCode::OK','query_rejections_are_not_http_success'),
]
def run(package,test,name):return subprocess.run(['cargo','test','--locked','--manifest-path',str(ROOT/'Cargo.toml'),'-p','tos-'+package,'--test',test,name,'--','--exact'],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env={**os.environ,"CARGO_INCREMENTAL":"0"})
def main():
 results=[]
 for label,package,test,file,old,new,name in CASES:
  baseline=run(package,test,name);assert baseline.returncode==0 and '1 passed; 0 failed' in baseline.stdout,baseline.stdout
  path=ROOT/'crates'/package/'src'/file;text=path.read_text()
  if label=='original-age':assert text.count(old)==2
  else:assert text.count(old)==1,(label,text.count(old))
  try:
   path.write_text(text.replace(old,new,1));mutant=run(package,test,name)
  finally:path.write_text(text)
  assert mutant.returncode!=0 and '0 passed; 1 failed' in mutant.stdout and f'test {name} ... FAILED' in mutant.stdout,(label,mutant.stdout)
  results.append(dict(mutation=label,test=name,baseline='passed',mutant='compiled_and_failed'));print(label+': compiled and failed',flush=True)
 # Cross-language native decoder must also notice removal of its reserved-bit guard.
 path=ROOT.parents[1]/'metrics/diagnostic-wire.h';text=path.read_text();old='|| wire_get(in+60,4)!=0';assert text.count(old)==1
 with tempfile.TemporaryDirectory() as directory:
  exe=pathlib.Path(directory)/'wire';cmd=['c++','-std=c++17','-I',str(ROOT.parents[1]),str(ROOT/'tests/native/diagnostic-wire.cpp'),'-o',str(exe)]
  subprocess.run(cmd,check=True);assert subprocess.run([str(exe)],stdout=subprocess.PIPE).returncode==0
  try:
   path.write_text(text.replace(old,'|| false'));subprocess.run(cmd,check=True);r=subprocess.run([str(exe)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   assert r.returncode!=0 and b'Assertion' in r.stderr
  finally:path.write_text(text)
 results.append(dict(mutation='native-ipc-reserved',baseline='passed',mutant='compiled_and_failed'))
 print(json.dumps(results,indent=2))
if __name__=='__main__':main()
