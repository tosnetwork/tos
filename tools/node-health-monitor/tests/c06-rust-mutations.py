#!/usr/bin/env python3
"""Compile faithful C06 guard removals; require the intended assertion to fail."""
import difflib,hashlib,json,os,pathlib,re,subprocess,sys
root=pathlib.Path(__file__).resolve().parents[1]
out=pathlib.Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
svc=root/'crates/health-services/src';core=root/'crates/health-core/src'
cases=[
 ('credential',svc/'diagnostic_ipc.rs','if cred.pid!=self.mapping.native_pid || cred.uid!=self.mapping.native_uid || cred.gid!=self.mapping.native_gid {','if false && (cred.pid!=self.mapping.native_pid || cred.uid!=self.mapping.native_uid || cred.gid!=self.mapping.native_gid) {','real_credentials_and_epoch_are_separate_rejection_gates','Received::Rejected("credentials")'),
 ('rights-close',svc/'diagnostic_ipc.rs','libc::close(std::ptr::read_unaligned(descriptors.add(i)));','let _=std::ptr::read_unaligned(descriptors.add(i));','real_credentials_and_epoch_are_separate_rejection_gates','rejected SCM_RIGHTS must not leak installed descriptors'),
 ('nofollow',svc/'diagnostic_ipc.rs','libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK','libc::O_CLOEXEC|libc::O_NONBLOCK','real_credentials_and_epoch_are_separate_rejection_gates','read_token(&link).is_err()'),
 ('epoch',svc/'diagnostic_ipc.rs','if size<64 || bytes[16..32]!=self.epoch {','if size<64 {','real_credentials_and_epoch_are_separate_rejection_gates','Received::Rejected("epoch_or_header")'),
 ('conflict',svc/'diagnostic_ingest.rs','if hash!=*digest {','if false && hash!=*digest {','conflict_quarantines_without_committing_an_earlier_new_record','called `Result::unwrap_err()` on an `Ok` value'),
 ('atomic-prefix',svc/'diagnostic_ingest.rs',None,None,'actual_mid_transaction_failure_rolls_back_and_never_returns_ack','left: 1\n right: 0'),
 ('predecode-reservation',svc/'diagnostic_ingest.rs','try_acquire_many_owned(PREDECODE_BYTES)','try_acquire_many_owned(PREDECODE_BYTES / 2)','actual_mid_transaction_failure_rolls_back_and_never_returns_ack','called `Option::unwrap()` on a `None` value'),
 ('json-limit',core/'contracts.rs','if bytes.len() > 262_144 {','if false && bytes.len() > 262_144 {','bounded_queue_and_json_have_separate_accounting','right: "JSON body limit"'),
 ('decoded-limit',core/'contracts.rs','if total > 65_536 {','if false && total > 65_536 {','bounded_queue_and_json_have_separate_accounting','right: "decoded payload limit"'),
 ('tcp-rate',svc/'diagnostic_transport.rs',None,None,'actual_tcp_writer_obeys_rate_and_counts_all_written_bytes','actual egress bypassed token rate'),
]
env=dict(os.environ,CARGO_BUILD_JOBS='2');index=[]
def run(args,path):
 with path.open('wb') as log: return subprocess.run(args,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=120).returncode
for name,p,old,new,test,needle in cases:
 original=p.read_bytes();s=original.decode()
 try:
  if name=='tcp-rate':
   old1='Ok(mut rate)=>rate.available()';old2='self.tokens=self.tokens.checked_sub(n).ok_or_else(||io::Error::other("egress budget underflow"))?;'
   assert s.count(old1)==s.count(old2)==1
   s=s.replace(old1,'Ok(_rate)=>u64::MAX').replace(old2,'self.tokens=self.tokens.saturating_sub(n);')
  elif name=='atomic-prefix':
   marker='    tx.commit().map_err(|e|e.to_string())?;\n    Ok(Ack'
   # Commit every successful prefix inside the existing insertion loop.
   start=s.index('    for ((value,');end=s.index('    tx.commit()',start)
   fragment=s[start:end];assert fragment.count('        }\n    }')==1
   fragment=fragment.replace('        }\n    }','            tx.execute_batch("COMMIT; BEGIN").map_err(|e|e.to_string())?;\n        }\n    }')
   s=s[:start]+fragment+s[end:]
  else:
   pattern='\\s*'.join(re.escape(char) for char in old if not char.isspace())
   s,count=re.subn(pattern,lambda _:new,s);assert count==1,(name,count)
  patch="".join(difflib.unified_diff(original.decode().splitlines(keepends=True),s.splitlines(keepends=True),fromfile=str(p.relative_to(root)),tofile=str(p.relative_to(root))))
  (out/(name+".patch")).write_text(patch)
  mutant_sha=hashlib.sha256(s.encode()).hexdigest();patch_sha=hashlib.sha256(patch.encode()).hexdigest()
  p.write_text(s)
  compiled=run(['cargo','test','-p','tos-health-services','--lib','--no-run'],out/(name+'-compile.log'))
  assert compiled==0,f'{name}: compile failed'
  red=run(['cargo','test','-p','tos-health-services','--lib',test,'--','--nocapture'],out/(name+'-red.log'))
  log=(out/(name+'-red.log')).read_text()
  assert red==101 and needle in log and 'test result: FAILED' in log,f'{name}: wrong branch or survived'
 finally:p.write_bytes(original)
 green=run(['cargo','test','-p','tos-health-services','--lib',test],out/(name+'-restored.log'))
 assert green==0,f'{name}: restore failed'
 index.append(dict(name=name,compile_exit=compiled,mutant_exit=red,restored_exit=green,intended_assertion=needle,mutant_source_sha256=mutant_sha,patch_sha256=patch_sha,restored_source_sha256=hashlib.sha256(original).hexdigest()))
 (out/'index.json').write_text(json.dumps(index,indent=2)+'\n');print(name,'compiled / intended red / restored 0',flush=True)
