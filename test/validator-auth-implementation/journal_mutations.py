"""Compiled production guard removals; only the named assertion is a kill."""
import argparse,json,subprocess,tempfile
from pathlib import Path
from mutation_support import replace_once
MUTATIONS=[
 ('primitive-reservation-fence','witness','if (request_fences_.at(request) != fence) return Error{"primitive-reservation-fence"};',''),
 ('primitive-claim-once','witness','if (claimed_.contains(request)) return Error{"primitive-already-claimed"};',''),
 ('single-writer','durable-log','if (::flock(fd, LOCK_EX | LOCK_NB) != 0) return Error{"journal-writer-conflict"};',''),
 ('journal-hash','durable-log','if (next.value().hash != recorded) return Error{"journal-hash"};',''),
 ('same-role-conflict','safety-ledger','if (old_role == role) return Error{"duty-conflict"};',''),
 ('candidate-conflict','safety-ledger','if (!std::equal(old.envelope.payload_.begin() + 4, old.envelope.payload_.end(), plan.envelope.payload_.begin() + 4)) return Error{"candidate-conflict"};',''),
 ('finalize-skip-conflict','safety-ledger','if ((old_role == 3 && role == 4) || (old_role == 4 && role == 3)) return Error{"finalize-skip-conflict"};',''),
 ('journal-statement-binding','safety-ledger','statement.value() != stored.plan.statement ||',''),
 ('sign-request-id','safety-ledger','if (rid.value() != request.request_id_) return Error{"sign-request-id"};',''),
 ('rollback-detection','witness','if (expected != journal_) return Error{"journal-witness-mismatch"};',''),
 ('primitive-fence','witness','Result<bool> FileWitness::primitive_allowed(std::uint64_t fence, const Hash& request) const { if (stopped_) return Error{"witness-unavailable"}; if (fence == 0 || fence != fence_) return Error{"fenced"};','Result<bool> FileWitness::primitive_allowed(std::uint64_t fence, const Hash& request) const { if (stopped_) return Error{"witness-unavailable"};'),
]
def main(build,out):
 folder=build.resolve()/'test/validator-auth-implementation';report=[]
 for name,module,before,after in MUTATIONS:
  source=folder/f'mutated-{module}.cpp';original=source.read_text();target=f'test-p0-{module}-mutant'
  def run(text):
   source.write_text(text)
   subprocess.run(['cmake','--build',str(build),'--target',target,'-j2'],check=True,capture_output=True,text=True)
   with tempfile.TemporaryDirectory(prefix='p0-journal-') as temp:
    return subprocess.run([str(folder/target),str(Path(temp)/'data')],capture_output=True,text=True)
  try:
   base=run(original);assert base.returncode==0,(name,base.stderr)
   result=run(replace_once(original,before,after))
   assert result.returncode==1 and result.stderr.strip()=='ASSERTION: '+name,(name,result.returncode,result.stderr)
   report.append({'guard':name,'compiled':True,'assertion_failed':True});print('KILLED:',name,flush=True)
  finally:
   restored=run(original);assert restored.returncode==0,(name,restored.stderr)
 out.write_text(json.dumps({'journal_mutations':report,'restored_baselines':True},indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();main(a.build,a.out)
