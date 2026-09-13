"""Compile issuer guard removals and require the intended assertion failure."""
import argparse,json,subprocess,tempfile
from pathlib import Path
from mutation_support import replace_once
MUTATIONS=[
 ('issuer-receipt-purpose','if(purpose_ != ServicePurpose::receipt)return Error{"issuer-purpose"};',''),
 ('issuer-permit-purpose','if(purpose_ != ServicePurpose::permit)return Error{"issuer-purpose"};',''),
 ('issuer-audience-binding','if(body.issuer_ != issuer_ || body.audience_ != audience_ || body.service_policy_ != policy_id_)return Error{"issuer-body-binding"};','if(body.issuer_ != issuer_ || body.service_policy_ != policy_id_)return Error{"issuer-body-binding"};'),
 ('issuer-key-binding','if(derived.value()!=key)return Error{"issuer-key-binding"};',''),
 ('issuer-policy-history','policy.revision_ != history_.size()+1','false'),
 ('issuer-store-purpose','purpose != static_cast<std::uint8_t>(purpose_) ||',''),
 ('issuer-result-shape','(body.state_==2 ? body.result_hash_==Hash{} : body.result_hash_!=Hash{}) ||',''),
 ('issuer-sequence-shape','body.journal_sequence_ == 0 ||',''),
 ('issuer-restart-persistence','auto saved=log_->append(w.data);','auto saved=Result<LogFrontier>(log_->frontier());'),
]
def main(build,out):
 folder=build.resolve()/'test/validator-auth-implementation';source=folder/'mutated-service-issuer.cpp';original=source.read_text();report=[]
 def run(text):
  source.write_text(text)
  subprocess.run(['cmake','--build',str(build),'--target','test-p0-service-issuer-mutant','-j2'],check=True,capture_output=True,text=True)
  with tempfile.TemporaryDirectory(prefix='p0-issuer-') as path:
   return subprocess.run([str(folder/'test-p0-service-issuer-mutant'),str(Path(path)/'issuer')],capture_output=True,text=True)
 for name,before,after in MUTATIONS:
  try:
   baseline=run(original);assert baseline.returncode==0,(name,baseline.stderr)
   # The two typed issue methods deliberately repeat identity binding. Mutate
   # the receipt path only; the permit path stays unchanged in this probe.
   if name=='issuer-audience-binding':
    offset=original.index('Result<Receipt> ServiceIssuer::issue(')
    end=original.index('Result<Permit> ServiceIssuer::issue_permit(')
    mutant=original[:offset]+replace_once(original[offset:end],before,after)+original[end:]
   else: mutant=replace_once(original,before,after)
   result=run(mutant)
   assert result.returncode==1 and result.stderr.strip()=='ASSERTION: '+name,(name,result.returncode,result.stderr)
   report.append({'guard':name,'compiled':True,'assertion_failed':True});print('KILLED:',name,flush=True)
  finally:
   restored=run(original);assert restored.returncode==0,(name,restored.stderr)
 out.write_text(json.dumps({'issuer_mutations':report,'restored_baselines':True},indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();main(a.build,a.out)
