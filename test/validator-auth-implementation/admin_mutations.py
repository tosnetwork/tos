"""Compile scoped administration mutations; require their exact assertion labels."""
import argparse,json,subprocess,tempfile
from pathlib import Path
from mutation_support import replace_once
MUTATIONS=[
 ('stage-permit-signature','admin-service','Result<StageResult> AdminSignerService::stage(',
  'auto valid=verify_permit(request.permit_,permission.value().body,permits_,permission.value().current_coordinate,permission.value().fence,permission.value().live_permission);','auto valid=Result<bool>(true);'),
 ('stage-handle-before-reservation','admin-service','Result<StageResult> AdminSignerService::stage(',
  'if(key.value()!=request.key_)return Error{"stage-provider-key"};',''),
 ('provider-possession-signature','admin-service','Result<StageResult> AdminSignerService::stage(',
  'auto verified=verify_possession(context_.chain(),request.update_,request.key_,proof.value());','auto verified=Result<bool>(true);'),
 ('cancel-target-key','admin-service','Result<PermitExpectation> AdminContext::authorize(const RetireRequest&',
  'if(target==Hash{} || target!=request.key_id_)return Error{"retire-target"};',''),
 ('operation-receipt-sequence','operation-ledger','',
  'if(receipt.value().body_.journal_sequence_!=sequence)return Error{"operation-receipt-sequence"};',''),
 ('preparation-conflict-before-reserve','operation-ledger','Result<bool> SafetyLedger::reserve_operation(',
  'if(old!=preparations_.end() && old->second!=parameters(q.value()))return Error{"preparation-conflict"};',''),
 ('pop-id-excludes-permit','operation-ledger','Result<bool> SafetyLedger::reserve_operation(',
  'operation_reservations_.contains(p.reservation)','false'),
 ('provider-preparation-id-conflict','c0-provider','Result<KeyHandle> C0Provider::prepare(',
  'if(old->second.first!=preparation_parameters(request))return Error{"preparation-conflict"};',''),
 ('selection-admission-before-write','c0-provider','Result<KeyHandle> C0Provider::prepare(',
  'if(!preparation_matches(request,key->second.key))return Error{"preparation-key-context"};',''),
 ('pop-backup-no-reinvoke','c0-provider','Result<PossessionAuth> C0Provider::prove_possession(',
  'auto claimed=witness_.claim_primitive(request.fence_,id);','auto claimed=Result<bool>(true);'),
 ('pop-stale-fence','c0-provider','Result<PossessionAuth> C0Provider::prove_possession(',
  'auto current=witness_.check_fence(request.fence_);','auto current=Result<bool>(true);'),
]
def main(build,out):
 folder=build.resolve()/'test/validator-auth-implementation';report=[]
 for name,module,scope,before,after in MUTATIONS:
  source=folder/f'mutated-{module}.cpp';original=source.read_text()
  target='test-p0-admin-provider-mutant' if module=='c0-provider' else f'test-p0-{module}-mutant'
  def run(text):
   source.write_text(text)
   subprocess.run(['cmake','--build',str(build),'--target',target,'-j2'],check=True,capture_output=True,text=True)
   with tempfile.TemporaryDirectory(prefix='p0-admin-') as temp:
    return subprocess.run([str(folder/target),str(Path(temp)/'data')],capture_output=True,text=True)
  try:
   base=run(original);assert base.returncode==0,(name,base.stderr)
   if scope:
    start=original.index(scope)
    end=original.find('\nResult<',start+1)
    if end<0:end=len(original)
    mutant=original[:start]+replace_once(original[start:end],before,after)+original[end:]
   else:mutant=replace_once(original,before,after)
   result=run(mutant)
   assert result.returncode==1 and result.stderr.strip()=='ASSERTION: '+name,(name,result.returncode,result.stderr)
   report.append({'guard':name,'compiled':True,'assertion_failed':True});print('KILLED:',name,flush=True)
  finally:
   restored=run(original);assert restored.returncode==0,(name,restored.stderr)
 out.write_text(json.dumps({'admin_mutations':report,'restored_baselines':True},indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();main(a.build,a.out)
