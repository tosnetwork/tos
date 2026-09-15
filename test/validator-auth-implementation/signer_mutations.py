"""Remove signer/provider durability guards and require their named assertions."""
import argparse,json,subprocess,tempfile
from pathlib import Path
from mutation_support import replace_once
MUTATIONS=[
 ('unreserved-provider-admission','c0-provider','if(!allowed.ok())return allowed.error();if(!allowed.value())return Error{"primitive-not-reserved"};',''),
 ('provider-rollback-no-primitive','c0-provider','auto claim=witness_.claim_primitive(request.fence_,request.request_id_);','auto claim=Result<bool>(true);'),
 ('provider-stale-fence','c0-provider','auto current=witness_.check_fence(request.fence_);','auto current=Result<bool>(true);'),
 ('signer-permit-signature','signer-service','auto permit=verify_permit(request.permit_,expected.value().body,permits_,expected.value().current_coordinate, expected.value().fence,expected.value().live_permission);','auto permit=Result<bool>(true);'),
 ('signer-key-before-reserve','signer-service','ref.value()!=Keyref{c.suite_,c.parameters_,c.epoch_,c.key_id_} ||',''),
 ('sync-before-success','sync','&& sync_file(fd_)',''),
 ('stopped-after-ambiguous-sync','sync','if (stopped_) return Error{"storage-unavailable"};',''),
]
def main(build,out):
 folder=build.resolve()/'test/validator-auth-implementation';report=[]
 for name,module,before,after in MUTATIONS:
  source=folder/f'mutated-{"durable-log" if module=="sync" else module}.cpp';original=source.read_text();target=f'test-p0-{module}-mutant'
  def run(text):
   source.write_text(text)
   subprocess.run(['cmake','--build',str(build),'--target',target,'-j2'],check=True,capture_output=True,text=True)
   with tempfile.TemporaryDirectory(prefix='p0-signer-') as temp:
    return subprocess.run([str(folder/target),str(Path(temp)/'data')],capture_output=True,text=True)
  try:
   base=run(original);assert base.returncode==0,(name,base.stderr)
   if module=='c0-provider':
    start=original.index('Result<Record> C0Provider::sign(')
    end=original.index('namespace {',start)
    mutant=original[:start]+replace_once(original[start:end],before,after)+original[end:]
   else: mutant=replace_once(original,before,after)
   result=run(mutant)
   assert result.returncode==1 and result.stderr.strip()=='ASSERTION: '+name,(name,result.returncode,result.stderr)
   report.append({'guard':name,'compiled':True,'assertion_failed':True});print('KILLED:',name,flush=True)
  finally:
   restored=run(original);assert restored.returncode==0,(name,restored.stderr)
 out.write_text(json.dumps({'signer_mutations':report,'restored_baselines':True},indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();main(a.build,a.out)
