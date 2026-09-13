"""Remove production API bindings; successful parses must reach wrong acceptance."""
import argparse,json,subprocess,sys
from pathlib import Path
from mutation_support import replace_once
MUTATIONS=[
 ('verified-signers','r.signers_ != signers ||','', 'verified-signers-omitted','verified-signers',None),
 ('receipt-result-hash','b.result_hash_ != hash.value() ||','', 'receipt-3-result_hash','result-receipt-binding',None),
 ('response-anchor',' || q != r','', 'anchor-8','response-anchor',None),
 ('proof-object',' || proof.object_id_ != id','', 'proof-binding','proof-binding',None),
 ('stage-owner','q.authorizations_.owner_.size() != 1 ||','', 'stage-authorizations','stage-authorizations',None),
 ('preparation-mode',' || (q.provider_handle_ == Hash{}) != (q.mode_ == 0)','', 'preparation-mode','preparation-mode',None),
 ('sign-permit-network','p.network_ != d.network_ ||','', 'sign-permit-association','sign-permit-association',None),
 ('capability-interface','if(r.interface_digest_ != interface_fingerprint)return Error{"interface-digest"};','', 'interface-digest','interface-digest','case 1:'),
]
def main(build,out):
 folder=build.resolve()/'test/validator-auth-implementation';source=folder/'mutated-api-semantics.cpp';original=source.read_text();report=[]
 script=Path(__file__).with_name('check_api_semantics.py')
 def run(text):
  source.write_text(text)
  subprocess.run(['cmake','--build',str(build),'--target','test-p0-api-semantics-mutant','-j2'],check=True,capture_output=True,text=True)
  return subprocess.run([sys.executable,str(script),'--driver',str(folder/'test-p0-api-semantics-mutant')],capture_output=True,text=True)
 for name,before,after,label,error,scope in MUTATIONS:
  try:
   baseline=run(original);assert baseline.returncode==0,(name,baseline.stderr)
   if scope:
    start=original.index(scope,original.index('Result<bool> validate_api_response('));end=original.index('case 2:',start)
    mutant=original[:start]+replace_once(original[start:end],before,after)+original[end:]
   else:mutant=replace_once(original,before,after)
   result=run(mutant)
   expected='AssertionError: '+repr((label,error,0,''))
   assert result.returncode==1 and result.stderr.strip().endswith(expected),(name,result.returncode,result.stderr)
   report.append({'guard':name,'compiled':True,'assertion_failed':True});print('KILLED:',name,flush=True)
  finally:
   restored=run(original);assert restored.returncode==0,(name,restored.stderr)
 out.write_text(json.dumps({'api_semantic_mutations':report,'restored_baselines':True},indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();main(a.build,a.out)
