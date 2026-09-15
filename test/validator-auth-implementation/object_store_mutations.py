"""Compile removals from the actual principal/anchor scoped object store."""
import argparse,json,subprocess
from pathlib import Path
from mutation_support import replace_once
MUTATIONS=[
 ('principal-scope','w.bytes(principal);',''),
 ('anchor-scope','write(w,anchor);',''),
 ('published-object-binding','if(canonical.value().reference_!=std::vector<ObjectRef>{ref})return Error{"published-object-binding"};',''),
 ('principal-object-quota','usage.objects>=4 ||',''),
 ('principal-byte-quota','ref.byte_length_>67108864-usage.bytes','false'),
 ('global-storage-quota','ref.byte_length_>limit_-used_','false'),
 ('storage-expiry','it->second.expires>now','true'),
 ('chunk-admission','auto checked=validate_chunk(ref,index,raw);','auto checked=Result<bool>(true);'),
]
def main(build,out):
 folder=build.resolve()/'test/validator-auth-implementation';report=[];source=folder/'mutated-object-store.cpp';original=source.read_text();target='test-p0-object-store-mutant'
 def run(text):
  source.write_text(text);subprocess.run(['cmake','--build',str(build),'--target',target,'-j2'],check=True,capture_output=True,text=True)
  return subprocess.run([str(folder/target)],capture_output=True,text=True)
 for name,before,after in MUTATIONS:
  try:
   baseline=run(original);assert baseline.returncode==0,(name,baseline.stderr)
   result=run(replace_once(original,before,after))
   assert result.returncode==1 and result.stderr.strip()=='ASSERTION: '+name,(name,result.returncode,result.stderr)
   report.append({'guard':name,'compiled':True,'assertion_failed':True});print('KILLED:',name,flush=True)
  finally:
   restored=run(original);assert restored.returncode==0,(name,restored.stderr)
 out.write_text(json.dumps({'object_store_mutations':report,'restored_baselines':True},indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();main(a.build,a.out)
