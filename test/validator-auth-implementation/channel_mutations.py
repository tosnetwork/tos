"""Require actual OS channel admission guards to fail semantic tests."""
import argparse,json,subprocess,tempfile
from pathlib import Path
from mutation_support import replace_once
MUTATIONS=[
 ('preallocation-bound','size>max_frame','false'),
 ('local-version','if(!std::equal(header.begin(),header.begin()+4,"P0X1"))return Error{"local-version"};',''),
 ('server-peer-credentials','if(credentials.value()!=principal_)return Error{"local-unauthorized"};',''),
 ('client-peer-credentials','if(credentials.value()!=expected)return Error{"local-unauthorized"};',''),
 ('private-parent','(dir.st_mode&0777)!=0700','false'),
 ('socket-mode','::chmod(path.c_str(),0600)<0 ||',''),
]
def main(build,out):
 folder=build.resolve()/'test/validator-auth-implementation';report=[]
 source=folder/'mutated-local-channel.cpp';original=source.read_text();target='test-p0-local-channel-mutant'
 def run(text):
  source.write_text(text)
  subprocess.run(['cmake','--build',str(build),'--target',target,'-j2'],check=True,capture_output=True,text=True)
  with tempfile.TemporaryDirectory(prefix='p0-channel-',dir='/tmp') as temp:
   return subprocess.run([str(folder/target),str(Path(temp)/'data')],capture_output=True,text=True)
 for name,before,after in MUTATIONS:
  try:
   base=run(original);assert base.returncode==0,(name,base.stderr)
   result=run(replace_once(original,before,after))
   assert result.returncode==1 and result.stderr.strip()=='ASSERTION: '+name,(name,result.returncode,result.stderr)
   report.append({'guard':name,'compiled':True,'assertion_failed':True});print('KILLED:',name,flush=True)
  finally:
   restored=run(original);assert restored.returncode==0,(name,restored.stderr)
 out.write_text(json.dumps({'channel_mutations':report,'restored_baselines':True},indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();main(a.build,a.out)
