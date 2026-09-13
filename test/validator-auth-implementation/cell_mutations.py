"""Compile native cell guard removals against the real VM cell library."""
import argparse,json,subprocess
from pathlib import Path
from mutation_support import replace_once

def main(build,out):
 build=build.resolve();folder=build/'test/validator-auth-implementation';source=folder/'mutated-cells.cpp';original=source.read_text();results=[]
 def run(text):
  source.write_text(text)
  subprocess.run(['cmake','--build',str(build),'--target','test-p0-cells-mutant','-j2'],check=True,capture_output=True,text=True)
  return subprocess.run([str(folder/'test-p0-cells-mutant')],capture_output=True,text=True)
 try:
  baseline=run(original);assert baseline.returncode==0,baseline.stderr
  for name,before in [('hash-binding','if(actual!=expected)return Error{"auth-bytes-hash"};'),('canonical-partition','n!=expected||')]:
   p=run(replace_once(original,before,''));assert p.returncode==1 and p.stderr.strip()=='ASSERTION: '+name,(name,p.stderr)
   results.append({'guard':name,'compiled':True,'assertion_failed':True})
 finally:
  restored=run(original);assert restored.returncode==0,restored.stderr
 out.write_text(json.dumps({'native_cell_mutations':results,'restored_baseline':True},indent=2)+'\n');print('PASS: 2 native cell mutations')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();main(a.build,a.out)
