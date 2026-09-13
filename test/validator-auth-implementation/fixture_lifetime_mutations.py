"""Remove actual fixture hash ownership and fail before any poisoned-memory read."""
import argparse,json,os,subprocess
from pathlib import Path
from mutation_support import replace_once

def main(args):
 build=args.build.resolve();folder=build/'test/validator-auth-implementation/lifetime';report=[]
 env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:detect_stack_use_after_return=1',UBSAN_OPTIONS='halt_on_error=1')
 for file,probe,before,after in [
  ('native-fixture.h','committee','auto owned_hash = root->get_hash(); auto raw = owned_hash.as_slice();','auto raw = root->get_hash().as_slice();'),
  ('proof-test.cpp','proof','auto owned_hash = inner->get_hash(0); auto hash = owned_hash.as_slice();','auto hash = inner->get_hash(0).as_slice();')]:
  source=folder/file;original=source.read_text();target=f'test-p0-{probe}-lifetime-mutant'
  def run(text):
   source.write_text(text)
   build_result=subprocess.run(['cmake','--build',str(build),'--target',target,'-j2'],capture_output=True,text=True)
   if build_result.returncode:raise RuntimeError(build_result.stdout+build_result.stderr)
   return subprocess.run([str(folder.parent/target)],capture_output=True,text=True,env=env)
  try:
   baseline=run(original);assert baseline.returncode==0,baseline.stdout+baseline.stderr
   result=run(replace_once(original,before,after))
   assert result.returncode==1 and result.stderr.strip()=='ASSERTION: fixture-hash-lifetime',(file,result.returncode,result.stderr)
   report.append(dict(source=file,compiled=True,assertion_failed=True,no_poisoned_read=True));print('KILLED: fixture hash ownership',file,flush=True)
  finally:
   restored=run(original);assert restored.returncode==0,restored.stdout+restored.stderr
 args.out.write_text(json.dumps(dict(fixture_lifetime_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True);main(p.parse_args())
