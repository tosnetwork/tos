"""Prove benchmark controls reach both native signature verifiers and context binding."""
import argparse,json,subprocess
from pathlib import Path
from mutation_support import replace_once
CASES=[
 ('p0-negative-control','verify','if (!valid.value()) return Error{"signature"};',''),
 ('legacy-signature-negative-control','signature-set','TRY_STATUS(E->check_signature(data, sig.signature.as_slice()));',''),
 ('legacy-negative-control','signature-set','if (block_id != expected_block_id) { return td::Status::Error("block id mismatch"); }',''),
]
def run(args):
 folder=args.build.resolve()/'test/validator-auth-implementation';report=[]
 def execute(module,text):
  (folder/f'benchmark-mutated-{module}.cpp').write_text(text)
  compiled=subprocess.run(['cmake','--build',str(args.build.resolve()),'--target',f'benchmark-p0-{module}-mutant','-j2'],capture_output=True,text=True)
  if compiled.returncode:raise RuntimeError(compiled.stdout+compiled.stderr)
  return subprocess.run([str(folder/f'benchmark-p0-{module}-mutant'),'--check'],capture_output=True,text=True)
 for label,module,before,after in CASES:
  original=(folder/f'benchmark-mutated-{module}.cpp').read_text()
  baseline=execute(module,original);assert baseline.returncode==0,baseline.stderr
  try:
   result=execute(module,replace_once(original,before,after))
   assert result.returncode==1 and result.stderr.strip()=='ASSERTION: '+label,(label,result.stderr)
   report.append(dict(guard=label,compiled=True,assertion_failed=True));print('KILLED:',label,flush=True)
  finally:
   baseline=execute(module,original);assert baseline.returncode==0,baseline.stderr
 args.out.write_text(json.dumps(dict(benchmark_control_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True);run(p.parse_args())
