"""Falsify native committee proof authentication, minimality and publication."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
from mutation_support import replace_once
ROOT=Path(__file__).resolve().parents[2]
CPP=[
 ('proof-anchor','proof.anchor_ != anchor','false'),
 ('proof-kind','proof.kind_ != 5','false'),
 ('proof-hash','hash.value() != proof.proof_hash_','false'),
 ('proof-object','proof.object_id_ != committee.value().snapshot().committee_id()','false'),
 ('proof-unrelated-values','minimal.ok()->get_hash() != root.value()->get_hash()','false'),
 ('proof-no-detached-cells','reachable.cells != static_cast<unsigned>(info.cell_count)','false'),
 ('proof-publication','if (!result.value()) return Error{"proof-publication"};',''),
 ('proof-carrier','if (!carrier.value().reference_.empty()) {','if (false) {'),
]
RUST=[
 ('proof-anchor','committee_proof.rs','proof.anchor != *anchor','false'),
 ('proof-kind','committee_proof.rs','proof.kind != 5','false'),
 ('proof-hash','committee_proof.rs','digest("proof", &raw)? != proof.proof_hash','false'),
 ('proof-object','committee_proof.rs','proof.object_id != object_id("committee", committee.snapshot().committee())?','false'),
 ('proof-unrelated-values','committee_proof.rs','native(minimal.serialize())?.repr_hash() != cell.repr_hash()','false'),
 ('proof-no-detached-cells','cells.rs','seen.len() != header.cells_count','false'),
 ('committee-proof','committee.rs','native(header.read_out_msg_queue_info())?;',''),
 ('committee-proof','committee.rs','native(header.read_accounts())?;',''),
]
def check_run(build,execute):
 result=subprocess.run(build,capture_output=True,text=True)
 if result.returncode:raise RuntimeError(result.stdout+result.stderr)
 return subprocess.run(execute,capture_output=True,text=True)
def apply(cases,build,execute,out):
 baseline=check_run(build,execute);assert baseline.returncode==0,baseline.stderr
 report=[]
 for label,source,before,after in cases:
  original=source.read_text()
  try:
   source.write_text(replace_once(original,before,after));result=check_run(build,execute)
   assert result.returncode==1 and result.stderr.startswith('ASSERTION: '+label) and 'panicked at' not in result.stderr,(label,result.stderr)
   report.append(dict(guard=label,compiled=True,assertion_failed=True));print('KILLED:',label,flush=True)
  finally:source.write_text(original)
 baseline=check_run(build,execute);assert baseline.returncode==0,baseline.stderr
 out.write_text(json.dumps(dict(committee_proof_mutations=report,restored_baselines=True),indent=2)+'\n')
def main(args):
 if args.language=='cpp':
  build=args.build.resolve();folder=build/'test/validator-auth-implementation'
  apply([(label,folder/'mutated-committee-proof.cpp',before,after) for label,before,after in CPP],['cmake','--build',str(build),'--target','test-p0-committee-proof-mutant','-j2'],[str(folder/'test-p0-committee-proof-mutant'),str(args.fixtures.resolve())],args.out)
 else:
  with tempfile.TemporaryDirectory(prefix='p0-rust-committee-proof-') as tmp:
   src=Path(tmp)/'src';src.mkdir();crate=src/'validator-auth-native'
   shutil.copytree(ROOT/'tosctl/src/validator-auth-native',crate,ignore=shutil.ignore_patterns('target'))
   for path in (ROOT/'tosctl/src').iterdir():
    if path.is_dir() and path.name not in ('target','validator-auth-native'):(src/path.name).symlink_to(path,target_is_directory=True)
   manifest=crate/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n');shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
   apply([(label,crate/'src'/file,before,after) for label,file,before,after in RUST],['cargo','build','--offline','--manifest-path',str(manifest),'--bin','committee-proof-conformance'],[str(crate/'target/debug/committee-proof-conformance'),str(args.fixtures.resolve())],args.out)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--language',choices=['cpp','rust'],required=True);p.add_argument('--build',type=Path);p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--out',type=Path,required=True);main(p.parse_args())
