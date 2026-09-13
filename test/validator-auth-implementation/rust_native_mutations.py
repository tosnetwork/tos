"""Compile independent Rust native proof/cell guard removals against native fixtures."""
import argparse,json,shutil,subprocess,sys,tempfile
from pathlib import Path
from mutation_support import replace_once
ROOT=Path(__file__).resolve().parents[2]
MUTATIONS=[
 ('hash-binding','cells.rs','Sha256::digest(&raw).as_slice() != expected','false'),
 ('budget-before-allocation','cells.rs','length > remaining','false'),
 ('canonical-partition','cells.rs','n != expected || n == 0','false || n == 0'),
 ('proof-9','proof.rs','root.repr_hash().as_slice() != &anchor.state','false'),
 ('proof-8','proof.rs','state.global_id() != network','false'),
 ('proof-19','proof.rs','proof.anchor != *anchor','false'),
 ('proof-12','proof.rs','digest("proof", &raw)? != proof.proof_hash','false'),
 ('proof-17','proof.rs','proof.kind != kind','false'),
 ('proof-18','proof.rs','proof.object_id != id','false'),
 ('proof-10','proof.rs','native(minimal.serialize())?.repr_hash() != cell.repr_hash()','false'),
 ('proof-5','proof.rs','expected != response','false'),
 ('proof-13','proof.rs','native(cap.get_next_u64())? & 1024 == 0','false'),
 ('proof-14','proof.rs','maximum > 400','false'),
 ('proof-15','proof.rs','native(p0.get_next_u16())? != 1','native(p0.get_next_u16())? == 65535'),
 ('proof-16','proof.rs','chain_domain == [0; 32]','false'),
 ('proof-11','cells.rs','seen.len() != header.cells_count','false'),
 ('proof-5','proof.rs','verify_native_response(method, request, response, &self.anchor, self.network, reader)','Ok(VerifiedNativeResponse { bytes: response.to_vec(), anchor: self.anchor.clone(), method })'),
]
def main(args):
 report=[]
 with tempfile.TemporaryDirectory(prefix='p0-rust-native-mut-') as tmp:
  tmp=Path(tmp);crate=tmp/'crate';shutil.copytree(ROOT/'tosctl/src/validator-auth-native',crate)
  manifest=crate/'Cargo.toml';text=manifest.read_text()
  text=text.replace('"../block"',json.dumps(str(ROOT/'tosctl/src/block'))).replace('"../validator-auth"',json.dumps(str(ROOT/'tosctl/src/validator-auth')))
  manifest.write_text(text+'\n[workspace]\n');shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
  binary=crate/'target/debug/native-conformance'
  def build():subprocess.run(['cargo','build','--offline','--manifest-path',str(manifest),'--bin','native-conformance'],check=True,capture_output=True,text=True)
  def run():
   return subprocess.run([sys.executable,str(ROOT/'test/validator-auth-implementation/check_native.py'),'--rust',str(binary),'--cells',str(args.cells.resolve()),'--proofs',str(args.proofs.resolve()),'--proof-only','--out',str(tmp/'result.json')],capture_output=True,text=True)
  build();base=run();assert base.returncode==0,base.stderr
  for label,file,before,after in MUTATIONS:
   source=crate/'src'/file;original=source.read_text();source.write_text(replace_once(original,before,after))
   try:
    build();result=run()
    assert result.returncode==1 and 'AssertionError:' in result.stderr and repr(label) in result.stderr and 'RuntimeError' not in result.stderr,(label,'invalid kill',result.stderr)
    report.append(dict(guard=before,case=label,compiled=True,assertion_failed=True));print('KILLED:',file,label,before,flush=True)
   finally:source.write_text(original)
  build();base=run();assert base.returncode==0,base.stderr
 args.out.write_text(json.dumps(dict(rust_native_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--cells',type=Path,required=True);p.add_argument('--proofs',type=Path,required=True);p.add_argument('--out',type=Path,required=True);main(p.parse_args())
