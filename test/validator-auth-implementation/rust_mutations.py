"""Compile and execute Rust production guard mutations in an isolated crate."""
import argparse,json,shutil,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
MUTATIONS=[
 ('public-subgroup','crypto.rs','p == EdwardsPoint::identity() || !p.is_torsion_free()','false','core'),
 ('signature-equation','crypto.rs','s * ED25519_BASEPOINT_POINT == rpoint + h * self.point','true','core'),
 ('expected-duty','verify.rs','if duty != expected {','if false {','core'),
 ('quorum','verify.rs','if quorum && signed_weight < required_weight {','if false {','core'),
 ('all-signatures','verify.rs','if !key.verify(&statement, signature) {','if false {','core'),
 ('duplicate-json-key','transport.rs','if fields.contains_key(&key) {','if false {','transport'),
 ('error-retry','transport.rs','if e.retryable != u8::from(read && (10..=12).contains(&e.code)) {','if false {','transport'),
]
def main(args):
 report=[]
 with tempfile.TemporaryDirectory(prefix='p0-rust-mutations-') as d:
  d=Path(d);shutil.copytree(ROOT/'tosctl/src/validator-auth',d/'crate')
  manifest=d/'crate/Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n')
  shutil.copy2(ROOT/'tosctl/src/Cargo.lock',d/'crate/Cargo.lock')
  def build():
   subprocess.run(['cargo','build','--offline','--manifest-path',str(manifest),'--bin','conformance'],capture_output=True,text=True,check=True)
   return d/'crate/target/debug/conformance'
  def test(suite,binary):
   if suite=='transport':command=[sys.executable,str(ROOT/'test/validator-auth-implementation/check_transport.py'),'--driver',str(binary)]
   else:command=[sys.executable,str(ROOT/'test/validator-auth-implementation/check.py'),'--cpp',str(args.cpp.resolve()),'--rust',str(binary),'--core-only','--out',str(d/'core.json')]
   return subprocess.run(command,capture_output=True,text=True)
  binary=build()
  for suite in ('core','transport'):
   p=test(suite,binary);assert p.returncode==0,p.stderr
  print('BASELINE: Rust core and transport',flush=True)
  for name,file,before,after,suite in MUTATIONS:
   path=d/'crate/src'/file;original=path.read_text();assert original.count(before)==1,name
   path.write_text(original.replace(before,after))
   try:
    p=test(suite,build())
    if p.returncode!=1 or 'AssertionError' not in p.stderr or 'RuntimeError' in p.stderr:raise AssertionError((name,'survived or invalid kill',p.stderr))
    report.append({'guard':name,'compiled':True,'assertion_failed':True});print('KILLED:',name,flush=True)
   finally:path.write_text(original)
  binary=build()
  for suite in ('core','transport'):
   p=test(suite,binary);assert p.returncode==0,p.stderr
 args.out.write_text(json.dumps({'production_rust_mutations':report,'restored_baselines':True},indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--cpp',type=Path,required=True);p.add_argument('--out',type=Path,required=True);main(p.parse_args())
