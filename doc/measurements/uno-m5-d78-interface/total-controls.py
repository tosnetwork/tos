from pathlib import Path
import shutil,subprocess,os
repo=Path('/home/tomi/tos-m2');root=Path('/tmp/b-d78-rust/tree');root.mkdir(exist_ok=True)
for crate in ('crypto','prover'):
 dest=root/'uno'/crate;dest.mkdir(parents=True,exist_ok=True)
 for name in ('src','include','fixtures','Cargo.toml','Cargo.lock','build.rs','cbindgen.toml'):
  src=repo/'uno'/crate/name
  if src.is_dir():shutil.copytree(src,dest/name,dirs_exist_ok=True)
  elif src.is_file():shutil.copy2(src,dest/name)
 if (repo/'uno'/crate/'vendor').is_dir() and not (dest/'vendor').exists():(dest/'vendor').symlink_to(repo/'uno'/crate/'vendor',target_is_directory=True)
(root/'crypto').mkdir(exist_ok=True)
if not (root/'crypto/test').exists(): (root/'crypto/test').symlink_to(repo/'crypto/test',target_is_directory=True)
p=root/'uno/crypto/src/withdrawal_statement.rs';original=p.read_text()
cases=[('fee-in-total',original.replace('self.principal.checked_add(self.outward_fee)','self.principal.checked_add(self.outward_fee).and_then(|v| v.checked_add(self.operation_fee))'),'withdrawal_real_proof_and_wrong_generated_points','left: 165'),('unchecked-total',original.replace('self.principal.checked_add(self.outward_fee)','Some(self.principal.wrapping_add(self.outward_fee))'),'withdrawal_amount_overflow_and_public_identity_binding','amounts.total().is_err()')]
for name,mutation,test,diagnostic in cases:
 assert mutation!=original;p.write_text(mutation)
 r=subprocess.run(['cargo','test','--manifest-path',str(root/'uno/prover/Cargo.toml'),'--locked','--offline',test,'--','--nocapture'],env=dict(os.environ,CARGO_TARGET_DIR=str(repo/'uno/prover/target')),text=True,capture_output=True)
 Path('/tmp/b-d78-rust/'+name+'.log').write_text(r.stdout+r.stderr+'\nexit='+str(r.returncode)+'\n')
 print(name,r.returncode,flush=True);assert r.returncode==101 and diagnostic in r.stdout+r.stderr
p.write_text(original)
