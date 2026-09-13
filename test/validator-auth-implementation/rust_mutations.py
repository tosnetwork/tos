"""Compile and execute Rust production guard mutations in an isolated crate."""
import argparse,json,shutil,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
MUTATIONS=[
 ('lifecycle-predecessor','lifecycle.rs','if update.previous != predecessor {','if false {','lifecycle'),
 ('lifecycle-block-gap','lifecycle.rs','if parent_coordinate >= u32::MAX - 1 || parent_coordinate.checked_add(1) != Some(coordinate) {','if false {','lifecycle'),
 ('lifecycle-epoch','lifecycle.rs','if key.epoch <= epoch || key.epoch == u64::MAX {','if false {','lifecycle'),
 ('lifecycle-bootstrap','lifecycle.rs','if initial && (op != 1 || target.0 != 5) {','if false {','lifecycle'),
 ('lifecycle-authority','lifecycle.rs','if needed && !callback(&rows[0])? {','if false {','lifecycle'),
 ('lifecycle-snapshot-due','lifecycle.rs','if state.pending.iter().any(|p| p.effective_from <= anchor) {','if false {','lifecycle'),
 ('lifecycle-snapshot-validity','lifecycle.rs','if key.valid_from > anchor || key.valid_until <= anchor {','if false {','lifecycle'),
 ('public-subgroup','crypto.rs','p == EdwardsPoint::identity() || !p.is_torsion_free()','false','core'),
 ('signature-equation','crypto.rs','s * ED25519_BASEPOINT_POINT == rpoint + h * self.point','true','core'),
 ('expected-duty','verify.rs','if duty != expected {','if false {','core'),
 ('quorum','verify.rs','if quorum && signed_weight < required_weight {','if false {','core'),
 ('all-signatures','verify.rs','if !key.verify(&statement, signature) {','if false {','core'),
 ('duplicate-json-key','transport.rs','if fields.contains_key(&key) {','if false {','transport'),
 ('error-retry','transport.rs','if e.retryable != u8::from(read && (10..=12).contains(&e.code)) {','if false {','transport'),
 ('api-verified-signers','api_semantics.rs','r.signers != signers || ','','api'),
 ('api-receipt-hash','api_semantics.rs','|| b.result_hash != digest("api-result", &bytes)?','','api'),
 ('api-response-anchor','api_semantics.rs','method >= 8 && anchor_prefix(request)? != anchor_prefix(response)?','false','api'),
 ('api-proof-object','api_semantics.rs','|| p.object_id != *id','','api'),
 ('api-stage-owner','api_semantics.rs','q.authorizations.owner.len() != 1','false','api'),
 ('api-preparation-mode','api_semantics.rs','|| (q.provider_handle == [0; 32]) != (q.mode == 0)','','api'),
 ('api-sign-network','api_semantics.rs','p.network != d.network','false','api'),
 ('service-signature','service_auth.rs','if !found.admitted.verify(raw, &c.signature) {','if false {','service'),
 ('service-current-policy','service_auth.rs','if self.current.get(&value.body.issuer) != Some(&value.body.service_policy) {','if false {','service'),
 ('service-witness','service_auth.rs','if !witness.contains(body.journal_sequence, &object_id("receipt_body", body)?)? {','if false {','service'),
 ('terminal-state','service_auth.rs','if (old.state == 2 || old.state == 3) && old != next {','if false {','service'),
 ('object-chunk-hash','transfer.rs','if chunk_hash(&manifest.object_id, index, bytes)? != manifest.chunk_hashes[i] {','if false {','api'),
 ('object-whole-hash','transfer.rs','if transferred_id(kind, &out)? != reference.object_id {','if false {','api'),
 ('object-aggregate','transfer.rs','self.remaining = self.remaining.checked_sub(size).ok_or(Error("attachment-budget"))?;','','api'),
]
EXPECTED={'api-verified-signers': ('verified-signers-omitted', 'verified-signers'), 'api-receipt-hash': ('receipt-3-result_hash', 'result-receipt-binding'), 'api-response-anchor': ('anchor-8', 'response-anchor'), 'api-proof-object': ('proof-binding', 'proof-binding'), 'api-stage-owner': ('stage-authorizations', 'stage-authorizations'), 'api-preparation-mode': ('preparation-mode', 'preparation-mode'), 'api-sign-network': ('sign-permit-association', 'sign-permit-association'), 'service-signature': ('permit-signature', 'service-signature'), 'service-current-policy': ('stale-policy', 'stale-permit-policy'), 'service-witness': ('receipt-frontier', 'receipt-frontier'), 'terminal-state': ('terminal-regression', 'terminal-state-regression'), 'object-chunk-hash': ('chunk-hash', 'chunk-hash'), 'object-whole-hash': ('referenced-whole-hash', 'object-hash'), 'object-aggregate': ('aggregate-attachment-budget', 'attachment-budget')}
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
   if suite=='lifecycle':
    command=[sys.executable,str(ROOT/'test/validator-auth-implementation/check_lifecycle.py'),'--driver',str(binary),'--out',str(d/'lifecycle.json')]
   elif suite in ('api','service'):
    script='check_api_semantics.py' if suite=='api' else 'check_service_auth.py'
    command=[sys.executable,str(ROOT/'test/validator-auth-implementation'/script),'--driver',str(binary)]
   elif suite=='transport':command=[sys.executable,str(ROOT/'test/validator-auth-implementation/check_transport.py'),'--driver',str(binary)]
   else:command=[sys.executable,str(ROOT/'test/validator-auth-implementation/check.py'),'--cpp',str(args.cpp.resolve()),'--rust',str(binary),'--core-only','--out',str(d/'core.json')]
   return subprocess.run(command,capture_output=True,text=True)
  binary=build()
  for suite in ('core','transport','api','service','lifecycle'):
   p=test(suite,binary);assert p.returncode==0,p.stderr
  print('BASELINE: Rust core and transport',flush=True)
  for name,file,before,after,suite in MUTATIONS:
   path=d/'crate/src'/file;original=path.read_text();assert original.count(before)==1,name
   path.write_text(original.replace(before,after))
   try:
    p=test(suite,build())
    if p.returncode!=1 or 'AssertionError' not in p.stderr or 'RuntimeError' in p.stderr:raise AssertionError((name,'survived or invalid kill',p.stderr))
    if name in EXPECTED:
     label,error=EXPECTED[name]
     assert p.stderr.strip().endswith('AssertionError: '+repr((label,error,0,''))),(name,p.stderr)
    report.append({'guard':name,'compiled':True,'assertion_failed':True});print('KILLED:',name,flush=True)
   finally:path.write_text(original)
  binary=build()
  for suite in ('core','transport','api','service','lifecycle'):
   p=test(suite,binary);assert p.returncode==0,p.stderr
 args.out.write_text(json.dumps({'production_rust_mutations':report,'restored_baselines':True},indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--cpp',type=Path,required=True);p.add_argument('--out',type=Path,required=True);main(p.parse_args())
