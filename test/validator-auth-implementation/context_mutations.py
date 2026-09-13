"""Compile current-authority and context mutations; require the intended assertion."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
from mutation_support import replace_once
ROOT=Path(__file__).resolve().parents[2]
# Guard name, failing independent case, original production expression, replacement.
CPP=[
 ('genesis-root','context-1-genesis_root','context.genesis_root == Hash{} ||',''),
 ('chain-domain','context-1-chain_domain','|| context.chain_domain == Hash{}',''),
 ('session-committee','session-full-origin','w.bytes(snapshot.committee_id());',''),
 ('session-options','session-full-origin','w.bytes(origin.native_options_hash);',''),
 ('session-vertical','session-full-origin','w.integer(origin.vertical_seqno);',''),
 ('session-key-block','session-full-origin','w.integer(origin.key_block_seqno);',''),
 ('admin-target','admin-session-target','start.value().insert(start.value().end(), target.begin(), target.end());',''),
 ('duty-byte-bound','duty-payload-bound','if (payload.size() > 4096) return Error{"payload-bound"};',''),
 ('duty-session','duty-session-zero','if (session == Hash{}) return Error{"session"};',''),
 ('admin-masterchain','duty-admin-shard-normalization','duty.workchain_ = -1;',''),
 ('pop-bound','pop-preimage-bound','w.blob(raw.value(), 32768);','w.blob(raw.value(), 65536);'),
 ('identity-current-key','identity-current-key','!active ||',''),
]
RUST=[
 ('genesis-root','context-1-genesis_root','context.genesis_root == [0; 32] ||',''),
 ('genesis-file','context-1-genesis_file','|| context.genesis_file == [0; 32]',''),
 ('chain-domain','context-1-chain_domain','|| context.chain_domain == [0; 32]',''),
 ('session-committee','session-full-origin','bytes.extend_from_slice(snapshot.committee_id());',''),
 ('session-options','session-full-origin','bytes.extend_from_slice(&origin.native_options_hash);',''),
 ('session-vertical','session-full-origin','bytes.extend_from_slice(&origin.vertical_seqno.to_be_bytes());',''),
 ('session-key-block','session-full-origin','bytes.extend_from_slice(&origin.key_block_seqno.to_be_bytes());',''),
 ('admin-target','admin-session-target','bytes.extend_from_slice(target);',''),
 ('duty-byte-bound','duty-payload-bound','if payload.len() > 4096 { return Err(Error("payload-bound")); }',''),
 ('duty-session','duty-session-zero','if session == [0; 32] { return Err(Error("session")); }',''),
 ('admin-masterchain','duty-admin-shard-normalization','workchain: if role == 5 { -1 } else { snapshot.committee().workchain },','workchain: snapshot.committee().workchain,'),
 ('pop-domain','pop-chain-domain','if context.chain_domain == [0; 32] { return Err(Error("chain-domain")); }',''),
 ('pop-domain-preimage','pop-preimage','bytes.extend_from_slice(&context.chain_domain);',''),
 ('pop-bound','pop-preimage-bound','if raw.len() > 32768 { return Err(Error("blob-bound")); }',''),
 ('pop-descriptor','pop-descriptor-bytes','if update.new_key != encode(key)? { return Err(Error("possession-key")); }',''),
 ('pop-update','pop-update-binding','proof.update_id != object_id("update", update)? ||',''),
 ('pop-keyref','pop-keyref-binding','|| proof.key != key_reference(key)?',''),
 ('pop-signature','pop-signature','if !admitted.verify(&preimage, &proof.signature) { return Err(Error("possession-signature")); }',''),
 ('pop-operation','pop-operation','!matches!(update.operation, 1 | 2) ||',''),
 ('pop-key-identity','pop-descriptor-identity-1','|| update.identity != key.identity',''),
 ('pop-key-suite','pop-descriptor-suite-2','|| key.suite != 1',''),
 ('pop-key-role','pop-descriptor-role-0','|| !(1..=5).contains(&key.role)',''),
 ('pop-capacity','pop-descriptor-capacity_limit-1','|| key.capacity_limit != 0',''),
 ('identity-budget','identity-certificate-budget','if encode(certificate)?.len() > 524288 { return Err(Error("certificate-budget")); }',''),
 ('identity-age','identity-stale','if age > 128 { return Err(Error("admin-freshness")); }',''),
 ('identity-future','identity-future-anchor','inclusion.checked_sub(expected.anchor_mc).ok_or(Error("admin-freshness"))?','inclusion.saturating_sub(expected.anchor_mc)'),
 ('identity-context','identity-expected-duty','certificate.duty != *expected ||',''),
 ('identity-target','identity-target','if update.identity != identity.identity { return Err(Error("identity-target")); }',''),
 ('identity-count','identity-key-count-2','|| keys.len() != 1','|| keys.is_empty()'),
 ('identity-start','identity-key-valid_from','key.valid_from > inclusion ||',''),
 ('identity-end','identity-key-valid_until','key.valid_until <= inclusion','key.valid_until < inclusion'),
 ('identity-current-key','identity-current-key','!active ||',''),
 ('identity-signed-keyref','identity-signed-keyref','|| reference != signed',''),
 ('identity-signature','identity-signature','if !admitted.verify(&statement, &component.signature) { return Err(Error("identity-signature")); }',''),
]
def validate(result,label=None):
 if label is None:assert result.returncode==0,result.stderr
 else:assert result.returncode==1 and result.stderr.strip().endswith('ASSERTION: '+label) and 'panicked at' not in result.stderr,(label,result.returncode,result.stderr)
def checked(command):
 p=subprocess.run(command,capture_output=True,text=True)
 if p.returncode:raise RuntimeError('build failed: '+p.stdout+p.stderr)
def mutate(path,cases,run):
 original=path.read_text();report=[];validate(run())
 try:
  for guard,label,before,after in cases:
   # The suite and capacity terms occur in both PoP and identity admission.
   if guard.startswith('pop-'):
    start=original.index('pub fn verify_possession(') if 'pub fn verify_possession(' in original and guard not in ('pop-domain','pop-domain-preimage','pop-bound') else 0
    end=original.index('pub fn verify_identity_certificate(') if start else len(original)
    text=original[:start]+replace_once(original[start:end],before,after)+original[end:]
   else:text=replace_once(original,before,after)
   path.write_text(text);validate(run(),label);report.append(dict(guard=guard,assertion=label,compiled=True,assertion_failed=True));print('KILLED:',guard,flush=True)
 finally:path.write_text(original);validate(run())
 return report
def main(args):
 if args.language=='cpp':
  folder=args.build.resolve()/'test/validator-auth-implementation';path=folder/'context-mutated.cpp'
  def run():
   checked(['cmake','--build',str(args.build.resolve()),'--target','test-p0-context-parity-mutant','-j2'])
   return subprocess.run([str(folder/'test-p0-context-parity-mutant'),str(args.fixtures.resolve())],capture_output=True,text=True)
  report=mutate(path,CPP,run)
 else:
  with tempfile.TemporaryDirectory(prefix='p0-context-mutations-') as tmp:
   root=Path(tmp)
   for part in ('validator-auth','validator-auth-crypto'):shutil.copytree(ROOT/'tosctl/src'/part,root/part)
   crate=root/'validator-auth';manifest=crate/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n');shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
   def run():
    checked(['cargo','build','--offline','--manifest-path',str(manifest),'--bin','context-conformance'])
    return subprocess.run([str(crate/'target/debug/context-conformance'),str(args.fixtures.resolve())],capture_output=True,text=True)
   report=mutate(crate/'src/context.rs',RUST,run)
 args.out.write_text(json.dumps(dict(language=args.language,context_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--language',choices=['cpp','rust'],required=True);p.add_argument('--build',type=Path);p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--out',type=Path,required=True);main(p.parse_args())
