"""Compile native authority integration and ordered-state mutations, then restore."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
from context_mutations import checked,mutate,ROOT
CPP=[
 ('apply-domain','native-wrong-current-domain','current_.chain_domain() != context_.chain.chain_domain ||',''),
 ('apply-policy','native-policy-before-authorization','if (current_.current_policy() != context_.governing.policy_id()) return Error{"authority-current-policy"};',''),
 ('apply-masterchain','native-shard-governance','committee.workchain_ != -1 ||',''),
 ('apply-owner-fork','native-wrong-finalized-fork','anchor.value(), context_.chain, reader_','proof.proof_.anchor_, context_.chain, reader_'),
 ('apply-owner-verifier','native-wrong-finalized-fork','if (!verified.ok()) return verified.error();',''),
 ('apply-possession-verifier','native-pop-signature','return verify_possession(context_.chain, update, key, proof);','return true;'),
 ('apply-identity-verifier','native-old-admin-after-rotation','return verify_identity_certificate(certificate.value(), expected.value(), identity, keys.value(), inclusion);','return true;'),
 ('apply-current-archive','native-same-block-current-key','select_identity_keys(identity, current_, inclusion, {{5, 1, 1}})','Result<std::vector<Key>>(std::vector<Key>{context_.governing.committee().members_[0].keys_[4]})'),
 ('apply-expectation','native-claimed-duty-is-not-context','verify_identity_certificate(certificate.value(), expected.value(), identity, keys.value(), inclusion)','verify_identity_certificate(certificate.value(), certificate.value().duty_, identity, keys.value(), inclusion)'),
]
RUST=[
 ('apply-domain','native-wrong-current-domain','self.current.chain_domain() != &self.context.chain.chain_domain ||',''),
 ('apply-policy','native-policy-before-authorization','if self.current.current_policy() != self.context.governing.policy_id() { return Err(Error("authority-current-policy")); }',''),
 ('apply-masterchain','native-shard-governance','committee.workchain != -1 ||',''),
 ('apply-owner-fork','native-wrong-finalized-fork','&anchor, &self.context.chain, &mut reader','&proof.proof.anchor, &self.context.chain, &mut reader'),
 ('apply-owner-verifier','native-wrong-finalized-fork','verify_owner_execution(proof, update, identity, &anchor, &self.context.chain, &mut reader)?;',''),
 ('apply-possession-verifier','native-pop-signature','verify_possession(&self.context.chain, update, key, proof)?;',''),
 ('apply-identity-verifier','native-old-admin-after-rotation','verify_identity_certificate(&certificate, &expected, identity, &keys, inclusion)?;',''),
 ('apply-current-archive','native-same-block-current-key','select_identity_keys(identity, self.current, inclusion, &[(5, 1, 1)])?','vec![self.context.governing.committee().members[0].keys[4].clone()]'),
 ('apply-expectation','native-claimed-duty-is-not-context','verify_identity_certificate(&certificate, &expected, identity, &keys, inclusion)?','verify_identity_certificate(&certificate, &certificate.duty, identity, &keys, inclusion)?'),
]
CPP_STATE=[
 ('apply-policy-selection','native-policy-before-authorization','next.current_policy_ = id.value();',''),
 ('apply-revision','native-batch-one-revision','next.revision_ = revision_ + 1;',''),
]
RUST_STATE=[
 ('apply-policy-selection','native-policy-before-authorization','next.current_policy = object_id("policy", next.policy_at(at)?)?;',''),
 ('apply-revision','native-admin-rotation','next.revision = self.revision.checked_add(1).ok_or(Error("registry-revision"))?;',''),
]
def main(a):
 if a.language=='cpp':
  folder=a.build.resolve()/'test/validator-auth-implementation'
  def runner(target):
   def run():
    checked(['cmake','--build',str(a.build.resolve()),'--target',target,'-j2'])
    with tempfile.TemporaryDirectory(prefix='p0-apply-cases-') as tmp:
     for i,inputs in enumerate((a.inputs,a.shard_inputs)):
      result=subprocess.run([str(folder/target),'verify',str(inputs.resolve()),str(Path(tmp)/str(i))],capture_output=True,text=True)
      if result.returncode:return result
     return result
   return run
  report=mutate(folder/'native-apply-mutated.cpp',CPP,runner('test-p0-native-apply-mutant'))
  report+=mutate(folder/'native-state-mutated.cpp',CPP_STATE,runner('test-p0-native-state-mutant'))
 else:
  with tempfile.TemporaryDirectory(prefix='p0-native-apply-mutations-') as tmp:
   root=Path(tmp)
   for part in ('validator-auth-native','validator-auth'):shutil.copytree(ROOT/'tosctl/src'/part,root/part)
   for part in (ROOT/'tosctl/src').iterdir():
    if part.is_dir() and part.name not in ('target','validator-auth-native','validator-auth'):(root/part.name).symlink_to(part,target_is_directory=True)
   crate=root/'validator-auth-native';manifest=crate/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n');shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
   def run():
    checked(['cargo','build','--offline','--manifest-path',str(manifest),'--bin','native-apply-conformance'])
    for fixtures in (a.fixtures,a.shard_fixtures):
     result=subprocess.run([str(crate/'target/debug/native-apply-conformance'),str(fixtures.resolve())],capture_output=True,text=True)
     if result.returncode:return result
    return result
   report=mutate(crate/'src/native_apply.rs',RUST,run)
   report+=mutate(crate/'src/registry.rs',RUST_STATE,run)
 a.out.write_text(json.dumps(dict(language=a.language,native_apply_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--language',choices=['cpp','rust'],required=True)
 for n in ('build','inputs','shard-inputs','fixtures','shard-fixtures','out'):p.add_argument('--'+n,type=Path,required=n=='out')
 main(p.parse_args())
