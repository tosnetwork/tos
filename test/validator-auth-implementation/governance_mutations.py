"""Compile current-governance authority substitutions and require named refusals."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
from context_mutations import checked,mutate,ROOT
CPP=[
 ('gov-target','governance-target-identity','|| update.identity_ != Hash{}',''),
 ('gov-operation','governance-target-operation','(update.operation_ != 4 && update.operation_ != 6) ||',''),
 ('gov-owner','governance-owner-separation','!evidence.owner_.empty() ||',''),
 ('gov-pop','governance-pop-separation','|| !evidence.possession_.empty()',''),
 ('gov-identity','governance-identity-separation','|| !evidence.administration_.empty()',''),
 ('gov-coordinate','governance-state-coordinate','current.coordinate() != inclusion ||',''),
 ('gov-domain','governance-chain-domain','|| current.chain_domain() != chain.chain_domain',''),
 ('gov-policy','governance-current-policy','if (current.current_policy() != governing.policy_id()) return Error{"governance-current-policy"};',''),
 ('gov-masterchain','governance-masterchain','committee.workchain_ != -1 ||',''),
 ('gov-age','governance-stale','if (committee.anchor_mc_ > inclusion || inclusion - committee.anchor_mc_ > 128) return Error{"admin-freshness"};',''),
 ('gov-update','governance-update-binding','auth.update_id_ != id.value() ||',''),
 ('gov-roster','governance-roster-binding','|| auth.committee_ != governing.committee_id()',''),
 ('gov-claim-as-context','governance-network','governing.verify(cert.value(), expected.value())','governing.verify(cert.value(), cert.value().duty_)'),
 ('gov-drop-missing','governance-missing-current-identity','if (identity == current.identities().end()) return Error{"governance-current-identity"};','if (identity == current.identities().end()) continue;'),
 ('gov-old-key','governance-retired-admin','if (ref.value() != Keyref{component.suite_, component.parameters_, component.epoch_, component.key_id_}) return Error{"governance-current-key"};',''),
 ('gov-old-time','governance-expired-admin','select_identity_keys(identity->second, current, inclusion, {{5, 1, 1}})','select_identity_keys(identity->second, current, committee.anchor_mc_, {{5, 1, 1}})'),
]
RUST=[
 ('gov-target','governance-target-identity','|| update.identity != [0; 32]',''),
 ('gov-operation','governance-target-operation','!matches!(update.operation, 4 | 6) ||',''),
 ('gov-owner','governance-owner-separation','!evidence.owner.is_empty() ||',''),
 ('gov-pop','governance-pop-separation','|| !evidence.possession.is_empty()',''),
 ('gov-identity','governance-identity-separation','|| !evidence.administration.is_empty()',''),
 ('gov-coordinate','governance-state-coordinate','current.coordinate() != inclusion ||',''),
 ('gov-domain','governance-chain-domain','|| current.chain_domain() != &chain.chain_domain',''),
 ('gov-policy','governance-current-policy','if current.current_policy() != governing.policy_id() { return Err(Error("governance-current-policy")); }',''),
 ('gov-masterchain','governance-masterchain','committee.workchain != -1 ||',''),
 ('gov-age','governance-stale','if age > 128 { return Err(Error("admin-freshness")); }',''),
 ('gov-future','governance-future-anchor','inclusion.checked_sub(committee.anchor_mc).ok_or(Error("admin-freshness"))?','inclusion.saturating_sub(committee.anchor_mc)'),
 ('gov-update','governance-update-binding','auth.update_id != object_id("update", update)? ||',''),
 ('gov-roster','governance-roster-binding','|| auth.committee != *governing.committee_id()',''),
 ('gov-claim-as-context','governance-network','governing.verify_certificate(&certificate, &expected)?','governing.verify_certificate(&certificate, &certificate.duty)?'),
 ('gov-drop-missing','governance-missing-current-identity','let identity = current.identities.get(&record.identity).ok_or(Error("governance-current-identity"))?;','let Some(identity) = current.identities.get(&record.identity) else { continue; };'),
 ('gov-old-key','governance-retired-admin','if reference != (Keyref { suite: component.suite, parameters: component.parameters, epoch: component.epoch, key_id: component.key_id, }) { return Err(Error("governance-current-key")); }',''),
 ('gov-old-time','governance-expired-admin','select_identity_keys(identity, current, inclusion, &[(5, 1, 1)])?','select_identity_keys(identity, current, committee.anchor_mc, &[(5, 1, 1)])?'),
]
def main(args):
 if args.language=='cpp':
  folder=args.build.resolve()/'test/validator-auth-implementation'
  def run():
   checked(['cmake','--build',str(args.build.resolve()),'--target','test-p0-governance-mutant','-j2'])
   return subprocess.run([str(folder/'test-p0-governance-mutant')],capture_output=True,text=True)
  report=mutate(folder/'governance-mutated.cpp',CPP,run)
 else:
  with tempfile.TemporaryDirectory(prefix='p0-governance-mutations-') as tmp:
   root=Path(tmp)
   for part in ('validator-auth-native','validator-auth'):shutil.copytree(ROOT/'tosctl/src'/part,root/part)
   for part in (ROOT/'tosctl/src').iterdir():
    if part.is_dir() and part.name not in ('target','validator-auth-native','validator-auth'):(root/part.name).symlink_to(part,target_is_directory=True)
   crate=root/'validator-auth-native';manifest=crate/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n');shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
   def run():
    checked(['cargo','build','--offline','--manifest-path',str(manifest),'--bin','governance-conformance'])
    return subprocess.run([str(crate/'target/debug/governance-conformance'),str(args.fixtures.resolve())],capture_output=True,text=True)
   report=mutate(crate/'src/governance.rs',RUST,run)
 args.out.write_text(json.dumps(dict(language=args.language,governance_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--language',choices=['cpp','rust'],required=True);p.add_argument('--build',type=Path);p.add_argument('--fixtures',type=Path);p.add_argument('--out',type=Path,required=True);main(p.parse_args())
