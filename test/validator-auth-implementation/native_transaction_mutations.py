"""Compile transaction-prefix mutations and require specific runtime assertions."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
from context_mutations import ROOT,checked,mutate
CPP=[
 ('transaction-dispatch','transaction-rejected-nonce','NativeRegistry::apply_updates(accepted, {{update, evidence}},','NativeRegistry::apply_updates(accepted, {},'),
 ('transaction-single-revision','native-batch-one-revision','accepted.revision_ = parent_revision_ + 1;','accepted.revision_ = accepted_.revision_ + 1;'),
 ('transaction-revision-overflow','native-revision-overflow','if (parent_revision_ == UINT64_MAX) return Error{"registry-revision"};',''),
 ('transaction-budget','transaction-cumulative-budget','auto accepted = accepted_;','auto accepted = accepted_; accepted.budget_ = {};'),
]
# Remove prefix copying without moving out of the aliased original; a moved-from
# fixture crash is not evidence for the isolation assertion.
_prefix=(ROOT/'validator/auth/native-transaction.cpp').read_text()
_prefix=_prefix[_prefix.index('Result<NativeRegistryBlock> NativeRegistryBlock::apply_transaction'):]
CPP.append(('transaction-prefix-ownership','transaction-immutable-prefix',_prefix,
 _prefix.replace('auto accepted = accepted_;','auto& accepted = const_cast<NativeRegistry&>(accepted_);').replace('std::move(accepted)','accepted')))
RUST=[
 ('transaction-dispatch','native-admin-rotation','&[(update.clone(), evidence.clone())]','&[]'),
 ('transaction-single-revision','native-same-block-current-key','self.parent_revision.checked_add(1).ok_or(Error("registry-revision"))?','self.accepted.revision.checked_add(1).ok_or(Error("registry-revision"))?'),
 ('transaction-revision-overflow','native-revision-overflow','self.parent_revision.checked_add(1).ok_or(Error("registry-revision"))?','self.parent_revision.wrapping_add(1)'),
 ('transaction-budget','native-same-block-current-key','let mut accepted = self.accepted.clone();','let mut accepted = self.accepted.clone(); accepted.budget = RefCell::new(StateReadBudget::default());'),
]
def main(a):
 if a.language=='cpp':
  folder=a.build.resolve()/'test/validator-auth-implementation'
  def run():
   checked(['cmake','--build',str(a.build.resolve()),'--target','test-p0-native-transactions-mutant','-j2'])
   with tempfile.TemporaryDirectory(prefix='p0-transaction-cases-') as tmp:
    return subprocess.run([str(folder/'test-p0-native-transactions-mutant'),'verify',str(a.inputs.resolve()),str(Path(tmp)/'cases')],capture_output=True,text=True)
  report=mutate(folder/'native-transaction-mutated.cpp',CPP,run)
 else:
  with tempfile.TemporaryDirectory(prefix='p0-transaction-mutations-') as tmp:
   root=Path(tmp)
   for part in ('validator-auth-native','validator-auth'):shutil.copytree(ROOT/'tosctl/src'/part,root/part)
   for part in (ROOT/'tosctl/src').iterdir():
    if part.is_dir() and part.name not in ('target','validator-auth-native','validator-auth'):(root/part.name).symlink_to(part,target_is_directory=True)
   crate=root/'validator-auth-native';manifest=crate/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n');shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
   def run():
    checked(['cargo','build','--offline','--manifest-path',str(manifest),'--bin','native-apply-conformance'])
    return subprocess.run([str(crate/'target/debug/native-apply-conformance'),'--transactions',str(a.fixtures.resolve())],capture_output=True,text=True)
   report=mutate(crate/'src/native_registry.rs',RUST,run)
 a.out.write_text(json.dumps(dict(language=a.language,native_transaction_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--language',choices=['cpp','rust'],required=True)
 for name in ('build','inputs','fixtures','out'):p.add_argument('--'+name,type=Path,required=name=='out')
 main(p.parse_args())
