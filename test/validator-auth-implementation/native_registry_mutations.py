"""Compile persistent native dictionary and authority mutations; restore baselines."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
from context_mutations import ROOT,checked,mutate,validate
CPP=[
 ('registry-checkpoint-root','persistent-checkpoint-root','need(hash(root) == expected, "checkpoint-registry");',''),
 ('registry-checkpoint-coordinate','persistent-checkpoint-coordinate','need(s.fetch_ulong(32) == coordinate, "checkpoint-coordinate");','s.fetch_ulong(32);'),
 ('registry-checkpoint-index','persistent-checkpoint-epochs','need(hash(take(result.checkpoint())) == hash(checkpoint), "checkpoint-index");',''),
 ('registry-checkpoint-version','persistent-checkpoint-version','&& s.fetch_ulong(16) == 1','&& (s.fetch_ulong(16), true)'),
 ('registry-bootstrap-budget','persistent-bootstrap-budget','RegistryState::decode_cell(root, at, budget)','RegistryState::decode_cell(root, at)'),
 ('registry-entry-budget','persistent-entry-budget','budget.entries != 0 && bytes <= budget.bytes','bytes <= budget.bytes'),
 ('registry-byte-budget','persistent-byte-budget','budget.entries != 0 && bytes <= budget.bytes','budget.entries != 0'),
 ('registry-known-identity','persistent-ever-registered','return value.not_null() && std::equal(id.begin(), id.end(), key.begin());','return false;'),
 ('registry-epoch-read','persistent-initial-epoch','return value->prefetch_ulong(64);','return 0;'),
 ('registry-epoch-update','checkpoint-roundtrip: checkpoint-index','epoch_put(next.epochs_, key);',''),
 ('registry-due-admission','checkpoint-roundtrip: checkpoint-index','schedules(next.due_, effect.identity, true);',''),
 ('registry-cancel-index','checkpoint-roundtrip: checkpoint-index','schedules(next.due_, before, false); schedules(next.due_, effect.identity, true);','schedules(next.due_, effect.identity, true);'),
 ('registry-due-boundary','due-other-identity-bytes','if (height != at) break;','if (height >= at) break;'),
 ('registry-policy-boundary','policy-boundary-bytes','need(selected.write().fetch_bytes(td::MutableSlice(next.policy_.data(), next.policy_.size())), "policy-index");',''),
 ('registry-block-gap','block-gap','need(coordinate_ < UINT32_MAX - 1 && at == coordinate_ + 1, "block-gap");','need(coordinate_ < UINT32_MAX - 1, "block-gap");'),
 ('registry-revision','multi-identity-stage-bytes','next.revision_ = revision_ + 1;',''),
 ('registry-revision-overflow','registry-revision-overflow','need(revision_ != UINT64_MAX, "registry-revision");',''),
]
RUST=[
 ('registry-checkpoint-root','persistent-checkpoint-root','need(hash(&root)? == *expected, "checkpoint-registry")?;',''),
 ('registry-checkpoint-coordinate','persistent-checkpoint-coordinate','need(native(s.get_next_u32())? == at, "checkpoint-coordinate")?;','native(s.get_next_u32())?;'),
 ('registry-checkpoint-index','persistent-checkpoint-epochs','need(hash(&result.checkpoint()?)? == hash(&checkpoint)?, "checkpoint-index")?;',''),
 ('registry-checkpoint-version','persistent-checkpoint-version','&& native(s.get_next_u16())? == 1','&& { native(s.get_next_u16())?; true }'),
 ('registry-bootstrap-budget','persistent-bootstrap-budget','RegistryState::decode_cell(root.clone(), at, budget)?','RegistryState::decode_cell(root.clone(), at, StateReadBudget::default())?'),
 ('registry-entry-budget','persistent-entry-budget','need(b.entries != 0 && bytes <= b.bytes, "state-resource")?; b.entries = b.entries.checked_sub(1).ok_or(Error("state-resource"))?;','need(bytes <= b.bytes, "state-resource")?; b.entries = b.entries.saturating_sub(1);'),
 ('registry-byte-budget','persistent-byte-budget','need(b.entries != 0 && bytes <= b.bytes, "state-resource")?; b.entries = b.entries.checked_sub(1).ok_or(Error("state-resource"))?; b.bytes = b.bytes.checked_sub(bytes).ok_or(Error("state-resource"))?;','need(b.entries != 0, "state-resource")?; b.entries = b.entries.checked_sub(1).ok_or(Error("state-resource"))?; b.bytes = b.bytes.saturating_sub(bytes);'),
 ('registry-known-identity','persistent-ever-registered','Ok(read_hash(&mut native(SliceData::load_builder(key))?)? == *id)','Ok(false)'),
 ('registry-epoch-read','persistent-initial-epoch','native(leaf.get_next_u64())','Ok(0)'),
 ('registry-epoch-update','persistent-index-bytes','epoch_put(&mut next.epochs, &key)?;',''),
 ('registry-due-admission','persistent-index-bytes','schedules(&mut next.due, &effect.identity, true)?;',''),
 ('registry-cancel-index','persistent-index-bytes','schedules(&mut next.due, &before, false)?; schedules(&mut next.due, &effect.identity, true)?;','schedules(&mut next.due, &effect.identity, true)?;'),
 ('registry-due-boundary','due-other-identity-bytes','if height != at { break; }','if height >= at { break; }'),
 ('registry-policy-boundary','policy-boundary-bytes','next.policy = read_hash(&mut selected)?;',''),
 ('registry-block-gap','block-gap','self.coordinate < u32::MAX - 1 && self.coordinate.checked_add(1) == Some(at)','self.coordinate < u32::MAX - 1'),
 ('registry-revision','multi-identity-stage-bytes','next.revision = self.revision.checked_add(1).ok_or(Error("registry-revision"))?;',''),
 ('registry-revision-overflow','registry-revision-overflow','self.revision.checked_add(1).ok_or(Error("registry-revision"))?','self.revision.wrapping_add(1)'),
]
CPP_NATIVE=[('registry-native-current','native-admin-rotation','NativeLifecycleAuthority authority(current, context, reader);','NativeLifecycleAuthority authority(*this, context, reader);')]
RUST_NATIVE=[('registry-native-current','native-admin-rotation','NativeLifecycleAuthority::new(current, context, reader)','NativeLifecycleAuthority::new(self, context, reader)')]
def main(a):
 if a.language=='cpp':
  folder=a.build.resolve()/'test/validator-auth-implementation';path=folder/'native-registry-mutated.cpp'
  def run(full=False):
   checked(['cmake','--build',str(a.build.resolve()),'--target','test-p0-native-registry-mutant','-j2'])
   with tempfile.TemporaryDirectory(prefix='p0-registry-cases-') as tmp:
    return subprocess.run([str(folder/'test-p0-native-registry-mutant'),str(a.replay.resolve()),str(Path(tmp)/'cases')]+([] if full else ['--guards']),capture_output=True,text=True)
  validate(run(True));report=mutate(path,CPP,run);validate(run(True))
  def run_native():
   checked(['cmake','--build',str(a.build.resolve()),'--target','test-p0-persistent-apply-mutant','-j2'])
   with tempfile.TemporaryDirectory(prefix='p0-registry-apply-') as tmp:
    return subprocess.run([str(folder/'test-p0-persistent-apply-mutant'),'verify',str(a.inputs.resolve()),str(Path(tmp)/'cases')],capture_output=True,text=True)
  report+=mutate(path,CPP_NATIVE,run_native)
 else:
  with tempfile.TemporaryDirectory(prefix='p0-native-registry-mutations-') as tmp:
   root=Path(tmp)
   for part in ('validator-auth-native','validator-auth'):shutil.copytree(ROOT/'tosctl/src'/part,root/part)
   for part in (ROOT/'tosctl/src').iterdir():
    if part.is_dir() and part.name not in ('target','validator-auth-native','validator-auth'):(root/part.name).symlink_to(part,target_is_directory=True)
   crate=root/'validator-auth-native';manifest=crate/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n');shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
   def run(full=False):
    checked(['cargo','build','--offline','--manifest-path',str(manifest),'--bin','native-registry-conformance'])
    return subprocess.run([str(crate/'target/debug/native-registry-conformance'),str(a.replay.resolve()),str(a.fixtures.resolve())]+([] if full else ['--guards']),capture_output=True,text=True)
   path=crate/'src/native_registry.rs';validate(run(True));report=mutate(path,RUST,run);validate(run(True))
   def run_native():
    checked(['cargo','build','--offline','--manifest-path',str(manifest),'--bin','native-apply-conformance'])
    return subprocess.run([str(crate/'target/debug/native-apply-conformance'),'--persistent',str(a.native_fixtures.resolve())],capture_output=True,text=True)
   report+=mutate(path,RUST_NATIVE,run_native)
 a.out.write_text(json.dumps(dict(language=a.language,native_registry_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--language',choices=['cpp','rust'],required=True)
 for name in ('build','replay','inputs','fixtures','native-fixtures','out'):p.add_argument('--'+name,type=Path,required=name in ('replay','out'))
 main(p.parse_args())
