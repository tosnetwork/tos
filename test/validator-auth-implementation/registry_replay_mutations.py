"""Compile native Rust registry mutations and require named replay assertions."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
from mutation_support import replace_once
ROOT=Path(__file__).resolve().parents[2]
CASES=[
 ('genesis-duplicate-identity','if state.identities.insert(identity.identity, identity).is_some() { return Err(Error("duplicate-identity")); }','state.identities.insert(identity.identity, identity);'),
 ('genesis-duplicate-key','if state.keys.insert(object_id("key", &key)?, key).is_some() { return Err(Error("duplicate-key")); }','state.keys.insert(object_id("key", &key)?, key);'),
 ('genesis-domain','state.validate()?; Ok(state) } pub fn encode_cell','Ok(state) } pub fn encode_cell'),
 ('block-gap','self.coordinate.checked_add(1) != Some(at)','false'),
 ('coordinate-overflow','self.coordinate >= u32::MAX - 1 ||',''),
 ('registry-revision-overflow','self.revision.checked_add(1).ok_or(Error("registry-revision"))?','self.revision.wrapping_add(1)'),
 ('large-registry-apply-bytes','next.revision = self.revision.checked_add(1).ok_or(Error("registry-revision"))?;','next.revision = self.revision;'),
 ('large-registry-apply-bytes','native(root.append_u64(self.revision))?;','native(root.append_u64(0))?;'),
 ('restart-roundtrip','let revision = native(s.get_next_u64())?;','native(s.get_next_u64())?; let revision = 0;'),
 ('due-other-identity-bytes','if let Some(due) = self.due.get(&at)','if let Some(due) = None::<&BTreeSet<Hash>>'),
 ('due-other-identity-checkpoint-replay','state.due.entry(pending.effective_from).or_default().insert(*id);',''),
 ('canceled-empty-boundary-checkpoint-replay','ids.remove(&update.identity);',''),
 ('due-other-identity-checkpoint-replay','if ids.is_empty() { next.due.remove(&coordinate); }','next.due.remove(&coordinate);'),
 ('due-other-identity-checkpoint-replay','next.due.entry(pending.effective_from).or_default().insert(update.identity);',''),
 ('canceled-epoch-retained-checkpoint-replay','next.epochs.insert((key.identity, (key.role, key.suite, key.parameters)), key.epoch);',''),
 ('policy-boundary-bytes','next.current_policy = object_id("policy", next.policy_at(at)?)?;',''),
 ('control-retention-bytes','store_dictionary(32, self.activations.iter())?','store_dictionary(32, std::iter::empty::<(&Vec<u8>, &Activation)>())?'),
 ('control-retention-bytes','store_dictionary(256, self.observations.iter())?','store_dictionary(256, std::iter::empty::<(&Hash, &Observation)>())?'),
]
def run(args):
 with tempfile.TemporaryDirectory(prefix='p0-rust-registry-') as tmp:
  base=Path(tmp);src=base/'src';src.mkdir();crate=src/'validator-auth-native'
  shutil.copytree(ROOT/'tosctl/src/validator-auth-native',crate,ignore=shutil.ignore_patterns('target'))
  for path in (ROOT/'tosctl/src').iterdir():
   if path.is_dir() and path.name not in ('target','validator-auth-native'):(src/path.name).symlink_to(path,target_is_directory=True)
  manifest=crate/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n')
  shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
  source=crate/'src/registry.rs';original=source.read_text();report=[]
  def execute(text):
   source.write_text(text)
   compiled=subprocess.run(['cargo','build','--offline','--manifest-path',str(manifest),'--bin','state-replay-conformance'],capture_output=True,text=True)
   if compiled.returncode:raise RuntimeError(compiled.stdout+compiled.stderr)
   return subprocess.run([str(crate/'target/debug/state-replay-conformance'),str(args.fixtures.resolve())],capture_output=True,text=True)
  baseline=execute(original);assert baseline.returncode==0,baseline.stderr
  try:
   for label,before,after in CASES:
    result=execute(replace_once(original,before,after))
    assert result.returncode==1 and result.stderr.startswith('ASSERTION: '+label) and 'panicked at' not in result.stderr,(label,result.stderr)
    report.append(dict(guard=label,compiled=True,assertion_failed=True));print('KILLED:',label,flush=True)
  finally:
   baseline=execute(original);assert baseline.returncode==0,baseline.stderr
  args.out.write_text(json.dumps(dict(registry_replay_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--out',type=Path,required=True);run(p.parse_args())
