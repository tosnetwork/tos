"""Falsify native Rust derivation and descriptor propagation with the native corpus."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
from mutation_support import replace_once
ROOT=Path(__file__).resolve().parents[2]
MUTATIONS=[
 ('native-zero-network','committee.rs','header.global_id() == 0 ||',''),
 ('unselected-duplicate-binding','committee.rs','!identities.insert(id) || !stakes.insert(stake) || !network_keys.insert(hash(member.public_key.as_slice())?)','{identities.insert(id); stakes.insert(stake); network_keys.insert(hash(member.public_key.as_slice())?); false}'),
 ('state-root','committee.rs','root.repr_hash().as_slice() != &anchor.state','false'),
 ('network','committee.rs','header.global_id() != chain.network','false'),
 ('native-version','committee.rs','native(cap.get_next_u32())? < 16','native(cap.get_next_u32())? == u32::MAX'),
 ('native-capability','committee.rs','native(cap.get_next_u64())? & 1024 == 0','false'),
 ('chain-domain','committee.rs','registry.chain_domain != chain.chain_domain','false'),
 ('validator-ceiling','committee.rs','maximum > 400','false'),
 ('elected-ceiling','committee.rs','election.total() > maximum','false'),
 ('election-time','committee.rs','header.gen_time() >= election.utime_until()','false'),
 ('stake-substitution','committee.rs','identity.stake_id != stake','false'),
 ('network-key-reuse','committee.rs','network_keys.contains(&hash(&key.public_key)?)','false'),
 ('unsupported-selector','committee.rs','selector.isolate_mc_validators ||',''),
 ('wide-selector','committee.rs','selector.shard_validators_num = selector.shard_validators_num.min(u32::from(election.total()));',''),
 ('temporary-election','committee.rs','native(config.config_present(35))?','false'),
 ('native-full-roster','committee.rs','weight: member.weight,','weight: 1,'),
 ('duplicate-key-epoch','registry.rs','if !unique_epochs.insert((k.identity, slot, k.epoch)) { return Err(Error("duplicate-key-epoch")); }','unique_epochs.insert((k.identity, slot, k.epoch));'),
 ('registry-entry-budget','registry.rs','budget.entries = budget.entries.checked_sub(1).ok_or(Error("state-resource"))?;',''),
 ('registry-byte-budget','registry.rs','budget.bytes = budget.bytes.checked_sub(raw.len()).ok_or(Error("state-resource"))?;',''),
 ('descriptor-zero-identity','../../block/src/validators.rs','if identity.is_zero() || stake_id.is_zero() {','if stake_id.is_zero() {'),
 ('descriptor-zero-stake','../../block/src/validators.rs','if identity.is_zero() || stake_id.is_zero() {','if identity.is_zero() {'),
 ('binding-tail','../../block/src/validators.rs','|| binding.remaining_bits() != 512',''),
 ('binding-reference','../../block/src/validators.rs','|| binding.remaining_references() != 0',''),
 ('native-shard-roster','../../block/src/validators.rs','last.auth_binding = next_validator.auth_binding.clone();',''),
 ('native-full-roster','../../block/src/validators.rs','if let Some(binding) = &self.auth_binding { if self.mc_seq_no_since != 0','if let Some(binding) = &None::<ValidatorAuthBinding> { if self.mc_seq_no_since != 0'),
]
def main(args):
 fixtures=args.fixtures.resolve();report=[]
 cases={}
 for path in fixtures.glob('*.case'):
  fields=path.read_text().split();cases.setdefault(fields[4],path.stem)
 with tempfile.TemporaryDirectory(prefix='p0-rust-committee-') as tmp:
  tmp=Path(tmp);source_root=tmp/'src';source_root.mkdir()
  for name in ('validator-auth-native','block'):
   shutil.copytree(ROOT/'tosctl/src'/name,source_root/name,ignore=shutil.ignore_patterns('target'))
  for path in (ROOT/'tosctl/src').iterdir():
   if path.is_dir() and path.name not in ('target','validator-auth-native','block'):(source_root/path.name).symlink_to(path,target_is_directory=True)
  for name in ('common','config','crypto'):
   path=ROOT/'tosctl'/name
   if path.exists():(tmp/name).symlink_to(path,target_is_directory=path.is_dir())
  crate=source_root/'validator-auth-native';manifest=crate/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n')
  shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
  binary=crate/'target/debug/committee-conformance'
  def run():
   build=subprocess.run(['cargo','build','--offline','--manifest-path',str(manifest),'--bin','committee-conformance'],capture_output=True,text=True)
   if build.returncode:raise RuntimeError(build.stdout+build.stderr)
   return subprocess.run([str(binary),str(fixtures)],capture_output=True,text=True)
  baseline=run();assert baseline.returncode==0,baseline.stderr
  for label,file,before,after in MUTATIONS:
   source=crate/'src'/file;original=source.read_text();source.write_text(replace_once(original,before,after))
   try:
    result=run()
    prefix='ASSERTION: '+('case-'+cases[label]+'-' if label in cases else label)
    assert result.returncode==1 and result.stderr.startswith(prefix) and 'panicked at' not in result.stderr,(label,result.stderr)
    report.append(dict(guard=label,source=file,compiled=True,assertion_failed=True));print('KILLED:',label,flush=True)
   finally:source.write_text(original)
  baseline=run();assert baseline.returncode==0,baseline.stderr
 args.out.write_text(json.dumps(dict(rust_committee_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--out',type=Path,required=True);main(p.parse_args())
