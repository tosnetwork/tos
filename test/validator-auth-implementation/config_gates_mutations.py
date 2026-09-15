"""Compile native config gates, actual call-site and generated TL-B mutations."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
from context_mutations import ROOT,checked,mutate
CPP=[
 ('config-vm','version','if (version < 16) return td::Status::Error("validator-auth-version");',''),
 ('config-capability-tag','capability-shape','cap.fetch_ulong(8) != 0xc4','(cap.fetch_ulong(8), false)'),
 ('config-mandatory','mandatory','for (int index : {9, 10})','for (int index : {10})'),
 ('config-critical','critical','for (int index : {9, 10})','for (int index : {9})'),
 ('config-ceiling','count','maximum > 400 ||',''),
 ('config-main','main-count','main > maximum ||',''),
 ('config-minimum','minimum-count','minimum < 1 ||',''),
 ('config-minimum-main','minimum-main','|| minimum > main',''),
 ('config-root-magic','registry-magic','root.fetch_ulong(32) != 0x76617131','(root.fetch_ulong(32), false)'),
 ('config-root-version','registry-version','root.fetch_ulong(16) != 1','(root.fetch_ulong(16), false)'),
 ('config-fingerprint','fingerprint','fingerprint.as_slice() != td::Slice(validator_auth_profile_fingerprint.data(), validator_auth_profile_fingerprint.size())','false'),
 ('config-policy-present','zero-policy','|| policy.is_zero()',''),
 ('config-dictionary','identity-wrapper','s.size_refs() == s.prefetch_ulong(1)','true'),
 ('config-control','control-magic','control.fetch_ulong(32) != 0x76616331','(control.fetch_ulong(32), false)'),
 ('config-activation','activation','if (!old.enabled) return td::Status::Error("validator-auth-transition-unapproved");','if (!old.enabled) return td::Status::OK();'),
 ('config-downgrade','downgrade','if (!next.enabled) return td::Status::Error("validator-auth-downgrade");','if (!next.enabled) return td::Status::OK();'),
 ('config-domain','domain','if (old.domain != next.domain) return td::Status::Error("validator-auth-domain");',''),
 ('config-revision','unchanged-revision','if (next.revision < old.revision || next.revision - old.revision != std::uint64_t(changed)) return td::Status::Error("validator-auth-revision");',''),
 ('config-revision-wrap','revision-wrap','next.revision < old.revision ||',''),
 ('config-key-revision','unrecorded-key-change','|| old.keys->get_hash() != next.keys->get_hash()',''),
]
CPP_CALLS=[
 ('config-transition-call','activation','TRY_STATUS(validate_validator_auth_transition(old_dict, new_dict));',''),
 ('config-data-call','config-data-version','if (validate_validator_auth_config(dict).is_error()) { return false; }',''),
 ('config-root-call','config-data-legacy-reserved-registry','if (cfg_idx == 46) { return validate_validator_auth_root_shape(std::move(cell)).is_ok(); }',''),
]
RUST=[
 ('config-vm','version','need(version >= 16, "validator-auth-version")?;',''),
 ('config-capability-tag','capability-shape','&& cap.get_next_byte()? == 0xc4','&& { cap.get_next_byte()?; true }'),
 ('config-mandatory','mandatory','for at in [9, 10]','for at in [10]'),
 ('config-critical','critical','for at in [9, 10]','for at in [9]'),
 ('config-ceiling','count','maximum <= 400 &&',''),
 ('config-main','main-count','&& main <= maximum',''),
 ('config-minimum','minimum-count','&& minimum >= 1',''),
 ('config-minimum-main','minimum-main','&& minimum <= main',''),
 ('config-root-magic','registry-magic','&& root.get_next_u32()? == 0x76617131','&& { root.get_next_u32()?; true }'),
 ('config-root-version','registry-version','&& root.get_next_u16()? == 1','&& { root.get_next_u16()?; true }'),
 ('config-fingerprint','fingerprint','root.get_next_bits(256)? == VALIDATOR_AUTH_PROFILE_FINGERPRINT','{ root.get_next_bits(256)?; true }'),
 ('config-policy-present','zero-policy','need(root.get_next_bits(256)? != [0; 32], "validator-auth-registry")?;','root.get_next_bits(256)?;'),
 ('config-dictionary','identity-wrapper','s.remaining_references() == usize::from(s.get_next_bit()?)','{ s.get_next_bit()?; true }'),
 ('config-control','control-magic','&& control.get_next_u32()? == 0x76616331','&& { control.get_next_u32()?; true }'),
 ('config-activation','activation','(None, Some(_)) => return Err(error!("validator-auth-transition-unapproved")),','(None, Some(_)) => return Ok(()),'),
 ('config-downgrade','downgrade','(Some(_), None) => return Err(error!("validator-auth-downgrade")),','(Some(_), None) => return Ok(()),'),
 ('config-domain','domain','need(old.domain == next.domain, "validator-auth-domain")?;',''),
 ('config-revision','unchanged-revision','need(next.revision.checked_sub(old.revision) == Some(u64::from(changed)), "validator-auth-revision",)?;',''),
 ('config-revision-wrap','revision-wrap','next.revision.checked_sub(old.revision)','Some(next.revision.wrapping_sub(old.revision))'),
 ('config-key-revision','unrecorded-key-change','|| old.keys.repr_hash() != next.keys.repr_hash()',''),
]
RUST_CALLS=[
 ('config-data-call','config-data-version','&& crate::validator_auth_config::validate_validator_auth_config(self).is_ok()',''),
 ('config-root-call','config-data-legacy-reserved-registry','crate::validator_auth_config::validate_validator_auth_root_shape(&cell)?;',''),
]
def main(a):
 if a.language=='cpp':
  folder=a.build.resolve()/'test/validator-auth-implementation'
  def runner(target):
   def run():
    checked(['cmake','--build',str(a.build.resolve()),'--target',target,'-j2'])
    with tempfile.TemporaryDirectory(prefix='p0-config-cases-') as tmp:
     return subprocess.run([str(folder/target),str(ROOT/'tosctl/src/block/src/tests/data/config.boc'),str(Path(tmp)/'cases')],capture_output=True,text=True)
   return run
  report=mutate(folder/'config-gates-validator-auth-config-mutated.cpp',CPP,runner('test-p0-config-gates-validator-auth-config-mutant'))
  report+=mutate(folder/'config-gates-block-mutated.cpp',CPP_CALLS,runner('test-p0-config-gates-block-mutant'))
  report+=mutate(folder/'config-gates-tuple/tl/tlblib.hpp',[
   ('config-tuple-overflow','tuple-unsigned-overflow','n(_n <= 0x7fffffffU ? static_cast<int>(_n) : -1)','n(static_cast<int>(_n & 0x7fffffffU))')],runner('test-p0-config-gates-tuple-mutant'))
  # Mutate the generated production parser, not the fixture or frozen schema.
  path=folder/'config-gates-schema-mutated.cpp';shutil.copy2(ROOT/'crypto/block/block-auto.cpp',path)
  original=path.read_text();begin=original.index('bool AuthByteNode::validate_skip(');end=original.index('\nbool ',begin+1)
  from mutation_support import replace_once
  from context_mutations import validate
  run=runner('test-p0-config-gates-schema-mutant');validate(run())
  try:
   path.write_text(original[:begin]+replace_once(original[begin:end],'&& 2 <= n','&& 1 <= n')+original[end:]);validate(run(),'compiled-auth-branch-minimum')
   report.append(dict(guard='config-native-byte-node',assertion='compiled-auth-branch-minimum',compiled=True,assertion_failed=True))
  finally:path.write_text(original);validate(run())
 else:
  with tempfile.TemporaryDirectory(prefix='p0-config-mutations-') as tmp:
   root=Path(tmp)
   for part in ('block','validator-auth-native','validator-auth'):shutil.copytree(ROOT/'tosctl/src'/part,root/part)
   for part in (ROOT/'tosctl/src').iterdir():
    if part.is_dir() and part.name not in ('target','block','validator-auth-native','validator-auth'):(root/part.name).symlink_to(part,target_is_directory=True)
   crate=root/'validator-auth-native';manifest=crate/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n');shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
   def run():
    checked(['cargo','build','--offline','--manifest-path',str(manifest),'--bin','config-gates-conformance'])
    return subprocess.run([str(crate/'target/debug/config-gates-conformance'),str(a.fixtures.resolve())],capture_output=True,text=True)
   report=mutate(root/'block/src/validator_auth_config.rs',RUST,run)
   report+=mutate(root/'block/src/config_params.rs',RUST_CALLS,run)
 a.out.write_text(json.dumps(dict(language=a.language,config_gate_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--language',choices=['cpp','rust'],required=True)
 for name in ('build','fixtures','out'):p.add_argument('--'+name,type=Path,required=name=='out')
 main(p.parse_args())
