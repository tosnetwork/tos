"""Compile privileged VM host isolation and metering mutations."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
from context_mutations import ROOT,checked,mutate
CPP=[
 ('host-state-gate','host-version','new CapabilityGated(OpcodeInstr::mksimple(validator_auth_state_opcode, 16, "VAUTH_STATE", exec_validator_auth_state))','OpcodeInstr::mksimple(validator_auth_state_opcode, 16, "VAUTH_STATE", exec_validator_auth_state)'),
 ('host-apply-gate','host-version','new CapabilityGated(OpcodeInstr::mksimple(validator_auth_apply_opcode, 16, "VAUTH_APPLY", exec_validator_auth_apply))','OpcodeInstr::mksimple(validator_auth_apply_opcode, 16, "VAUTH_APPLY", exec_validator_auth_apply)'),
 ('host-meter','host-negative-gas','if (gas < 0) throw VmError{Excno::range_chk, "negative native charge"};',''),
 ('host-operands','host-apply-success','host->apply(std::move(update), std::move(evidence),','host->apply(std::move(evidence), std::move(update),'),
]
# Scope the null-host check because both operations have one.
_source=(ROOT/'crypto/vm/authops.cpp').read_text();_start=_source.index('int exec_validator_auth_state(');_end=_source.index('int exec_validator_auth_apply(',_start);_state=_source[_start:_end]
from mutation_support import replace_once
CPP.append(('host-required','host-required',_state,replace_once(_state,'if (!host) throw VmError{Excno::inv_opcode, "P0 native transaction context required"};','if (!host) return 0;')))
CPP_VM=[('host-child-isolation','host-child-isolation','new_state.global_capabilities = global_capabilities;','new_state.global_capabilities = global_capabilities; new_state.set_validator_auth_host(validator_auth_host_);')]
_source=(ROOT/'tosctl/src/vm/src/executor/validator_auth.rs').read_text();_start=_source.index('fn native_gate(');_end=_source.index('fn charge_native(',_start);_gate=_source[_start:_end]
RUST=[
 ('host-version','host-version',_gate,_gate.replace('engine.block_version() < 16 || ','')),
 ('host-capability','host-capability',_gate,_gate.replace(' || !engine.check_capabilities(CAPABILITY)','')),
 # A refused opcode still charges; dropping the charge diverges from the
 # native implementation on exactly the versions that refuse it.
 ('host-refused-gas','host-version',_gate,_gate.replace('engine.try_use_gas(Gas::basic_gas_price(0, 0))?;','')),
 ('host-meter','host-negative-gas','if gas < 0 { fail!(ExceptionCode::RangeCheckError); }',''),
 ('host-operands','host-apply-success','.apply(update, evidence,','.apply(evidence, update,'),
]
# The scope ends at whichever function follows, not at one named here. It used
# to name execute_vauth_apply, and execute_vauth_bind was later inserted between
# the two -- so the slice covered two functions, the anchor matched twice, and
# the harness stopped before running anything.
_start=_source.index('pub(super) fn execute_vauth_state(')
_end=_source.index('\npub(super) fn ',_start+1)
_state=_source[_start:_end]
RUST.append(('host-required','host-required',_state,replace_once(_state,'let Some(host) = engine.validator_auth_host() else { fail!(ExceptionCode::InvalidOpcode); };','let Some(host) = engine.validator_auth_host() else { return Ok(()); };')))
RUST_VM=[('host-child-isolation','host-child-isolation','capabilities: self.capabilities, validator_auth_host: None, block_version: self.block_version,','capabilities: self.capabilities, validator_auth_host: self.validator_auth_host.clone(), block_version: self.block_version,')]
def main(a):
 if a.language=='cpp':
  folder=a.build.resolve()/'test/validator-auth-implementation'
  def runner(module):
   target='test-p0-native-host-'+module+'-mutant'
   def run():
    checked(['cmake','--build',str(a.build.resolve()),'--target',target,'-j2'])
    with tempfile.TemporaryDirectory(prefix='p0-host-cases-') as tmp:
     return subprocess.run([str(folder/target),str(Path(tmp)/'cases')],capture_output=True,text=True)
   return run
  report=mutate(folder/'native-host-authops-mutated.cpp',CPP,runner('authops'))
  report+=mutate(folder/'native-host-vm-mutated.cpp',CPP_VM,runner('vm'))
 else:
  with tempfile.TemporaryDirectory(prefix='p0-host-mutations-') as tmp:
   root=Path(tmp);parent=root/'tosctl/src';parent.mkdir(parents=True);shutil.copytree(ROOT/'tosctl/src/vm',parent/'vm')
   (root/'third-party').mkdir();(root/'third-party/mldsa-native').symlink_to(ROOT/'third-party/mldsa-native',target_is_directory=True)
   (root/'crypto').mkdir();(root/'crypto/pq').symlink_to(ROOT/'crypto/pq',target_is_directory=True)
   for part in (ROOT/'tosctl/src').iterdir():
    if part.is_dir() and part.name not in ('target','vm'):(parent/part.name).symlink_to(part,target_is_directory=True)
   crate=parent/'vm';manifest=crate/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n');shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
   def run():
    checked(['cargo','build','--offline','--manifest-path',str(manifest),'--example','native-host-parity'])
    return subprocess.run([str(crate/'target/debug/examples/native-host-parity'),str(a.fixtures.resolve())],capture_output=True,text=True)
   report=mutate(crate/'src/executor/validator_auth.rs',RUST,run)
   report+=mutate(crate/'src/executor/engine/core.rs',RUST_VM,run)
 a.out.write_text(json.dumps(dict(language=a.language,native_host_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--language',choices=['cpp','rust'],required=True)
 for name in ('build','fixtures','out'):p.add_argument('--'+name,type=Path,required=name=='out')
 main(p.parse_args())
