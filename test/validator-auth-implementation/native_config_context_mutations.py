"""Compile native account ownership, checkpoint and invocation binding guards."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
from context_mutations import checked,mutate,ROOT
CPP=[
 ('config-address-binding','config-extra-address','|| params.config_addr != td::Bits256(td::ConstBitPtr(address.data()))',''),
 ('config-tick','config-required-tick','|| !account.tick',''),
 ('config-data-shape','config-data-trailing','|| data.size() != 289',''),
 ('config-owned-root','config-owned-dictionary','if (!same(owned_config, cfg.get_root_cell())) return Error{"config-dictionary-binding"};',''),
 ('config-cache-checkpoint','config-cache-index','|| !same(check.value(), checkpoint)',''),
 ('config-cache-coordinate','config-cache-coordinate','|| cached->coordinate() != head.seqno_',''),
 ('config-cache-registry','config-cache-registry','|| !same(encoded.value(), registry)',''),
 ('config-invocation-workchain','config-bind-workchain','workchain != -1 ||',''),
 ('config-invocation-address','config-bind-address','address != address_ ||',''),
 ('config-invocation-code','config-bind-code','!same(code, code_) ||',''),
 ('config-invocation-data','config-bind-data','!same(data, data_) ||',''),
 ('config-invocation-library','config-bind-library','|| !same(library, library_)',''),
]
RUST=[
 ('config-address-binding','config-extra-address','|| config.config_addr.get_bytestring(0) != address',''),
 ('config-tick','config-required-tick','|| account.get_tick_tock().is_none_or(|t| !t.tick)',''),
 ('config-data-shape','config-data-trailing','|| d.remaining_bits() != 289',''),
 ('config-owned-root','config-owned-dictionary','if owned_config.repr_hash() != actual_config.repr_hash() { return Err(Error("config-dictionary-binding")); }',''),
 ('config-cache-checkpoint','config-cache-index','|| value.checkpoint()?.repr_hash() != checkpoint.repr_hash()',''),
 ('config-cache-coordinate','config-cache-coordinate','value.coordinate() != head.seqno','false'),
 ('config-cache-registry','config-cache-registry','|| value.encode_cell()?.repr_hash() != registry.repr_hash()',''),
 ('config-invocation-workchain','config-bind-workchain','workchain != -1','false'),
 ('config-invocation-address','config-bind-address','|| address != &self.address',''),
 ('config-invocation-code','config-bind-code','|| code.repr_hash() != self.code.repr_hash()',''),
 ('config-invocation-data','config-bind-data','|| data.repr_hash() != self.data.repr_hash()',''),
 ('config-invocation-library','config-bind-library','|| !same(&library, &self.library)',''),
]
def main(a):
 if a.language=='cpp':
  folder=a.build.resolve()/'test/validator-auth-implementation'
  def run():
   checked(['cmake','--build',str(a.build.resolve()),'--target','test-p0-native-config-context-mutant','-j2'])
   with tempfile.TemporaryDirectory(prefix='p0-config-context-cases-') as tmp:
    return subprocess.run([str(folder/'test-p0-native-config-context-mutant'),str(a.inputs.resolve()),str(Path(tmp)/'cases')],capture_output=True,text=True)
  report=mutate(folder/'native-config-context-mutated.cpp',CPP,run)
 else:
  with tempfile.TemporaryDirectory(prefix='p0-native-config-context-mutations-') as tmp:
   root=Path(tmp)
   for part in ('validator-auth-native','validator-auth'):shutil.copytree(ROOT/'tosctl/src'/part,root/part)
   for part in (ROOT/'tosctl/src').iterdir():
    if part.is_dir() and part.name not in ('target','validator-auth-native','validator-auth'):(root/part.name).symlink_to(part,target_is_directory=True)
   crate=root/'validator-auth-native';manifest=crate/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n');shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
   def run():
    checked(['cargo','build','--offline','--manifest-path',str(manifest),'--bin','native-config-context-conformance'])
    return subprocess.run([str(crate/'target/debug/native-config-context-conformance'),str(a.fixtures.resolve())],capture_output=True,text=True)
   report=mutate(crate/'src/native_config_context.rs',RUST,run)
 a.out.write_text(json.dumps(dict(language=a.language,native_config_context_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--language',choices=['cpp','rust'],required=True)
 for n in ('build','inputs','fixtures','out'):p.add_argument('--'+n,type=Path,required=n=='out')
 main(p.parse_args())
