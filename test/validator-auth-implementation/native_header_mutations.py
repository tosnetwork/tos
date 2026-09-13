"""Compile fixed-surface native header trust and resource guard removals."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
from context_mutations import checked,mutate,ROOT
CPP=[
 ('header-root','header-independent-root','root.is_error() || root.ok()->get_hash().as_slice() != id.root_hash.as_slice()','root.is_error()'),
 ('header-network','header-network','record.global_id != chain_.network ||',''),
 ('header-sequence','header-sequence','info.seq_no != at ||',''),
 ('header-not-master','header-not-master','info.not_master ||',''),
 ('header-workchain','header-workchain','shard.workchain_id != -1 ||',''),
 ('header-full-shard','header-full-shard','shard.shard_pfx_len != 0','false'),
 ('header-head-state','header-head-state-binding','if (at == head_.seqno_ && state != head_.state_) return Error{"header-head-state"};',''),
 ('header-state-output','header-native-old-state','update.advance(8 + 256);','update.advance(8);'),
 ('header-file-output','header-native-old-state','hash(id.file_hash.as_slice()), state','Hash{}, state'),
 ('header-value-reveal','header-value-flow-pruned','!terminal(root.prefetch_ref(1), 0) ||',''),
 ('header-extra-reveal','header-block-extra-pruned','!terminal(root.prefetch_ref(3), 0)','false'),
 ('header-predecessor-reveal','header-predecessor-pruned','if (!terminal(info.prefetch_ref(i), 0)) return false;','if (false) return false;'),
 ('header-old-reveal','header-old-state-pruned','terminal(update.prefetch_ref(0), 1) &&',''),
 ('header-new-reveal','header-new-state-pruned','&& terminal(update.prefetch_ref(1), 1)',''),
]
RUST=[
 ('header-root','header-independent-root','if root.hash(0).as_slice() != &root_hash { return Err(Error("header-root")); }',''),
 ('header-network','header-network','record.global_id() != self.chain.network','false'),
 ('header-sequence','header-sequence','|| seqno != at',''),
 ('header-not-master','header-not-master','|| not_master',''),
 ('header-full-shard','header-workchain','|| !shard.is_masterchain_ext()',''),
 ('header-head-state','header-head-state-binding','if at == self.head.seqno && state != self.head.state { return Err(Error("header-head-state")); }',''),
 ('header-state-output','header-native-old-state','native(update.get_next_bits(8 + 256))?;','native(update.get_next_bits(8))?;'),
 ('header-file-output','header-native-old-state','file: file_hash,','file: [0;32],'),
 ('header-value-reveal','header-value-flow-pruned','!terminal(&native(root.reference(1))?, 0) ||',''),
 ('header-extra-reveal','header-block-extra-pruned','!terminal(&native(root.reference(3))?, 0)','false'),
 ('header-predecessor-reveal','header-predecessor-pruned','if !terminal(&native(info.reference(i))?, 0) { return Err(Error("header-surface")); }','if false { return Err(Error("header-surface")); }'),
 ('header-old-reveal','header-old-state-pruned','|| !terminal(&native(update.reference(0))?, 1)',''),
 ('header-new-reveal','header-new-state-pruned','|| !terminal(&native(update.reference(1))?, 1)',''),
]
def main(a):
 if a.language=='cpp':
  folder=a.build.resolve()/'test/validator-auth-implementation'
  def run():
   checked(['cmake','--build',str(a.build.resolve()),'--target','test-p0-native-header-mutant','-j2'])
   with tempfile.TemporaryDirectory(prefix='p0-header-cases-') as tmp:
    return subprocess.run([str(folder/'test-p0-native-header-mutant'),str(a.inputs.resolve()),str(Path(tmp)/'cases')],capture_output=True,text=True)
  report=mutate(folder/'native-header-mutated.cpp',CPP,run)
 else:
  with tempfile.TemporaryDirectory(prefix='p0-native-header-mutations-') as tmp:
   root=Path(tmp)
   for part in ('validator-auth-native','validator-auth'):shutil.copytree(ROOT/'tosctl/src'/part,root/part)
   for part in (ROOT/'tosctl/src').iterdir():
    if part.is_dir() and part.name not in ('target','validator-auth-native','validator-auth'):(root/part.name).symlink_to(part,target_is_directory=True)
   crate=root/'validator-auth-native';manifest=crate/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n');shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
   def run():
    checked(['cargo','build','--offline','--manifest-path',str(manifest),'--bin','native-header-conformance'])
    return subprocess.run([str(crate/'target/debug/native-header-conformance'),str(a.fixtures.resolve())],capture_output=True,text=True)
   report=mutate(crate/'src/native_header.rs',RUST,run)
 a.out.write_text(json.dumps(dict(language=a.language,native_header_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--language',choices=['cpp','rust'],required=True)
 for n in ('build','inputs','fixtures','out'):p.add_argument('--'+n,type=Path,required=n=='out')
 main(p.parse_args())
