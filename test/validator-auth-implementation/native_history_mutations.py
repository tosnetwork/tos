"""Compile native history trust, commitment, cache and resource guard removals."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
from context_mutations import checked,mutate,ROOT
CPP=[
 ('history-state','history-state-substitution','|| head.state_ != hash(root->get_hash().as_slice())',''),
 ('history-genesis-root','history-genesis-root','hash(zero.root_hash.as_slice()) != chain.genesis_root ||',''),
 ('history-genesis-file','history-genesis-file','hash(zero.file_hash.as_slice()) != chain.genesis_file ||',''),
 ('history-zero-state','history-zerostate-root-is-state','|| (head.seqno_ == 0 && head.root_ != head.state_)',''),
 ('history-network','history-chain-network','if (cfg.get_global_blockchain_id() != chain.network) return Error{"history-network"};',''),
 ('history-domain','history-chain-domain','if (registry.value().chain_domain() != chain.chain_domain) return Error{"history-domain"};',''),
 ('history-version','history-version-gate','cfg.get_global_version() < 16','cfg.get_global_version() < 1'),
 ('history-capability','history-capability-gate','|| !(cfg.get_capabilities() & tos::capValidatorAuth)',''),
 ('history-file','history-original-file-binding','if (file != hash(id.file_hash.as_slice())) return Error{"history-file-hash"};',''),
 ('history-root','history-independent-root-binding','|| root.value()->get_hash().as_slice() != id.root_hash.as_slice()',''),
 ('history-block-network','history-block-network','block.global_id != chain_.network ||',''),
 ('history-block-sequence','history-block-sequence','info.seq_no != at ||',''),
 ('history-output-state','history-native-old-block','|| !update.advance(256)',''),
 ('history-cache','history-cache-and-exact-budget','if (auto found = cache_.find(at); found != cache_.end()) return found->second;',''),
 ('history-update-kind','history-ordinary-update-is-not-merkle','!update.is_special() ||',''),
 ('history-block-budget','history-block-count-bound','budget_.blocks == 0 ||',''),
 ('history-source-budget','history-source-oversize','|| raw.size() > maximum',''),
]
RUST=[
 ('history-state','history-state-substitution','|| head.state != hash(root.repr_hash().as_slice())?',''),
 ('history-genesis-root','history-genesis-root','zero != (chain.genesis_root, chain.genesis_file)','zero.1 != chain.genesis_file'),
 ('history-genesis-file','history-genesis-file','zero != (chain.genesis_root, chain.genesis_file)','zero.0 != chain.genesis_root'),
 ('history-zero-state','history-zerostate-root-is-state','|| head.seqno == 0 && head.root != head.state',''),
 ('history-network','history-chain-network','if header.global_id() != chain.network { return Err(Error("history-network")); }',''),
 ('history-domain','history-chain-domain','if registry.chain_domain != chain.chain_domain { return Err(Error("history-domain")); }',''),
 ('history-version','history-version-gate','native(cap.get_next_u32())? < 16','native(cap.get_next_u32())? < 1'),
 ('history-capability','history-capability-gate','native(cap.get_next_u64())? & 1024 == 0','{ let _ = native(cap.get_next_u64())?; false }'),
 ('history-file','history-original-file-binding','if Sha256::digest(&raw).as_slice() != id.file_hash.as_slice() { return Err(Error("history-file-hash")); }',''),
 ('history-root','history-independent-root-binding','|| root.repr_hash() != id.root_hash',''),
 ('history-block-network','history-block-network','block.global_id() != self.chain.network ||',''),
 ('history-block-sequence','history-block-sequence','|| info.seq_no() != at',''),
 ('history-output-state','history-native-old-block','hash(update.new_hash.as_slice())?','hash(update.old_hash.as_slice())?'),
 ('history-cache','history-cache-and-exact-budget','if let Some(found) = access.cache.get(&at) { return Ok(found.clone()); }',''),
 ('history-update-kind','history-ordinary-update-is-not-merkle','update_cell.cell_type() != CellType::MerkleUpdate ||',''),
 ('history-block-budget','history-block-count-bound','if access.budget.blocks == 0 || access.budget.bytes == 0 { return Err(Error("history-resource")); } access.budget.blocks = access.budget.blocks.checked_sub(1).ok_or(Error("history-resource"))?;','if access.budget.bytes == 0 { return Err(Error("history-resource")); } access.budget.blocks = access.budget.blocks.saturating_sub(1);'),
 ('history-source-budget','history-source-oversize','if raw.is_empty() || raw.len() > maximum { return Err(Error("history-block-bound")); } access.budget.bytes = access.budget.bytes.checked_sub(raw.len()).ok_or(Error("history-resource"))?;','if raw.is_empty() { return Err(Error("history-block-bound")); } access.budget.bytes = access.budget.bytes.saturating_sub(raw.len());'),
]
def main(a):
 if a.language=='cpp':
  folder=a.build.resolve()/'test/validator-auth-implementation'
  def run():
   checked(['cmake','--build',str(a.build.resolve()),'--target','test-p0-native-history-mutant','-j2'])
   with tempfile.TemporaryDirectory(prefix='p0-history-cases-') as tmp:
    return subprocess.run([str(folder/'test-p0-native-history-mutant'),str(a.inputs.resolve()),str(Path(tmp)/'cases')],capture_output=True,text=True)
  report=mutate(folder/'native-history-mutated.cpp',CPP,run)
 else:
  with tempfile.TemporaryDirectory(prefix='p0-native-history-mutations-') as tmp:
   root=Path(tmp)
   for part in ('validator-auth-native','validator-auth'):shutil.copytree(ROOT/'tosctl/src'/part,root/part)
   for part in (ROOT/'tosctl/src').iterdir():
    if part.is_dir() and part.name not in ('target','validator-auth-native','validator-auth'):(root/part.name).symlink_to(part,target_is_directory=True)
   crate=root/'validator-auth-native';manifest=crate/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n');shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
   def run():
    checked(['cargo','build','--offline','--manifest-path',str(manifest),'--bin','native-history-conformance'])
    return subprocess.run([str(crate/'target/debug/native-history-conformance'),str(a.fixtures.resolve())],capture_output=True,text=True)
   report=mutate(crate/'src/native_history.rs',RUST,run)
 a.out.write_text(json.dumps(dict(language=a.language,native_history_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--language',choices=['cpp','rust'],required=True)
 for n in ('build','inputs','fixtures','out'):p.add_argument('--'+n,type=Path,required=n=='out')
 main(p.parse_args())
