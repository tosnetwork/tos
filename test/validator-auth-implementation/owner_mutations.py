"""Compile owner-proof guards and require the precise intended assertion failure."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
from context_mutations import checked,mutate,ROOT
CPP=[
 ('owner-wrapper-update','owner-wrapper-update','auth.update_id_ != id.value() ||',''),
 ('owner-wrapper-stake','owner-wrapper-stake','|| auth.stake_id_ != current.stake_id_',''),
 ('owner-wrapper-address','owner-wrapper-address','|| auth.owner_address_ != current.owner_address_',''),
 ('owner-wrapper-workchain','owner-wrapper-workchain','|| auth.owner_workchain_ != current.owner_workchain_',''),
 ('owner-kind','owner-proof-kind','if (proof.kind_ != 1) return Error{"proof-kind"};',''),
 ('owner-object','owner-proof-object','if (proof.object_id_ != id.value()) return Error{"proof-object"};',''),
 ('owner-hash','owner-proof-hash','if (hash.value() != proof.proof_hash_) return Error{"proof-hash"};',''),
 ('owner-anchor','owner-proof-anchor','if (proof.anchor_ != anchor) return Error{"proof-anchor"};',''),
 ('owner-state-root','owner-state-substitution','|| cell_hash(state) != anchor.state_',''),
 ('owner-block-root','owner-block-substitution','|| cell_hash(block_root) != anchor.root_',''),
 ('owner-header-tag','owner-header-tag','header.fetch_ulong(32) != owner_proof_tag','header.fetch_ulong(32) == 0'),
 ('owner-header-version','owner-header-version','header.fetch_ulong(16) != 1','header.fetch_ulong(16) == 0'),
 ('owner-operation','owner-operation','(update.operation_ != 1 && update.operation_ != 2 && update.operation_ != 5) ||',''),
 ('owner-compute','owner-compute-success','|| !compute.success',''),
 ('owner-aborted','owner-aborted','|| ordinary.aborted',''),
 ('owner-destroyed','owner-destroyed','|| ordinary.destroyed',''),
 ('owner-action-success','owner-action-success','|| !action.success',''),
 ('owner-action-valid','owner-action-valid','|| !action.valid',''),
 ('owner-action-funds','owner-action-funds','|| action.no_funds',''),
 ('owner-action-code','owner-action-code','|| action.result_code != 0',''),
 ('owner-action-count','owner-action-count','|| action.msgs_created != transaction.outmsg_cnt',''),
 ('owner-approval','wrong-update','|| body.fetch_ref()->get_hash() != expected_body.value()->get_hash()',''),
 ('owner-recipient','wrong-target','|| !address(message_info.dest, -1, recipient)',''),
 ('owner-shard-root','owner-shard-substitution','|| top->top_block_id().root_hash.as_slice() != block_root->get_hash().as_slice()',''),
 ('owner-minimal','owner-unrelated-reveals','if (!minimal_state.ok() || !minimal_block.ok() || minimal_state.value()->get_hash() != state_proof->get_hash() || minimal_block.value()->get_hash() != block_proof->get_hash()) return Error{"proof-unrelated-values"};',''),
]
RUST=[
 ('owner-wrapper-update','owner-wrapper-update','auth.update_id != id ||',''),
 ('owner-wrapper-stake','owner-wrapper-stake','|| auth.stake_id != current.stake_id',''),
 ('owner-wrapper-address','owner-wrapper-address','|| auth.owner_address != current.owner_address',''),
 ('owner-wrapper-workchain','owner-wrapper-workchain','|| auth.owner_workchain != current.owner_workchain',''),
 ('owner-kind','owner-proof-kind','if proof.kind != 1 { return Err(Error("proof-kind")); }',''),
 ('owner-object','owner-proof-object','if proof.object_id != id { return Err(Error("proof-object")); }',''),
 ('owner-hash','owner-proof-hash','if digest("proof", &raw)? != proof.proof_hash { return Err(Error("proof-hash")); }',''),
 ('owner-anchor','owner-proof-anchor','if proof.anchor != *anchor { return Err(Error("proof-anchor")); }',''),
 ('owner-state-root','owner-state-substitution','|| state.repr_hash().as_slice() != &anchor.state',''),
 ('owner-block-root','owner-block-substitution','|| block_root.repr_hash().as_slice() != &anchor.root',''),
 ('owner-header-tag','owner-header-tag','native(header.get_next_u32())? != OWNER_PROOF_TAG','native(header.get_next_u32())? == 0'),
 ('owner-header-version','owner-header-version','native(header.get_next_u16())? != 1','native(header.get_next_u16())? == 0'),
 ('owner-operation','owner-operation','!matches!(update.operation, 1 | 2 | 5) ||',''),
 ('owner-compute','owner-compute-success','|| !matches!(ordinary.compute_ph,TrComputePhase::Vm(ref c) if c.success)',''),
 ('owner-aborted','owner-aborted','ordinary.aborted ||',''),
 ('owner-destroyed','owner-destroyed','|| ordinary.destroyed',''),
 ('owner-action-success','owner-action-success','!action.success ||',''),
 ('owner-action-valid','owner-action-valid','|| !action.valid',''),
 ('owner-action-funds','owner-action-funds','|| action.no_funds',''),
 ('owner-action-code','owner-action-code','|| action.result_code != 0',''),
 ('owner-action-count','owner-action-count','|| action.msgs_created != tx.msg_count()',''),
 ('owner-approval','wrong-update','|| actual_body != expected',''),
 ('owner-recipient','wrong-target','|| !address(&mh.dst, -1, &recipient)',''),
 ('owner-shard-root','owner-shard-substitution','|| top.block_id().root_hash() != &block_root.repr_hash()',''),
 ('owner-minimal','owner-unrelated-reveals','if state_minimal.repr_hash() != state_proof.repr_hash() || block_minimal.repr_hash() != block_proof.repr_hash() { return Err(Error("proof-unrelated-values")); }',''),
 ('owner-nested-level','owner-valid','self.effective + u8::from(self.cell.is_merkle())','self.effective'),
]
def main(args):
 if args.language=='cpp':
  folder=args.build.resolve()/'test/validator-auth-implementation'
  def run():
   checked(['cmake','--build',str(args.build.resolve()),'--target','test-p0-owner-proof-mutant','-j2'])
   with tempfile.TemporaryDirectory(prefix='p0-owner-check-') as tmp:
    for i,inputs in enumerate((args.inputs,args.shard_inputs)):
     result=subprocess.run([str(folder/'test-p0-owner-proof-mutant'),'verify',str(inputs.resolve()),str(Path(tmp)/str(i))],capture_output=True,text=True)
     if result.returncode:return result
    return result
  report=mutate(folder/'owner-proof-mutated.cpp',CPP,run)
 else:
  with tempfile.TemporaryDirectory(prefix='p0-owner-mutations-') as tmp:
   root=Path(tmp)
   for part in ('validator-auth-native','validator-auth'):shutil.copytree(ROOT/'tosctl/src'/part,root/part)
   for part in (ROOT/'tosctl/src').iterdir():
    if part.is_dir() and part.name not in ('target','validator-auth-native','validator-auth'):(root/part.name).symlink_to(part,target_is_directory=True)
   crate=root/'validator-auth-native';manifest=crate/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n');shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
   def run():
    checked(['cargo','build','--offline','--manifest-path',str(manifest),'--bin','owner-conformance'])
    for fixtures in (args.fixtures,args.shard_fixtures):
     result=subprocess.run([str(crate/'target/debug/owner-conformance'),str(fixtures.resolve())],capture_output=True,text=True)
     if result.returncode:return result
    return result
   report=[] if args.depth_only else mutate(crate/'src/owner_proof.rs',RUST,run)
   report+=mutate(crate/'src/cells.rs',[('owner-boc-depth','owner-boc-depth','.set_max_cell_depth(1024)','')],run)
 args.out.write_text(json.dumps(dict(language=args.language,owner_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--language',choices=['cpp','rust'],required=True);p.add_argument('--build',type=Path);p.add_argument('--inputs',type=Path);p.add_argument('--fixtures',type=Path);p.add_argument('--depth-only',action='store_true');p.add_argument('--shard-inputs',type=Path);p.add_argument('--shard-fixtures',type=Path);p.add_argument('--out',type=Path,required=True);main(p.parse_args())
