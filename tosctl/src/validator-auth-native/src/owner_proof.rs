use crate::{cells, native, registry::StateReadBudget, registry_view::RegistryView};
use chain_block::{
    Block, Cell, CellType, Deserializable, HashmapAugType, McStateExtra, MerkleProof,
    MsgAddressInt, MsgAddressIntOrNone, Serializable, ShardIdent, ShardStateUnsplit, SliceData,
    TrComputePhase, TransactionDescr, UsageTree,
};
use tos_validator_auth::{
    codec::{Error, Hash},
    context::ChainContext,
    crypto::{digest, object_id},
    transfer::ObjectReader,
    types::{Anchor, Identity, ObjectRef, OwnerAuth, Update},
};
pub const OWNER_APPROVAL_TAG: u32 = 0x76616f31;
pub const OWNER_PROOF_TAG: u32 = 0x76616f70;
/// A finalized successful native owner action, not PoP or committee authority.
pub struct VerifiedOwnerExecution {
    update_id: Hash,
    transaction_id: Hash,
    anchor: Anchor,
}
impl VerifiedOwnerExecution {
    pub fn update_id(&self) -> &Hash {
        &self.update_id
    }
    pub fn transaction_id(&self) -> &Hash {
        &self.transaction_id
    }
    pub fn anchor(&self) -> &Anchor {
        &self.anchor
    }
}
fn binding(chain: &ChainContext, update: &Update, current: &Identity) -> Result<Hash, Error> {
    if chain.genesis_root == [0; 32]
        || chain.genesis_file == [0; 32]
        || chain.chain_domain == [0; 32]
    {
        return Err(Error("chain-context"));
    }
    if !matches!(update.operation, 1 | 2 | 5)
        || update.identity == [0; 32]
        || update.identity != current.identity
        || current.stake_id == [0; 32]
    {
        return Err(Error("owner-target"));
    }
    object_id("update", update)
}
fn parameter(config: &chain_block::ConfigParams, index: u32) -> Result<Cell, Error> {
    let entry = native(config.config_params.get(native(index.write_to_bitstring())?))?
        .ok_or(Error("native-config"))?;
    if entry.remaining_bits() != 0 || entry.remaining_references() != 1 {
        return Err(Error("native-config"));
    }
    native(entry.reference(0))
}
fn address(addr: &MsgAddressInt, wc: i32, expected: &Hash) -> bool {
    let (workchain, anycast, bits) = match addr {
        MsgAddressInt::AddrStd(a) => (i32::from(a.workchain_id), a.anycast.is_some(), &a.address),
        MsgAddressInt::AddrVar(a) => (a.workchain_id, a.anycast.is_some(), &a.address),
    };
    !anycast
        && workchain == wc
        && bits.remaining_bits() == 256
        && bits.remaining_references() == 0
        && bits.get_bytestring(0) == expected
}
struct Header {
    shard: ShardIdent,
    seqno: u32,
    start: u64,
    end: u64,
}
fn block_header(cell: Cell) -> Result<Header, Error> {
    // Only the authenticated header fields needed by this proof are opened.
    // Native predecessor/history subtrees remain pruned in both implementations.
    let mut s = native(SliceData::load_cell(cell))?;
    if s.cell_type() != CellType::Ordinary || native(s.get_next_u32())? != 0x9bc7a987 {
        return Err(Error("owner-block"));
    }
    native(s.get_next_u32())?;
    let flags = native(s.get_next_byte())?;
    let software = native(s.get_next_byte())?;
    let seqno = native(s.get_next_u32())?;
    let vertical = native(s.get_next_u32())?;
    if software > 1 || seqno == 0 || vertical < u32::from(flags & 1) {
        return Err(Error("owner-block"));
    }
    let shard = native(ShardIdent::construct_from(&mut s))?;
    native(s.get_next_u32())?;
    let start = native(s.get_next_u64())?;
    let end = native(s.get_next_u64())?;
    native(s.get_next_bits(128))?;
    if software == 1 {
        native(s.get_next_bits(104))?;
    }
    if s.remaining_bits() != 0
        || s.remaining_references()
            != 1 + usize::from(flags & 128 != 0) + usize::from(flags & 1 != 0)
    {
        return Err(Error("owner-block"));
    }
    Ok(Header { shard, seqno, start, end })
}
fn executed(
    state: Cell,
    block_root: Cell,
    anchor: &Anchor,
    chain: &ChainContext,
    update: &Update,
    current: &Identity,
    locator: (u64, u16),
) -> Result<Hash, Error> {
    let (lt, index) = locator;
    let id = binding(chain, update, current)?;
    if anchor.seqno == 0
        || anchor.seqno == u32::MAX
        || anchor.root == [0; 32]
        || anchor.file == [0; 32]
        || state.repr_hash().as_slice() != &anchor.state
    {
        return Err(Error("owner-anchor"));
    }
    let header = native(ShardStateUnsplit::construct_from_full_cell(state))?;
    if header.global_id() != chain.network
        || header.seq_no() != anchor.seqno
        || !header.shard().is_masterchain_ext()
    {
        return Err(Error("state-context"));
    }
    let extra = native(McStateExtra::construct_from_full_cell(
        header.custom_cell().ok_or(Error("native-config"))?,
    ))?;
    let config = &extra.config;
    let mut caps = native(SliceData::load_cell(parameter(config, 8)?))?;
    if caps.cell_type() != CellType::Ordinary
        || caps.remaining_bits() != 104
        || caps.remaining_references() != 0
        || native(caps.get_next_byte())? != 0xc4
        || native(caps.get_next_u32())? < 16
        || native(caps.get_next_u64())? & 1024 == 0
    {
        return Err(Error("owner-capability"));
    }
    let registry =
        RegistryView::open(parameter(config, 46)?, anchor.seqno, StateReadBudget::default())?;
    if registry.chain_domain != chain.chain_domain {
        return Err(Error("chain-domain"));
    }
    let allocated = registry.identity(&current.identity)?;
    if allocated.stake_id != current.stake_id
        || allocated.owner_workchain != current.owner_workchain
        || allocated.owner_address != current.owner_address
    {
        return Err(Error("owner-allocation"));
    }
    let mut recipient = native(SliceData::load_cell(parameter(config, 1)?))?;
    if recipient.cell_type() != CellType::Ordinary
        || recipient.remaining_bits() != 256
        || recipient.remaining_references() != 0
    {
        return Err(Error("owner-recipient"));
    }
    let recipient: Hash =
        native(recipient.get_next_bits(256))?.try_into().map_err(|_| Error("owner-recipient"))?;
    if recipient == [0; 32] {
        return Err(Error("owner-recipient"));
    }
    let block = native(Block::construct_from_full_cell(block_root.clone()))?;
    let info = block_header(block.info_cell())?;
    let owner = native(current.owner_address.write_to_bitstring())?;
    if block.global_id() != chain.network
        || info.shard.workchain_id() != current.owner_workchain
        || !native(info.shard.contains_account(&owner))?
    {
        return Err(Error("owner-block-context"));
    }
    if current.owner_workchain == -1 {
        if !info.shard.is_masterchain_ext()
            || info.seqno != anchor.seqno
            || block_root.repr_hash().as_slice() != &anchor.root
        {
            return Err(Error("owner-block-anchor"));
        }
        let change = native(block.read_state_update())?;
        if change.new_hash.as_slice() != &anchor.state {
            return Err(Error("owner-state-update"));
        }
    } else {
        let top =
            native(extra.shards().get_shard(&info.shard))?.ok_or(Error("owner-shard-anchor"))?;
        if top.block_id().seq_no() != info.seqno
            || top.block_id().root_hash() != &block_root.repr_hash()
        {
            return Err(Error("owner-shard-anchor"));
        }
    }
    if lt <= info.start || lt >= info.end {
        return Err(Error("owner-transaction"));
    }
    let blocks = native(native(block.read_extra())?.read_account_blocks())?;
    let account = native(blocks.get(&owner))?.ok_or(Error("owner-transaction"))?;
    let tx = native(account.transaction(lt))?.ok_or(Error("owner-transaction"))?;
    if account.account_id() != &owner || tx.account_id() != &owner || tx.logical_time() != lt {
        return Err(Error("owner-transaction-binding"));
    }
    let description = native(tx.read_description())?;
    let ordinary = match description {
        TransactionDescr::Ordinary(o) => o,
        _ => return Err(Error("owner-execution")),
    };
    if ordinary.aborted
        || ordinary.destroyed
        || !matches!(ordinary.compute_ph,TrComputePhase::Vm(ref c) if c.success)
    {
        return Err(Error("owner-execution"));
    }
    let action = ordinary.action.ok_or(Error("owner-execution"))?;
    if !action.success || !action.valid || action.no_funds || action.result_code != 0 {
        return Err(Error("owner-execution"));
    }
    if i32::from(index) >= i32::from(tx.msg_count()) || action.msgs_created != tx.msg_count() {
        return Err(Error("owner-message-index"));
    }
    let msg = native(tx.get_out_msg(index as i16))?.ok_or(Error("owner-message"))?;
    let mh = msg.int_header().ok_or(Error("owner-message"))?;
    if mh.bounced
        || !mh.ihr_disabled
        || !matches!(&mh.src,MsgAddressIntOrNone::Some(a) if address(a,current.owner_workchain,&current.owner_address))
        || !address(&mh.dst, -1, &recipient)
        || msg.state_init().is_some()
    {
        return Err(Error("owner-message"));
    }
    if lt.checked_add(1).and_then(|n| n.checked_add(u64::from(index))) != Some(mh.created_lt) {
        return Err(Error("owner-message-time"));
    }
    let body = msg.body().ok_or(Error("owner-approval"))?;
    let mut expected = Vec::with_capacity(102);
    expected.extend_from_slice(&OWNER_APPROVAL_TAG.to_be_bytes());
    expected.extend_from_slice(&1u16.to_be_bytes());
    expected.extend_from_slice(&chain.chain_domain);
    expected.extend_from_slice(&current.stake_id);
    expected.extend_from_slice(&id);
    let actual_body = body.get_bytestring(0);
    if body.remaining_bits() != 816 || body.remaining_references() != 0 || actual_body != expected {
        return Err(Error("owner-approval"));
    }
    Ok(*native(tx.serialize())?.repr_hash().as_slice())
}
pub fn verify_owner_execution<F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>>(
    auth: &OwnerAuth,
    update: &Update,
    current: &Identity,
    anchor: &Anchor,
    chain: &ChainContext,
    reader: &mut ObjectReader<F>,
) -> Result<VerifiedOwnerExecution, Error> {
    let id = binding(chain, update, current)?;
    if auth.update_id != id
        || auth.stake_id != current.stake_id
        || auth.owner_workchain != current.owner_workchain
        || auth.owner_address != current.owner_address
    {
        return Err(Error("owner-binding"));
    }
    let proof = &auth.proof;
    if proof.anchor != *anchor {
        return Err(Error("proof-anchor"));
    }
    if proof.kind != 1 {
        return Err(Error("proof-kind"));
    }
    if proof.object_id != id {
        return Err(Error("proof-object"));
    }
    let raw = reader.resolve(&proof.proof, 5)?;
    if digest("proof", &raw)? != proof.proof_hash {
        return Err(Error("proof-hash"));
    }
    let cell = cells::read_boc(&raw, true)?;
    let mut header = native(SliceData::load_cell(cell))?;
    if header.cell_type() != CellType::Ordinary
        || header.remaining_bits() != 127
        || header.remaining_references() != 2
        || native(header.get_next_u32())? != OWNER_PROOF_TAG
        || native(header.get_next_u16())? != 1
    {
        return Err(Error("owner-proof-header"));
    }
    let lt = native(header.get_next_u64())?;
    let index = native(header.get_next_int(15))? as u16;
    let state_proof = native(header.checked_drain_reference())?;
    let block_proof = native(header.checked_drain_reference())?;
    let state =
        virtualize(native(MerkleProof::construct_from_full_cell(state_proof.clone()))?.proof, 0);
    let block =
        virtualize(native(MerkleProof::construct_from_full_cell(block_proof.clone()))?.proof, 0);
    let state_used = UsageTree::with_root(state.clone());
    let block_used = UsageTree::with_root(block.clone());
    let transaction_id = executed(
        state_used.root_cell(),
        block_used.root_cell(),
        anchor,
        chain,
        update,
        current,
        (lt, index),
    )?;
    let state_minimal = canonical_proof(&state, &state_used)?;
    let block_minimal = canonical_proof(&block, &block_used)?;
    if state_minimal.repr_hash() != state_proof.repr_hash()
        || block_minimal.repr_hash() != block_proof.repr_hash()
    {
        return Err(Error("proof-unrelated-values"));
    }
    Ok(VerifiedOwnerExecution { update_id: id, transaction_id, anchor: anchor.clone() })
}

fn canonical_proof(root: &Cell, used: &UsageTree) -> Result<Cell, Error> {
    use chain_block::{BuilderData, IBitstring, UInt256};
    use std::collections::BTreeMap;
    fn build(
        cell: &Cell,
        used: &UsageTree,
        depth: u8,
        height: usize,
        memo: &mut BTreeMap<(UInt256, u8), Cell>,
    ) -> Result<Cell, Error> {
        let key = (cell.repr_hash(), depth);
        if let Some(old) = memo.get(&key) {
            return Ok(old.clone());
        }
        if height > 1024 || memo.len() >= 400_001 || depth > 3 {
            return Err(Error("proof-pruning-bound"));
        }
        let result = if cell.virtualization() == 0
            && cell.cell_type() == CellType::PrunedBranch
            && cell.level_mask().mask() < (1 << depth)
        {
            // Preserve native lower-level pruned data under a Merkle update.
            cell.clone()
        } else if !used.contains(&cell.repr_hash()) {
            if depth >= 3 || cell.level_mask().mask() >= (1 << depth) {
                return Err(Error("proof-pruning-bound"));
            }
            let mut b = BuilderData::new();
            b.set_type(CellType::PrunedBranch);
            native(b.append_u8(1))?;
            native(b.append_u8(cell.level_mask().mask() | (1 << depth)))?;
            for hash in cell.hashes() {
                native(b.append_raw(hash.as_slice(), 256))?;
            }
            for d in cell.depths() {
                native(b.append_u16(d))?;
            }
            native(b.into_cell())?
        } else {
            let mut b = native(BuilderData::with_raw(cell.data().to_vec(), cell.bit_length()))?;
            b.set_type(cell.cell_type());
            let child_depth = depth + u8::from(cell.is_merkle());
            for i in 0..cell.references_count() {
                native(b.checked_append_reference(build(
                    &native(cell.reference(i))?,
                    used,
                    child_depth,
                    height + 1,
                    memo,
                )?))?;
            }
            native(b.into_cell())?
        };
        memo.insert(key, result.clone());
        Ok(result)
    }
    let proof = build(root, used, 0, 0, &mut BTreeMap::new())?;
    native(MerkleProof { hash: root.repr_hash(), depth: root.repr_depth(), proof }.serialize())
}

// Native Merkle cells increment the child's effective level. Apply an absolute
// level cap; shifting every descendant by one loses an intrinsic update hash.
fn virtualize(cell: Cell, effective: u8) -> Cell {
    if cell.level_mask().mask() < (1 << effective) {
        return cell;
    }
    Cell::with_cell_impl(EffectiveCell { cell, effective })
}
struct EffectiveCell {
    cell: Cell,
    effective: u8,
}
impl chain_block::CellImpl for EffectiveCell {
    fn data(&self) -> &[u8] {
        self.cell.data()
    }
    fn raw_data(&self) -> chain_block::Result<&[u8]> {
        Err(std::io::Error::other("virtual proof has no raw BOC").into())
    }
    fn bit_length(&self) -> usize {
        self.cell.bit_length()
    }
    fn references_count(&self) -> usize {
        self.cell.references_count()
    }
    fn reference(&self, index: usize) -> chain_block::Result<Cell> {
        Ok(virtualize(
            self.cell.reference(index)?,
            self.effective + u8::from(self.cell.is_merkle()),
        ))
    }
    fn cell_type(&self) -> CellType {
        self.cell.cell_type()
    }
    fn level_mask(&self) -> chain_block::LevelMask {
        chain_block::LevelMask::with_mask(
            self.cell.level_mask().mask() & ((1 << self.effective) - 1),
        )
    }
    fn hash(&self, index: usize) -> chain_block::UInt256 {
        self.cell.hash(index.min(usize::from(self.effective)))
    }
    fn depth(&self, index: usize) -> u16 {
        self.cell.depth(index.min(usize::from(self.effective)))
    }
    fn store_hashes(&self) -> bool {
        self.cell.store_hashes()
    }
    fn virtualization(&self) -> u8 {
        1
    }
}
