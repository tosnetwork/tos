use super::*;
use chain_block::{BuilderData, IBitstring, MerkleProof, ShardIdent};

fn terminal(cell: &Cell, depth: u8) -> bool {
    let mask = cell.level_mask().mask();
    cell.cell_type() == CellType::PrunedBranch
        && cell.references_count() == 0
        && if depth == 0 { mask == 1 } else { mask == 2 || mask == 3 }
}
// Fixed surface: at most eleven cell occurrences, depth three. Reject extra
// reveals before parsing native fields or performing any history resolution.
fn surface(proof: &Cell) -> Result<Cell, Error> {
    if proof.virtualization() != 0
        || proof.level() != 0
        || proof.cell_type() != CellType::MerkleProof
        || proof.bit_length() != 280
        || proof.references_count() != 1
    {
        return Err(Error("header-surface"));
    }
    let root = native(proof.reference(0))?;
    if root.cell_type() != CellType::Ordinary
        || root.bit_length() != 64
        || root.references_count() != 4
    {
        return Err(Error("header-surface"));
    }
    if !terminal(&native(root.reference(1))?, 0) || !terminal(&native(root.reference(3))?, 0) {
        return Err(Error("header-surface"));
    }
    let info = native(root.reference(0))?;
    if info.cell_type() != CellType::Ordinary || !(1..=3).contains(&info.references_count()) {
        return Err(Error("header-surface"));
    }
    for i in 0..info.references_count() {
        if !terminal(&native(info.reference(i))?, 0) {
            return Err(Error("header-surface"));
        }
    }
    let update = native(root.reference(2))?;
    if update.cell_type() != CellType::MerkleUpdate
        || update.bit_length() != 552
        || update.references_count() != 2
        || !terminal(&native(update.reference(0))?, 1)
        || !terminal(&native(update.reference(1))?, 1)
    {
        return Err(Error("header-surface"));
    }
    Ok(root)
}
fn prune(cell: Cell, depth: u8) -> Result<Cell, Error> {
    if cell.level_mask().mask() >= (1 << depth) {
        return Err(Error("header-generation"));
    }
    let mut b = BuilderData::new();
    b.set_type(CellType::PrunedBranch);
    native(b.append_u8(1))?;
    native(b.append_u8(cell.level_mask().mask() | (1 << depth)))?;
    for h in cell.hashes() {
        native(b.append_raw(h.as_slice(), 256))?;
    }
    for d in cell.depths() {
        native(b.append_u16(d))?;
    }
    native(b.into_cell())
}
fn prune_refs(cell: Cell, depth: u8) -> Result<Cell, Error> {
    let mut b = native(BuilderData::with_raw(cell.data().to_vec(), cell.bit_length()))?;
    b.set_type(cell.cell_type());
    for i in 0..cell.references_count() {
        native(b.checked_append_reference(prune(native(cell.reference(i))?, depth)?))?;
    }
    native(b.into_cell())
}
pub fn native_header_proof(block: Cell) -> Result<Cell, Error> {
    if block.level() != 0 || block.virtualization() != 0 {
        return Err(Error("header-block"));
    }
    let record =
        Block::construct_from_full_cell(block.clone()).map_err(|_| Error("header-block"))?;
    block_header(record.info_cell())?;
    let update = record.state_update_cell();
    if update.cell_type() != CellType::MerkleUpdate
        || update.bit_length() != 552
        || update.references_count() != 2
    {
        return Err(Error("header-state-update"));
    }
    let mut b = native(BuilderData::with_raw(block.data().to_vec(), block.bit_length()))?;
    native(b.checked_append_reference(prune_refs(record.info_cell(), 0)?))?;
    native(b.checked_append_reference(prune(native(block.reference(1))?, 0)?))?;
    native(b.checked_append_reference(prune_refs(update, 1)?))?;
    native(b.checked_append_reference(prune(native(block.reference(3))?, 0)?))?;
    let root = native(b.into_cell())?;
    if root.hash(0) != block.repr_hash() {
        return Err(Error("header-generation"));
    }
    let proof = native(
        MerkleProof { hash: block.repr_hash(), depth: block.repr_depth(), proof: root }.serialize(),
    )?;
    surface(&proof)?;
    Ok(proof)
}
fn block_header(cell: Cell) -> Result<(u32, bool, ShardIdent), Error> {
    let mut s = native(SliceData::load_cell(cell))?;
    if s.cell_type() != CellType::Ordinary || native(s.get_next_u32())? != 0x9bc7a987 {
        return Err(Error("header-block"));
    }
    native(s.get_next_u32())?;
    let flags = native(s.get_next_byte())?;
    let software = native(s.get_next_byte())?;
    let seqno = native(s.get_next_u32())?;
    let vertical = native(s.get_next_u32())?;
    if software > 1 || seqno == 0 || vertical < u32::from(flags & 1) {
        return Err(Error("header-block"));
    }
    let shard = native(ShardIdent::construct_from(&mut s))?;
    native(s.get_next_bits(288))?;
    if software == 1 {
        native(s.get_next_bits(104))?;
    }
    if s.remaining_bits() != 0
        || s.remaining_references()
            != 1 + usize::from(flags & 128 != 0) + usize::from(flags & 1 != 0)
    {
        return Err(Error("header-block"));
    }
    Ok((seqno, flags & 128 != 0, shard))
}
impl<F> NativeFinalizedHistory<F> {
    /// Authenticate a fixed-surface header witness without archive IO or cache
    /// effects. The caller cannot provide a competing native block commitment.
    pub fn authenticate_header(&self, at: u32, proof: Cell) -> Result<Anchor, Error> {
        if at == 0 || at > self.head.seqno || at == u32::MAX {
            return Err(Error("header-coordinate"));
        }
        let (root_hash, file_hash) = if at == self.head.seqno {
            (self.head.root, self.head.file)
        } else {
            let entry = native(self.history.get(&at))?.ok_or(Error("header-index"))?;
            if entry.blk_ref.seq_no != at
                || entry.blk_ref.root_hash.is_zero()
                || entry.blk_ref.file_hash.is_zero()
            {
                return Err(Error("header-index"));
            }
            (hash(entry.blk_ref.root_hash.as_slice())?, hash(entry.blk_ref.file_hash.as_slice())?)
        };
        let root = surface(&proof)?;
        if root.hash(0).as_slice() != &root_hash {
            return Err(Error("header-root"));
        }
        let record = Block::construct_from_full_cell(root).map_err(|_| Error("header-block"))?;
        let (seqno, not_master, shard) = block_header(record.info_cell())?;
        if record.global_id() != self.chain.network
            || seqno != at
            || not_master
            || !shard.is_masterchain_ext()
        {
            return Err(Error("header-context"));
        }
        let mut update = native(SliceData::load_cell(record.state_update_cell()))?;
        native(update.get_next_bits(8 + 256))?;
        let state = hash(&native(update.get_next_bits(256))?)?;
        if state == [0; 32] {
            return Err(Error("header-state"));
        }
        if at == self.head.seqno && state != self.head.state {
            return Err(Error("header-head-state"));
        }
        Ok(Anchor { seqno: at, root: root_hash, file: file_hash, state })
    }
}
