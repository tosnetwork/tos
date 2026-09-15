use crate::{
    cells, native, native_apply::FinalizedAnchorSource, registry::StateReadBudget,
    registry_view::RegistryView,
};
use chain_block::{
    Block, BlockIdExt, Cell, CellType, Deserializable, HashmapAugType, McStateExtra,
    OldMcBlocksInfo, Serializable, ShardStateUnsplit, SliceData,
};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, collections::BTreeMap};
use tos_validator_auth::{
    codec::{Error, Hash},
    context::ChainContext,
    types::Anchor,
};
#[path = "native_header.rs"]
mod header;
pub use header::native_header_proof;
#[derive(Clone, Copy)]
pub struct HistoryReadBudget {
    pub blocks: usize,
    pub bytes: usize,
}
impl Default for HistoryReadBudget {
    fn default() -> Self {
        Self { blocks: 129, bytes: 268_435_456 }
    }
}
struct Access<F> {
    read: F,
    budget: HistoryReadBudget,
    cache: BTreeMap<u32, Anchor>,
}
/// Request-scoped, serialized access to an independently finalized native state.
/// The block source supplies original BOC bytes and must honor the given read bound.
pub struct NativeFinalizedHistory<F> {
    history: OldMcBlocksInfo,
    head: Anchor,
    chain: ChainContext,
    access: RefCell<Access<F>>,
}
fn hash(raw: &[u8]) -> Result<Hash, Error> {
    raw.try_into().map_err(|_| Error("native-hash"))
}
fn parameter(config: &chain_block::ConfigParams, index: u32) -> Result<Cell, Error> {
    let entry = native(config.config_params.get(native(index.write_to_bitstring())?))?
        .ok_or(Error("native-config"))?;
    if entry.remaining_bits() != 0 || entry.remaining_references() != 1 {
        return Err(Error("native-config"));
    }
    native(entry.reference(0))
}
impl<F> NativeFinalizedHistory<F> {
    pub fn open(
        root: Cell,
        head: Anchor,
        chain: ChainContext,
        read: F,
        budget: HistoryReadBudget,
    ) -> Result<Self, Error> {
        if root.level() != 0
            || head.seqno == u32::MAX
            || head.root == [0; 32]
            || head.file == [0; 32]
            || head.state != hash(root.repr_hash().as_slice())?
        {
            return Err(Error("history-anchor"));
        }
        if chain.genesis_root == [0; 32]
            || chain.genesis_file == [0; 32]
            || chain.chain_domain == [0; 32]
        {
            return Err(Error("chain-context"));
        }
        let header = ShardStateUnsplit::construct_from_full_cell(root)
            .map_err(|_| Error("history-native-state"))?;
        if header.global_id() == 0
            || header.seq_no() != head.seqno
            || !header.shard().is_masterchain_ext()
        {
            return Err(Error("history-native-state"));
        }
        let extra = McStateExtra::construct_from_full_cell(
            header.custom_cell().ok_or(Error("history-native-state"))?,
        )
        .map_err(|_| Error("history-native-state"))?;
        // Match native ConfigInfo genesis admission before accepting its index.
        let zero = if head.seqno == 0 {
            (head.root, head.file)
        } else {
            let entry = native(extra.prev_blocks.get(&0))?.ok_or(Error("history-native-state"))?;
            if entry.blk_ref.seq_no != 0 {
                return Err(Error("history-native-state"));
            }
            (hash(entry.blk_ref.root_hash.as_slice())?, hash(entry.blk_ref.file_hash.as_slice())?)
        };
        if header.global_id() != chain.network {
            return Err(Error("history-network"));
        }
        if zero != (chain.genesis_root, chain.genesis_file)
            || head.seqno == 0 && head.root != head.state
        {
            return Err(Error("history-genesis"));
        }
        let mut cap = native(SliceData::load_cell(parameter(&extra.config, 8)?))?;
        if cap.cell_type() != CellType::Ordinary
            || cap.remaining_bits() != 104
            || cap.remaining_references() != 0
            || native(cap.get_next_byte())? != 0xc4
            || native(cap.get_next_u32())? < 16
            || native(cap.get_next_u64())? & 1024 == 0
        {
            return Err(Error("history-capability"));
        }
        let registry = RegistryView::open(
            parameter(&extra.config, 46)?,
            head.seqno,
            StateReadBudget::default(),
        )?;
        if registry.chain_domain != chain.chain_domain {
            return Err(Error("history-domain"));
        }
        Ok(Self {
            history: extra.prev_blocks,
            head,
            chain,
            access: RefCell::new(Access { read, budget, cache: BTreeMap::new() }),
        })
    }
}
impl<F: FnMut(&BlockIdExt, usize) -> Result<Vec<u8>, Error>> FinalizedAnchorSource
    for NativeFinalizedHistory<F>
{
    fn finalized_anchor(&self, at: u32) -> Result<Anchor, Error> {
        if at > self.head.seqno || at == u32::MAX {
            return Err(Error("history-future"));
        }
        if at == self.head.seqno {
            return Ok(self.head.clone());
        }
        let mut access = self.access.try_borrow_mut().map_err(|_| Error("history-busy"))?;
        if let Some(found) = access.cache.get(&at) {
            return Ok(found.clone());
        }
        let entry = native(self.history.get(&at))?.ok_or(Error("finalized-anchor-unavailable"))?;
        if entry.blk_ref.seq_no != at
            || entry.blk_ref.root_hash.is_zero()
            || entry.blk_ref.file_hash.is_zero()
        {
            return Err(Error("finalized-anchor-unavailable"));
        }
        if at == 0 {
            return Ok(Anchor {
                seqno: 0,
                root: self.chain.genesis_root,
                file: self.chain.genesis_file,
                state: self.chain.genesis_root,
            });
        }
        if access.budget.blocks == 0 || access.budget.bytes == 0 {
            return Err(Error("history-resource"));
        }
        access.budget.blocks =
            access.budget.blocks.checked_sub(1).ok_or(Error("history-resource"))?;
        let id = BlockIdExt::from_ext_blk(entry.blk_ref);
        let maximum = 67_108_864.min(access.budget.bytes);
        let raw = (access.read)(&id, maximum)?;
        if raw.is_empty() || raw.len() > maximum {
            return Err(Error("history-block-bound"));
        }
        access.budget.bytes =
            access.budget.bytes.checked_sub(raw.len()).ok_or(Error("history-resource"))?;
        if Sha256::digest(&raw).as_slice() != id.file_hash.as_slice() {
            return Err(Error("history-file-hash"));
        }
        let root = cells::read_boc(&raw, true).map_err(|_| Error("history-boc"))?;
        if root.level() != 0 || root.repr_hash() != id.root_hash {
            return Err(Error("history-block-root"));
        }
        let block = Block::construct_from_full_cell(root).map_err(|_| Error("history-block"))?;
        let info = block.read_info().map_err(|_| Error("history-block"))?;
        if block.global_id() != self.chain.network
            || info.seq_no() != at
            || !info.shard().is_masterchain_ext()
        {
            return Err(Error("history-block-context"));
        }
        let update_cell = block.state_update_cell();
        if update_cell.cell_type() != CellType::MerkleUpdate || update_cell.level() != 0 {
            return Err(Error("history-state-update"));
        }
        let update = block.read_state_update().map_err(|_| Error("history-state-update"))?;
        let state = hash(update.new_hash.as_slice())?;
        if state == [0; 32] {
            return Err(Error("history-state-update"));
        }
        let result = Anchor {
            seqno: at,
            root: hash(id.root_hash.as_slice())?,
            file: hash(id.file_hash.as_slice())?,
            state,
        };
        access.cache.insert(at, result.clone());
        Ok(result)
    }
}
