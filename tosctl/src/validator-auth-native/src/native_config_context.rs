use crate::{
    committee::NativeCommittee,
    native,
    native_apply::CurrentRegistry,
    native_history::{HistoryReadBudget, NativeFinalizedHistory},
    native_registry::NativeRegistry,
    registry::StateReadBudget,
};
use chain_block::{
    BlockIdExt, Cell, CellType, Deserializable, HashmapType, McStateExtra, Serializable,
    ShardStateUnsplit, SliceData,
};
use tos_validator_auth::{
    codec::{Error, Hash},
    context::ChainContext,
    types::Anchor,
};
type OfflineHistory = NativeFinalizedHistory<fn(&BlockIdExt, usize) -> Result<Vec<u8>, Error>>;
fn unavailable(_: &BlockIdExt, _: usize) -> Result<Vec<u8>, Error> {
    Err(Error("history-block-unavailable"))
}
fn parameter(config: &chain_block::ConfigParams, index: u32) -> Result<Cell, Error> {
    let entry = native(config.config_params.get(native(index.write_to_bitstring())?))?
        .ok_or(Error("native-config"))?;
    if entry.remaining_bits() != 0 || entry.remaining_references() != 1 {
        return Err(Error("native-config"));
    }
    native(entry.reference(0))
}
fn same(a: &Option<Cell>, b: &Option<Cell>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.repr_hash() == b.repr_hash(),
        (None, None) => true,
        _ => false,
    }
}
/// Immutable native parent authority. Account bytes are selected from the actual
/// authenticated ShardAccounts dictionary, never supplied by a contract or C7.
pub struct NativeConfigContext {
    chain: ChainContext,
    head: Anchor,
    address: Hash,
    code: Cell,
    data: Cell,
    library: Option<Cell>,
    config: Cell,
    parent: NativeRegistry,
    committee: NativeCommittee,
    history: OfflineHistory,
}
impl NativeConfigContext {
    pub fn open(
        root: Cell,
        head: &Anchor,
        chain: &ChainContext,
        cached: Option<&NativeRegistry>,
        budget: StateReadBudget,
    ) -> Result<Self, Error> {
        let history = NativeFinalizedHistory::open(
            root.clone(),
            head.clone(),
            chain.clone(),
            unavailable as fn(&BlockIdExt, usize) -> Result<Vec<u8>, Error>,
            HistoryReadBudget { blocks: 0, bytes: 0 },
        )?;
        let state = native(ShardStateUnsplit::construct_from_full_cell(root.clone()))?;
        let extra = native(McStateExtra::construct_from_full_cell(
            state.custom_cell().ok_or(Error("config-native-state"))?,
        ))?;
        let config = &extra.config;
        let address_cell = parameter(config, 0)?;
        if address_cell.cell_type() != CellType::Ordinary
            || address_cell.bit_length() != 256
            || address_cell.references_count() != 0
        {
            return Err(Error("config-address"));
        }
        let mut a = native(SliceData::load_cell(address_cell))?;
        let address: Hash =
            native(a.get_next_bits(256))?.try_into().map_err(|_| Error("config-address"))?;
        if address == [0; 32] {
            return Err(Error("config-address"));
        }
        if config.config_addr.remaining_bits() != 256
            || config.config_addr.get_bytestring(0) != address
        {
            return Err(Error("config-address-binding"));
        }
        let accounts = native(state.read_accounts())?;
        let shard_account =
            native(accounts.account(&config.config_addr))?.ok_or(Error("config-account"))?;
        let account = native(shard_account.read_account())?;
        let addr = account.get_addr().ok_or(Error("config-account"))?;
        let init = account.state_init().ok_or(Error("config-account"))?;
        let code = account.get_code().ok_or(Error("config-account"))?;
        let data = account.get_data().ok_or(Error("config-account"))?;
        if addr.workchain_id() != -1
            || addr.rewrite_pfx().is_some()
            || addr.address().get_bytestring(0) != address
            || account.get_tick_tock().is_none_or(|t| !t.tick)
            || code.level() != 0
            || data.level() != 0
            || account.last_tr_time().ok_or(Error("config-account"))?.max(1)
                <= shard_account.last_trans_lt()
        {
            return Err(Error("config-account"));
        }
        let mut d = native(SliceData::load_cell(data.clone()))?;
        if d.cell_type() != CellType::Ordinary
            || d.remaining_bits() != 289
            || d.remaining_references() < 2
        {
            return Err(Error("config-data"));
        }
        let owned_config = native(d.checked_drain_reference())?;
        let actual_config = config.config_params.data().ok_or(Error("config-native-state"))?;
        if owned_config.repr_hash() != actual_config.repr_hash() {
            return Err(Error("config-dictionary-binding"));
        }
        native(d.get_next_bits(288))?;
        if native(d.get_next_bit())? {
            if d.remaining_references() != 2 {
                return Err(Error("config-data"));
            }
            native(d.checked_drain_reference())?;
        }
        if d.remaining_references() != 1 {
            return Err(Error("config-data"));
        }
        let checkpoint = native(d.checked_drain_reference())?;
        let registry = parameter(config, 46)?;
        let parent = match cached {
            Some(value) => {
                if value.coordinate() != head.seqno
                    || value.checkpoint()?.repr_hash() != checkpoint.repr_hash()
                    || value.encode_cell()?.repr_hash() != registry.repr_hash()
                {
                    return Err(Error("config-cache-binding"));
                }
                value.clone()
            }
            None => NativeRegistry::restore(
                checkpoint,
                registry.repr_hash().as_slice(),
                head.seqno,
                budget,
            )?,
        };
        let committee = NativeCommittee::derive(
            root,
            head,
            chain,
            -1,
            1 << 63,
            extra.validator_info.catchain_seqno,
            budget,
        )?;
        Ok(Self {
            chain: chain.clone(),
            head: head.clone(),
            address,
            code,
            data,
            library: init.library.root().cloned(),
            config: actual_config.clone(),
            parent,
            committee,
            history,
        })
    }
    pub fn binds(
        &self,
        workchain: i32,
        address: &Hash,
        code: Cell,
        data: Cell,
        library: Option<Cell>,
    ) -> Result<bool, Error> {
        if workchain != -1
            || address != &self.address
            || code.repr_hash() != self.code.repr_hash()
            || data.repr_hash() != self.data.repr_hash()
            || !same(&library, &self.library)
        {
            return Err(Error("config-transaction-binding"));
        }
        Ok(true)
    }
    pub fn chain(&self) -> &ChainContext {
        &self.chain
    }
    pub fn head(&self) -> &Anchor {
        &self.head
    }
    pub fn address(&self) -> &Hash {
        &self.address
    }
    pub fn parent(&self) -> &NativeRegistry {
        &self.parent
    }
    pub fn committee(&self) -> &NativeCommittee {
        &self.committee
    }
    pub fn history(&self) -> &OfflineHistory {
        &self.history
    }
    pub fn config(&self) -> Cell {
        self.config.clone()
    }
    pub fn data(&self) -> Cell {
        self.data.clone()
    }
}
