//! Pure checks that the monitored shard states come only from what the frontier commits to:
//! the shard inventory its block records and the configuration of the state it records. Each
//! refusal case changes exactly one property of an otherwise valid answer, so the check named
//! in its message is the one that refuses.
use super::*;
use chain_block::{
    BlockExtra, BlockInfo, ConfigParam0, ConfigParam12, ConfigParamEnum, ExtBlkRef, HashmapAugType,
    KeyExtBlkRef, McBlockExtra, McStateExtra, MerkleUpdate, ShardIdent, UsageTree, WorkchainDescr,
};
use tos::lite_server::{allshardsinfo, configinfo};

const GLOBAL_ID: i32 = 3;
const FRONTIER: u32 = 10;

fn hash(salt: u8, kind: u8) -> UInt256 {
    UInt256::from([salt ^ kind; 32])
}

/// A configuration whose ConfigParam 12 lists `(id, active, salt)` workchains; the zero-state
/// hashes are derived from `salt`.
fn config(workchains: &[(i32, bool, u8)]) -> Result<ConfigParams> {
    let mut param = ConfigParam12::new();
    for &(id, active, salt) in workchains {
        let descr = WorkchainDescr {
            active,
            zerostate_root_hash: hash(salt, 0x10),
            zerostate_file_hash: hash(salt, 0x20),
            ..WorkchainDescr::default()
        };
        param.insert(id, &descr)?;
    }
    let mut config = ConfigParams::default();
    config.set_config(ConfigParamEnum::ConfigParam12(param))?;
    Ok(config)
}

/// A shard inventory listing `(workchain, salt)` entries at their zero state.
fn shards(entries: &[(i32, u8)]) -> Result<ShardHashes> {
    let mut shards = ShardHashes::default();
    for &(workchain, salt) in entries {
        shards.add_workchain(workchain, 0, hash(salt, 0x30), hash(salt, 0x40))?;
    }
    Ok(shards)
}

/// A state of `shard` at `seq_no`; with `config`, it carries a masterchain extra holding
/// that configuration, the shard inventory and one previous block, so a proof that visits
/// only the configuration leaves the rest pruned.
fn mc_state(
    global_id: i32,
    seq_no: u32,
    shard: ShardIdent,
    salt: u32,
    config: Option<&ConfigParams>,
    inventory: &ShardHashes,
) -> Result<chain_block::Cell> {
    let mut state = ShardStateUnsplit::with_ident(shard);
    state.set_global_id(global_id);
    state.set_seq_no(seq_no);
    state.set_gen_time(2000 + salt);
    if let Some(config) = config {
        let mut extra = McStateExtra { config: config.clone(), ..McStateExtra::default() };
        extra.shards = inventory.clone();
        extra.prev_blocks.set_augmentable(
            &1,
            &KeyExtBlkRef {
                key: false,
                blk_ref: ExtBlkRef {
                    end_lt: 1000,
                    seq_no: 1,
                    root_hash: hash(1, 0x50),
                    file_hash: hash(1, 0x60),
                },
            },
        )?;
        state.write_custom(Some(&extra))?;
    }
    state.serialize()
}

/// A masterchain block at the frontier height recording `state`; with `inventory`, its
/// masterchain extra lists those shards. Returns the block and its full id.
fn tip(state: &chain_block::Cell, inventory: Option<&ShardHashes>) -> Result<(Block, FullId)> {
    let mut info = BlockInfo::default();
    info.set_shard(ShardIdent::masterchain());
    info.set_seq_no(FRONTIER)?;
    info.set_gen_utime(1000);
    let mut extra = BlockExtra::default();
    if let Some(inventory) = inventory {
        let mut custom = McBlockExtra::default();
        *custom.shards_mut() = inventory.clone();
        extra.write_custom(&custom)?;
    }
    let update = MerkleUpdate::create(state, state)?;
    let block = Block::with_params(GLOBAL_ID, info, Default::default(), update, extra)?;
    let boc = block.write_to_bytes()?;
    let id = FullId {
        workchain: -1,
        shard: i64::MIN,
        seqno: FRONTIER,
        root_hash: hex::encode(block.serialize()?.repr_hash().as_slice()),
        file_hash: sha256(&boc),
    };
    Ok((block, id))
}

fn held() -> Network {
    let zero = FullId {
        workchain: -1,
        shard: i64::MIN,
        seqno: 0,
        root_hash: "10".repeat(32),
        file_hash: "11".repeat(32),
    };
    Network { global_id: GLOBAL_ID, zero: zero.clone(), init: zero }
}

struct Frontier {
    held: Network,
    state: chain_block::Cell,
    tip: Block,
    frontier: FullId,
    inventory: ShardHashes,
    config: ConfigParams,
}

/// The honest frontier: inventory {wc0}, configuration {wc0 active, wc8 inactive}.
fn frontier() -> Result<Frontier> {
    frontier_with(GLOBAL_ID, FRONTIER, ShardIdent::masterchain())
}
fn frontier_with(global_id: i32, seq_no: u32, shard: ShardIdent) -> Result<Frontier> {
    let inventory = shards(&[(0, 1)])?;
    let config = config(&[(0, true, 1), (8, false, 8)])?;
    let state = mc_state(global_id, seq_no, shard, 0, Some(&config), &inventory)?;
    let (tip, frontier) = tip(&state, Some(&inventory))?;
    Ok(Frontier { held: held(), state, tip, frontier, inventory, config })
}

/// Same coordinates as the honest state, but its configuration adds active workchain 7.
fn substituted_state(f: &Frontier) -> Result<chain_block::Cell> {
    let config = config(&[(0, true, 1), (7, true, 7), (8, false, 8)])?;
    mc_state(GLOBAL_ID, FRONTIER, ShardIdent::masterchain(), 0, Some(&config), &f.inventory)
}

fn full_proof(state: &chain_block::Cell) -> Result<Vec<u8>> {
    MerkleProof::create(state, |_| true)?.write_to_bytes()
}

/// The proof shape the engine returns for `GetConfigAll` mode 0: only the path to the
/// configuration and ConfigParam 12 is visited, the shards and previous blocks stay pruned.
fn real_config_proof(state: &chain_block::Cell) -> Result<Vec<u8>> {
    let usage = UsageTree::with_root(state.clone());
    let visited = ShardStateUnsplit::construct_from_cell(usage.root_cell())?;
    visited
        .read_custom()?
        .context("fixture state has no masterchain extra")?
        .config
        .workchains()?
        .iterate_with_keys(|_: i32, _| Ok(true))?;
    MerkleProof::create_by_usage_tree(state, &usage)?.write_to_bytes()
}

fn config_answer(frontier: &FullId, config_proof: Vec<u8>) -> Result<tos::lite_server::ConfigInfo> {
    Ok(tos::lite_server::ConfigInfo::LiteServer_ConfigInfo(configinfo::ConfigInfo {
        mode: 0,
        id: frontier.native()?,
        state_proof: Vec::new(),
        config_proof,
    }))
}

fn shards_answer(frontier: &FullId, data: Vec<u8>) -> Result<tos::lite_server::AllShardsInfo> {
    Ok(tos::lite_server::AllShardsInfo::LiteServer_AllShardsInfo(allshardsinfo::AllShardsInfo {
        id: frontier.native()?,
        proof: Vec::new(),
        data,
    }))
}

fn inventory_bytes(inventory: &ShardHashes) -> Result<Vec<u8>> {
    chain_block::write_boc(&inventory.serialize()?)
}

fn verify_config(f: &Frontier, answer: &tos::lite_server::ConfigInfo) -> Result<ConfigParams> {
    verify_configuration(&f.held, &f.frontier, &frontier_state_hash(&f.tip)?, answer)
}

fn refused<T>(result: Result<T>, expected: &str) {
    match result {
        Ok(_) => panic!("accepted; expected refusal containing {expected:?}"),
        Err(error) => {
            let text = format!("{error:#}");
            assert!(text.contains(expected), "refused for another reason: {text}");
        }
    }
}

fn workchain_ids(config: &ConfigParams) -> Result<Vec<(i32, bool)>> {
    let mut ids = Vec::new();
    config.workchains()?.iterate_with_keys(|id: i32, descr| {
        ids.push((id, descr.active));
        Ok(true)
    })?;
    Ok(ids)
}

#[test]
fn configuration_of_the_frontier_state_is_accepted() -> Result<()> {
    let f = frontier()?;
    let config = verify_config(&f, &config_answer(&f.frontier, full_proof(&f.state)?)?)?;
    assert_eq!(workchain_ids(&config)?, workchain_ids(&f.config)?);
    assert_eq!(workchain_ids(&config)?, vec![(0, true), (8, false)]);
    Ok(())
}

#[test]
fn pruned_configuration_proof_of_the_frontier_state_is_accepted() -> Result<()> {
    let f = frontier()?;
    let pruned = real_config_proof(&f.state)?;
    assert!(pruned.len() < full_proof(&f.state)?.len(), "the fixture proof prunes nothing");
    let config = verify_config(&f, &config_answer(&f.frontier, pruned)?)?;
    assert_eq!(workchain_ids(&config)?, vec![(0, true), (8, false)]);
    Ok(())
}

#[test]
fn shard_inventory_of_the_frontier_block_is_accepted() -> Result<()> {
    let f = frontier()?;
    let answer = shards_answer(&f.frontier, inventory_bytes(&f.inventory)?)?;
    let accepted = verify_shard_inventory(&f.frontier, &f.tip, &answer)?;
    assert_eq!(accepted.serialize()?.repr_hash(), f.inventory.serialize()?.repr_hash());
    // A masterchain-only network records an empty inventory, which is accepted as such.
    let empty = ShardHashes::default();
    let state =
        mc_state(GLOBAL_ID, FRONTIER, ShardIdent::masterchain(), 0, Some(&f.config), &empty)?;
    let (tip, frontier) = tip(&state, Some(&empty))?;
    let answer = shards_answer(&frontier, inventory_bytes(&empty)?)?;
    assert!(verify_shard_inventory(&frontier, &tip, &answer)?.is_empty());
    Ok(())
}

#[test]
fn monitored_blocks_cover_shards_and_inactive_free_workchains() -> Result<()> {
    let f = frontier()?;
    let config = config(&[(0, true, 1), (7, true, 7), (8, false, 8)])?;
    let blocks = monitored_blocks(&f.frontier, &f.inventory, &config)?;
    let expected = vec![
        f.frontier.native()?,
        BlockIdExt::with_params(ShardIdent::with_workchain_id(0)?, 0, hash(1, 0x30), hash(1, 0x40)),
        BlockIdExt::with_params(ShardIdent::with_workchain_id(7)?, 0, hash(7, 0x10), hash(7, 0x20)),
    ];
    // wc0 is listed once (from the inventory), wc7 at its zero state, inactive wc8 not at all.
    assert_eq!(blocks, expected);
    Ok(())
}

/// The issue's acceptance control: a proof of another state with the same global id, height
/// and shard, whose configuration would add a workchain, is refused by the state binding.
#[test]
fn configuration_proof_of_another_state_is_refused() -> Result<()> {
    let f = frontier()?;
    let other = substituted_state(&f)?;
    assert_ne!(other.repr_hash(), f.state.repr_hash());
    refused(
        verify_config(&f, &config_answer(&f.frontier, full_proof(&other)?)?),
        "configuration proof is not a proof of the frontier block's state",
    );
    Ok(())
}

#[test]
fn pruned_proof_of_another_state_is_refused() -> Result<()> {
    let f = frontier()?;
    let other = substituted_state(&f)?;
    refused(
        verify_config(&f, &config_answer(&f.frontier, real_config_proof(&other)?)?),
        "configuration proof is not a proof of the frontier block's state",
    );
    Ok(())
}

#[test]
fn substituted_configuration_cannot_change_the_coverage() -> Result<()> {
    let f = frontier()?;
    let wc7 = ShardIdent::with_workchain_id(7)?;
    let other = substituted_state(&f)?;
    // Were the substituted configuration accepted, it would add workchain 7 to the coverage.
    let other_config = ShardStateUnsplit::construct_from_cell(other.clone())?
        .read_custom()?
        .context("substituted state has no masterchain extra")?
        .config;
    let forged = monitored_blocks(&f.frontier, &f.inventory, &other_config)?;
    assert!(forged.iter().any(|block| block.shard() == &wc7));
    let substituted = verify_config(&f, &config_answer(&f.frontier, real_config_proof(&other)?)?)
        .and_then(|config| monitored_blocks(&f.frontier, &f.inventory, &config));
    refused(substituted, "configuration proof is not a proof of the frontier block's state");
    let honest = verify_config(&f, &config_answer(&f.frontier, real_config_proof(&f.state)?)?)?;
    let blocks = monitored_blocks(&f.frontier, &f.inventory, &honest)?;
    assert!(blocks.iter().all(|block| block.shard() != &wc7), "{blocks:?}");
    Ok(())
}

#[test]
fn shard_inventory_of_another_block_is_refused() -> Result<()> {
    let f = frontier()?;
    for other in [shards(&[(0, 1), (5, 5)])?, shards(&[(0, 2)])?, ShardHashes::default()] {
        let answer = shards_answer(&f.frontier, inventory_bytes(&other)?)?;
        refused(
            verify_shard_inventory(&f.frontier, &f.tip, &answer),
            "native shard inventory differs from the frontier block's shard hashes",
        );
    }
    Ok(())
}

#[test]
fn configuration_answer_for_another_block_is_refused() -> Result<()> {
    let f = frontier()?;
    let sibling = FullId { root_hash: "77".repeat(32), ..f.frontier.clone() };
    refused(
        verify_config(&f, &config_answer(&sibling, full_proof(&f.state)?)?),
        "native configuration frontier mismatch",
    );
    Ok(())
}

#[test]
fn malformed_configuration_proofs_are_refused() -> Result<()> {
    let f = frontier()?;
    let oversized = usize::try_from(MANIFEST_LIMIT)? + 1;
    for (bytes, expected) in [
        (Vec::new(), "configuration state proof is empty"),
        (vec![0; oversized], "configuration state proof exceeds the byte limit"),
        // A plain state cell, not a Merkle proof.
        (chain_block::write_boc(&f.state)?, "configuration state proof is not a Merkle proof"),
        (vec![0xa5; 64], "configuration state proof"),
    ] {
        refused(verify_config(&f, &config_answer(&f.frontier, bytes)?), expected);
    }
    Ok(())
}

/// The tip records a state of another network, height or shard, so the hash binding holds
/// and only the identity check can refuse.
#[test]
fn configuration_state_of_another_network_height_or_shard_is_refused() -> Result<()> {
    for f in [
        frontier_with(GLOBAL_ID + 1, FRONTIER, ShardIdent::masterchain())?,
        frontier_with(GLOBAL_ID, FRONTIER - 1, ShardIdent::masterchain())?,
        frontier_with(GLOBAL_ID, FRONTIER, ShardIdent::with_workchain_id(0)?)?,
    ] {
        refused(
            verify_config(&f, &config_answer(&f.frontier, full_proof(&f.state)?)?),
            "native configuration state identity mismatch",
        );
    }
    Ok(())
}

#[test]
fn configuration_state_without_masterchain_extra_or_workchains_is_refused() -> Result<()> {
    let f = frontier()?;
    let bare = mc_state(GLOBAL_ID, FRONTIER, ShardIdent::masterchain(), 0, None, &f.inventory)?;
    let (tip, frontier) = tip(&bare, Some(&f.inventory))?;
    let g = Frontier { state: bare, tip, frontier, ..f };
    refused(
        verify_config(&g, &config_answer(&g.frontier, full_proof(&g.state)?)?),
        "masterchain state lacks configuration",
    );
    let mut no_workchains = ConfigParams::default();
    let address = ConfigParam0 { config_addr: chain_block::AccountId::ZERO_ID };
    no_workchains.set_config(ConfigParamEnum::ConfigParam0(address))?;
    refused(
        monitored_blocks(&g.frontier, &g.inventory, &no_workchains),
        "Workchains not found in config",
    );
    Ok(())
}

#[test]
fn shard_inventory_answer_for_another_block_is_refused() -> Result<()> {
    let f = frontier()?;
    let sibling = FullId { root_hash: "77".repeat(32), ..f.frontier.clone() };
    let answer = shards_answer(&sibling, inventory_bytes(&f.inventory)?)?;
    refused(
        verify_shard_inventory(&f.frontier, &f.tip, &answer),
        "native shard inventory frontier mismatch",
    );
    Ok(())
}

#[test]
fn malformed_shard_inventory_is_refused() -> Result<()> {
    let f = frontier()?;
    let oversized = usize::try_from(MANIFEST_LIMIT)? + 1;
    for (bytes, expected) in [
        (Vec::new(), "native shard inventory is empty"),
        (vec![0; oversized], "native shard inventory exceeds the byte limit"),
    ] {
        refused(
            verify_shard_inventory(&f.frontier, &f.tip, &shards_answer(&f.frontier, bytes)?),
            expected,
        );
    }
    let garbage = shards_answer(&f.frontier, vec![0xa5; 64])?;
    assert!(verify_shard_inventory(&f.frontier, &f.tip, &garbage).is_err());
    Ok(())
}

#[test]
fn frontier_block_without_masterchain_extra_is_refused() -> Result<()> {
    let f = frontier()?;
    let (tip, frontier) = tip(&f.state, None)?;
    let answer = shards_answer(&frontier, inventory_bytes(&f.inventory)?)?;
    refused(
        verify_shard_inventory(&frontier, &tip, &answer),
        "frontier block has no masterchain extra",
    );
    Ok(())
}

#[test]
fn monitored_block_limit_is_enforced() -> Result<()> {
    let f = frontier()?;
    let empty = ShardHashes::default();
    // The frontier plus 1023 zero states fills the 1024 limit; one more is refused.
    let entries = |count: i32| (1..=count).map(|id| (id, true, 1)).collect::<Vec<_>>();
    assert_eq!(monitored_blocks(&f.frontier, &empty, &config(&entries(1023))?)?.len(), 1024);
    refused(
        monitored_blocks(&f.frontier, &empty, &config(&entries(1024))?),
        "native monitored workchain count limit",
    );
    let no_workchains = config(&[])?;
    let inventory = |count: i32| shards(&(1..=count).map(|id| (id, 1)).collect::<Vec<_>>());
    assert_eq!(monitored_blocks(&f.frontier, &inventory(1023)?, &no_workchains)?.len(), 1024);
    refused(
        monitored_blocks(&f.frontier, &inventory(1024)?, &no_workchains),
        "native monitored shard count limit",
    );
    Ok(())
}
