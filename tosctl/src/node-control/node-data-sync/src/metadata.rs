use crate::model::{Manifest, sha256};
use anyhow::{Result, ensure};
use chain_block::{Block, Deserializable, ShardStateUnsplit, read_single_root_boc};

/// Bind public metadata bytes to the held network and to the coherent manifest frontier.
pub fn validate(manifest: &Manifest, zero: &[u8], tip: &[u8]) -> Result<()> {
    manifest.validate()?;
    ensure!(
        sha256(zero) == manifest.network.zero.file_hash,
        "zero-state file hash differs from held anchor"
    );
    let zero_root = read_single_root_boc(zero)?;
    ensure!(
        hex::encode(zero_root.repr_hash().as_slice()) == manifest.network.zero.root_hash,
        "zero-state root hash differs from held anchor"
    );
    let zero_state = ShardStateUnsplit::construct_from_cell(zero_root)?;
    network_id(zero_state.global_id(), manifest.network.global_id)?;
    ensure!(
        zero_state.seq_no() == 0 && zero_state.shard() == manifest.network.zero.native()?.shard(),
        "zero-state network identity mismatch"
    );
    ensure!(sha256(tip) == manifest.frontier.file_hash, "tip block file hash mismatch");
    let tip_root = read_single_root_boc(tip)?;
    ensure!(
        hex::encode(tip_root.repr_hash().as_slice()) == manifest.frontier.root_hash,
        "tip block root hash mismatch"
    );
    let block = Block::construct_from_cell(tip_root)?;
    let info = block.read_info()?;
    network_id(block.global_id(), manifest.network.global_id)?;
    ensure!(
        info.seq_no() == manifest.frontier.seqno
            && info.shard() == manifest.frontier.native()?.shard()
            && u64::from(info.gen_utime()) == manifest.frontier_utime,
        "tip block does not match the manifest network, frontier or timestamp"
    );
    Ok(())
}

fn network_id(actual: i32, expected: i32) -> Result<()> {
    ensure!(actual == expected, "public metadata global id differs from held network");
    Ok(())
}
