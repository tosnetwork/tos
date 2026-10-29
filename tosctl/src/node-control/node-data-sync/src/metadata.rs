use crate::model::{Manifest, sha256};
use anyhow::{Result, ensure};
use chain_block::{Block, Deserializable, read_single_root_boc};

/// Bind public tip metadata to the held network and to the coherent manifest frontier.
/// The held zero state and init block are bound by the manifest's network identity and by
/// native ancestry proofs at creation and restore; no zero-state bytes are published.
pub fn validate(manifest: &Manifest, tip: &[u8]) -> Result<()> {
    manifest.validate()?;
    ensure!(sha256(tip) == manifest.frontier.file_hash, "tip block file hash mismatch");
    let tip_root = read_single_root_boc(tip)?;
    ensure!(
        hex::encode(tip_root.repr_hash().as_slice()) == manifest.frontier.root_hash,
        "tip block root hash mismatch"
    );
    let block = Block::construct_from_cell(tip_root)?;
    let info = block.read_info()?;
    ensure!(
        block.global_id() == manifest.network.global_id,
        "public metadata global id differs from held network"
    );
    ensure!(
        info.seq_no() == manifest.frontier.seqno
            && info.shard() == manifest.frontier.native()?.shard()
            && u64::from(info.gen_utime()) == manifest.frontier_utime,
        "tip block does not match the manifest network, frontier or timestamp"
    );
    Ok(())
}
