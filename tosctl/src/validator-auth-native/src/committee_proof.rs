use crate::{
    cells,
    committee::{ChainContext, NativeCommittee},
    native,
    registry::StateReadBudget,
};
use chain_block::{Deserializable, MerkleProof, Serializable, UsageTree};
use tos_validator_auth::{
    codec::Error,
    crypto::{digest, object_id},
    transfer::ObjectReader,
    types::{Anchor, ObjectRef, Proofref},
};

pub fn verify_committee_proof<F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>>(
    proof: &Proofref,
    anchor: &Anchor,
    chain: &ChainContext,
    workchain: i32,
    shard: u64,
    catchain: u32,
    reader: &mut ObjectReader<F>,
) -> Result<NativeCommittee, Error> {
    if proof.anchor != *anchor {
        return Err(Error("proof-anchor"));
    }
    if proof.kind != 5 {
        return Err(Error("proof-kind"));
    }
    let raw = reader.resolve(&proof.proof, 5)?;
    if digest("proof", &raw)? != proof.proof_hash {
        return Err(Error("proof-hash"));
    }
    let cell = cells::read_boc(&raw, true)?;
    let merkle = native(MerkleProof::construct_from_full_cell(cell.clone()))?;
    let virtualized = merkle.proof.virtualize(1);
    let used = UsageTree::with_root(virtualized.clone());
    let committee = NativeCommittee::derive(
        used.root_cell(),
        anchor,
        chain,
        workchain,
        shard,
        catchain,
        StateReadBudget::default(),
    )?;
    if proof.object_id != object_id("committee", committee.snapshot().committee())? {
        return Err(Error("proof-object"));
    }
    let minimal = native(MerkleProof::create_by_usage_tree(&virtualized, &used))?;
    if native(minimal.serialize())?.repr_hash() != cell.repr_hash() {
        return Err(Error("proof-unrelated-values"));
    }
    Ok(committee)
}
