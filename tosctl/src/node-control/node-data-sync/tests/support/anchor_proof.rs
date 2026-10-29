//! Pure checks of the native ancestry proof. Each refusal case changes exactly one property
//! of an otherwise valid answer, so the check named in its message is the one that refuses.
use super::*;
use chain_block::{
    BlockIdExt, BlockInfo, ExtBlkRef, HashmapAugType, KeyExtBlkRef, McStateExtra, MerkleUpdate,
    Serializable, ShardIdent, UsageTree,
};
use tos::lite_server::{
    BlockLink, PartialBlockProof,
    blocklink::{BlockLinkBack, BlockLinkForward},
    partialblockproof,
};

const GLOBAL_ID: i32 = 3;
const FRONTIER: u32 = 10;
const INIT: u32 = 5;
const FILLER: u32 = 7;

/// A masterchain block at `seqno` whose header differs by `salt`; its cell and full id.
fn block(seqno: u32, salt: u32, state: Option<&chain_block::Cell>) -> Result<(Block, FullId)> {
    let mut info = BlockInfo::default();
    info.set_shard(ShardIdent::masterchain());
    info.set_seq_no(seqno)?;
    info.set_gen_utime(1000 + salt);
    let update = match state {
        Some(state) => MerkleUpdate::create(state, state)?,
        None => MerkleUpdate::default(),
    };
    let block =
        Block::with_params(GLOBAL_ID, info, Default::default(), update, Default::default())?;
    let boc = block.write_to_bytes()?;
    let id = FullId {
        workchain: -1,
        shard: i64::MIN,
        seqno,
        root_hash: hex::encode(block.serialize()?.repr_hash().as_slice()),
        file_hash: sha256(&boc),
    };
    Ok((block, id))
}

fn zero_id() -> FullId {
    FullId {
        workchain: -1,
        shard: i64::MIN,
        seqno: 0,
        root_hash: "10".repeat(32),
        file_hash: "11".repeat(32),
    }
}

/// Masterchain state at `seq_no` whose previous-block dictionary lists `entries`.
fn state(global_id: i32, seq_no: u32, salt: u32, entries: &[FullId]) -> Result<chain_block::Cell> {
    let mut extra = McStateExtra::default();
    for entry in entries {
        let native = entry.native()?;
        extra.prev_blocks.set_augmentable(
            &entry.seqno,
            &KeyExtBlkRef {
                key: entry.seqno == 0,
                blk_ref: ExtBlkRef {
                    end_lt: u64::from(entry.seqno) * 1000,
                    seq_no: entry.seqno,
                    root_hash: native.root_hash().clone(),
                    file_hash: native.file_hash().clone(),
                },
            },
        )?;
    }
    let mut state = ShardStateUnsplit::with_ident(ShardIdent::masterchain());
    state.set_global_id(global_id);
    state.set_seq_no(seq_no);
    state.set_gen_time(2000 + salt);
    state.write_custom(Some(&extra))?;
    state.serialize()
}

struct Chain {
    held: Network,
    init_block: Block,
    filler: FullId,
    state: chain_block::Cell,
    tip: Block,
    frontier: FullId,
}

/// A consistent chain: zero state, init block 5, filler block 7 and frontier block 10 whose
/// state update records the masterchain state listing all three.
fn chain() -> Result<Chain> {
    chain_with(GLOBAL_ID, FRONTIER)
}
fn chain_with(state_global_id: i32, state_seq_no: u32) -> Result<Chain> {
    let zero = zero_id();
    let (init_block, init) = block(INIT, 0, None)?;
    let (_, filler) = block(FILLER, 0, None)?;
    let state =
        state(state_global_id, state_seq_no, 0, &[zero.clone(), init.clone(), filler.clone()])?;
    let (tip, frontier) = block(FRONTIER, 0, Some(&state))?;
    Ok(Chain {
        held: Network { global_id: GLOBAL_ID, zero, init },
        init_block,
        filler,
        state,
        tip,
        frontier,
    })
}

fn proof_bytes(root: &chain_block::Cell) -> Result<Vec<u8>> {
    MerkleProof::create(root, |_| true)?.write_to_bytes()
}

/// The answer an honest engine gives for `anchor`, whose header (if any) is `destination`.
fn answer(chain: &Chain, anchor: &FullId, destination: Option<&Block>) -> Result<BlockLinkBack> {
    Ok(BlockLinkBack {
        to_key_block: (anchor.seqno == 0).into(),
        from: chain.frontier.native()?,
        to: anchor.native()?,
        dest_proof: match destination {
            Some(header) => proof_bytes(&header.serialize()?)?,
            None => Vec::new(),
        },
        proof: proof_bytes(&chain.tip.serialize()?)?,
        state_proof: proof_bytes(&chain.state)?,
    })
}
fn wrap(chain: &Chain, anchor: &FullId, steps: Vec<BlockLink>) -> Result<PartialBlockProof> {
    Ok(PartialBlockProof::LiteServer_PartialBlockProof(partialblockproof::PartialBlockProof {
        complete: true.into(),
        from: chain.frontier.native()?,
        to: anchor.native()?,
        steps,
    }))
}
fn single(chain: &Chain, anchor: &FullId, link: BlockLinkBack) -> Result<PartialBlockProof> {
    wrap(chain, anchor, vec![BlockLink::LiteServer_BlockLinkBack(link)])
}
fn verify(chain: &Chain, anchor: &FullId, response: &PartialBlockProof) -> Result<()> {
    verify_anchor_proof(
        &chain.held,
        &chain.frontier,
        &frontier_state_hash(&chain.tip)?,
        anchor,
        response,
    )
}
fn refused(result: Result<()>, expected: &str) {
    match result {
        Ok(()) => panic!("accepted; expected refusal containing {expected:?}"),
        Err(error) => {
            let text = format!("{error:#}");
            assert!(text.contains(expected), "refused for another reason: {text}");
        }
    }
}

#[test]
fn zero_state_anchor_is_proven_without_a_header_proof() -> Result<()> {
    let mut chain = chain()?;
    chain.held.init = chain.held.zero.clone();
    let zero = chain.held.zero.clone();
    verify(&chain, &zero, &single(&chain, &zero, answer(&chain, &zero, None)?)?)
}

#[test]
fn init_block_anchor_is_proven() -> Result<()> {
    let chain = chain()?;
    let init = chain.held.init.clone();
    verify(&chain, &init, &single(&chain, &init, answer(&chain, &init, Some(&chain.init_block))?)?)
}

#[test]
fn frontier_state_hash_is_the_state_the_tip_records() -> Result<()> {
    let chain = chain()?;
    assert_eq!(frontier_state_hash(&chain.tip)?, chain.state.repr_hash());
    Ok(())
}

#[test]
fn frontier_and_later_anchors_need_no_proof_or_are_refused() -> Result<()> {
    let chain = chain()?;
    assert!(!needs_proof(&chain.frontier, &chain.frontier)?);
    assert!(needs_proof(&chain.frontier, &chain.held.init)?);
    let (_, ahead) = block(FRONTIER + 1, 0, None)?;
    refused(needs_proof(&chain.frontier, &ahead).map(drop), "is ahead of generation frontier");
    let (_, sibling) = block(FRONTIER, 9, None)?;
    refused(
        needs_proof(&chain.frontier, &sibling).map(drop),
        "differs from the generation frontier",
    );
    // The verifier itself refuses to be used for the frontier.
    let frontier = chain.frontier.clone();
    refused(
        verify(&chain, &frontier, &single(&chain, &frontier, answer(&chain, &frontier, None)?)?),
        "needs no ancestry proof",
    );
    Ok(())
}

#[test]
fn anchor_set_collapses_an_init_block_equal_to_the_zero_state() -> Result<()> {
    let mut chain = chain()?;
    let fork = chain.filler.clone();
    assert_eq!(anchor_set(&chain.held, std::slice::from_ref(&fork))?.len(), 3);
    chain.held.init = chain.held.zero.clone();
    assert_eq!(anchor_set(&chain.held, &[])?, BTreeSet::from([chain.held.zero.clone()]));
    Ok(())
}

/// A same-height init block from another history, with a header proof that matches it, so
/// only the previous-block membership can refuse it.
#[test]
fn conflicting_init_root_is_refused_by_membership() -> Result<()> {
    let mut chain = chain()?;
    let (other, conflicting) = block(INIT, 1, None)?;
    assert_ne!(conflicting.root_hash, chain.held.init.root_hash);
    chain.held.init = conflicting.clone();
    let response = single(&chain, &conflicting, answer(&chain, &conflicting, Some(&other))?)?;
    refused(verify(&chain, &conflicting, &response), "is not an earlier block of the frontier");
    Ok(())
}

#[test]
fn conflicting_init_file_hash_is_refused_by_membership() -> Result<()> {
    let mut chain = chain()?;
    let mut conflicting = chain.held.init.clone();
    conflicting.file_hash = "77".repeat(32);
    chain.held.init = conflicting.clone();
    let response =
        single(&chain, &conflicting, answer(&chain, &conflicting, Some(&chain.init_block))?)?;
    refused(verify(&chain, &conflicting, &response), "is not an earlier block of the frontier");
    Ok(())
}

#[test]
fn different_zero_state_is_refused_by_membership() -> Result<()> {
    for (root, file) in [("10", "99"), ("98", "11")] {
        let mut chain = chain()?;
        let zero = FullId { root_hash: root.repeat(32), file_hash: file.repeat(32), ..zero_id() };
        chain.held.zero = zero.clone();
        chain.held.init = zero.clone();
        let response = single(&chain, &zero, answer(&chain, &zero, None)?)?;
        refused(verify(&chain, &zero, &response), "is not an earlier block of the frontier");
    }
    Ok(())
}

/// A proof of another state that lists the same anchors: only the binding to the state the
/// frontier block records can refuse it.
#[test]
fn proof_of_another_state_is_refused() -> Result<()> {
    let chain = chain()?;
    let init = chain.held.init.clone();
    let other = state(GLOBAL_ID, FRONTIER, 1, &[zero_id(), init.clone(), chain.filler.clone()])?;
    let mut link = answer(&chain, &init, Some(&chain.init_block))?;
    link.state_proof = proof_bytes(&other)?;
    refused(
        verify(&chain, &init, &single(&chain, &init, link)?),
        "not a proof of the frontier block's state",
    );
    Ok(())
}

#[test]
fn state_of_another_network_or_height_is_refused() -> Result<()> {
    for chain in [chain_with(GLOBAL_ID + 1, FRONTIER)?, chain_with(GLOBAL_ID, FRONTIER - 1)?] {
        let init = chain.held.init.clone();
        let response = single(&chain, &init, answer(&chain, &init, Some(&chain.init_block))?)?;
        refused(verify(&chain, &init, &response), "another network or height");
    }
    Ok(())
}

#[test]
fn incomplete_answers_and_other_endpoints_are_refused() -> Result<()> {
    let chain = chain()?;
    let init = chain.held.init.clone();
    let good = answer(&chain, &init, Some(&chain.init_block))?;
    let edited = |edit: &dyn Fn(&mut partialblockproof::PartialBlockProof)| -> Result<_> {
        let mut inner = single(&chain, &init, good.clone())?.only();
        edit(&mut inner);
        Ok(PartialBlockProof::LiteServer_PartialBlockProof(inner))
    };
    let filler = chain.filler.native()?;
    let zero = chain.held.zero.native()?;
    refused(verify(&chain, &init, &edited(&|p| p.complete = false.into())?), "incomplete");
    refused(
        verify(&chain, &init, &edited(&|p| p.to = filler.clone())?),
        "ancestry proof has other endpoints",
    );
    refused(
        verify(&chain, &init, &edited(&|p| p.from = zero.clone())?),
        "ancestry proof has other endpoints",
    );
    let mut reversed = good.clone();
    reversed.from = init.native()?;
    reversed.to = chain.frontier.native()?;
    refused(
        verify(&chain, &init, &single(&chain, &init, reversed)?),
        "ancestry proof link has other endpoints",
    );
    let mut wrong_link = good.clone();
    wrong_link.to = chain.filler.native()?;
    refused(
        verify(&chain, &init, &single(&chain, &init, wrong_link)?),
        "ancestry proof link has other endpoints",
    );
    let forward = BlockLink::LiteServer_BlockLinkForward(BlockLinkForward {
        to_key_block: false.into(),
        from: chain.frontier.native()?,
        to: init.native()?,
        dest_proof: good.dest_proof.clone(),
        config_proof: good.state_proof.clone(),
        signatures: Default::default(),
    });
    refused(verify(&chain, &init, &wrap(&chain, &init, vec![forward])?), "not a backward link");
    Ok(())
}

#[test]
fn missing_or_extra_links_are_refused() -> Result<()> {
    let chain = chain()?;
    let init = chain.held.init.clone();
    let good = BlockLink::LiteServer_BlockLinkBack(answer(&chain, &init, Some(&chain.init_block))?);
    refused(verify(&chain, &init, &wrap(&chain, &init, vec![])?), "exactly one link, found 0");
    refused(
        verify(&chain, &init, &wrap(&chain, &init, vec![good.clone(), good])?),
        "exactly one link, found 2",
    );
    Ok(())
}

/// The engine proves only the dictionary path it visited. A proof that visited another
/// entry is valid for that entry and must not prove the anchor.
#[test]
fn pruned_dictionary_path_is_refused() -> Result<()> {
    let chain = chain()?;
    let usage = UsageTree::with_root(chain.state.clone());
    let visited = ShardStateUnsplit::construct_from_cell(usage.root_cell())?;
    visited
        .read_custom()?
        .context("fixture state has no masterchain extra")?
        .prev_blocks
        .check_block(&chain.filler.native()?)?;
    let pruned = MerkleProof::create_by_usage_tree(&chain.state, &usage)?.write_to_bytes()?;
    let (filler_block, _) = block(FILLER, 0, None)?;
    let mut filler = answer(&chain, &chain.filler, Some(&filler_block))?;
    filler.state_proof = pruned.clone();
    // Positive control: the same proof proves the entry it visited.
    verify(&chain, &chain.filler, &single(&chain, &chain.filler, filler)?)?;
    let init = chain.held.init.clone();
    let mut link = answer(&chain, &init, Some(&chain.init_block))?;
    link.state_proof = pruned;
    refused(
        verify(&chain, &init, &single(&chain, &init, link)?),
        "is not an earlier block of the frontier",
    );
    Ok(())
}

#[test]
fn malformed_state_proofs_are_refused() -> Result<()> {
    let chain = chain()?;
    let init = chain.held.init.clone();
    let good = answer(&chain, &init, Some(&chain.init_block))?;
    let oversized = usize::try_from(MANIFEST_LIMIT)? + 1;
    for (bytes, expected) in [
        (Vec::new(), "frontier state proof is empty"),
        (vec![0xa5; 64], "frontier state proof"),
        (vec![0; oversized], "frontier state proof exceeds the byte limit"),
        // A plain cell, not a Merkle proof.
        (chain_block::write_boc(&chain.state)?, "frontier state proof is not a Merkle proof"),
    ] {
        let mut link = good.clone();
        link.state_proof = bytes;
        refused(verify(&chain, &init, &single(&chain, &init, link)?), expected);
    }
    let mut header = good.clone();
    header.proof = proof_bytes(&chain.init_block.serialize()?)?;
    refused(
        verify(&chain, &init, &single(&chain, &init, header)?),
        "frontier header proof belongs to another block",
    );
    Ok(())
}

#[test]
fn destination_header_proofs_must_match_the_anchor() -> Result<()> {
    let chain = chain()?;
    let init = chain.held.init.clone();
    let (other, _) = block(INIT, 1, None)?;
    let mut wrong = answer(&chain, &init, Some(&other))?;
    refused(
        verify(&chain, &init, &single(&chain, &init, wrong.clone())?),
        "anchor header proof belongs to another block",
    );
    wrong.dest_proof = Vec::new();
    refused(verify(&chain, &init, &single(&chain, &init, wrong)?), "anchor header proof is empty");
    let zero = chain.held.zero.clone();
    let unexpected = answer(&chain, &zero, Some(&chain.init_block))?;
    refused(
        verify(&chain, &zero, &single(&chain, &zero, unexpected)?),
        "zero-state anchor has an unexpected header proof",
    );
    Ok(())
}

/// The engine cannot build a backward link to an anchor whose proof link it no longer holds.
/// That refusal names the anchor and the requirement; other failures keep their own text.
#[test]
fn unretained_anchor_proof_is_a_named_refusal() -> Result<()> {
    let chain = chain()?;
    let init = chain.held.init.clone();
    let engine = |id: &FullId| {
        anyhow::anyhow!(
            "native GetBlockProof: native state read failed (-400): cannot load proof link for {} : \
             not in db",
            describe(id)
        )
    };
    let text = format!("{:#}", anchor_read_refusal(&init, engine(&init)));
    assert!(text.contains("anchor proof not retained"), "{text}");
    assert!(text.contains(&describe(&init)), "{text}");
    // The frontier's own proof link, the zero state and unrelated errors are not this refusal.
    for (anchor, error) in [
        (&init, engine(&chain.frontier)),
        (&chain.held.zero, engine(&chain.held.zero)),
        (&init, anyhow::anyhow!("native GetBlockProof: timeout")),
    ] {
        let text = format!("{:#}", anchor_read_refusal(anchor, error));
        assert!(!text.contains("anchor proof not retained"), "{text}");
    }
    Ok(())
}

#[test]
fn engine_spelling_matches_the_native_block_id() -> Result<()> {
    let chain = chain()?;
    let native: BlockIdExt = chain.held.init.native()?;
    assert_eq!(
        describe(&chain.held.init),
        format!(
            "(-1,8000000000000000,{}):{}:{}",
            native.seq_no(),
            hex::encode_upper(native.root_hash().as_slice()),
            hex::encode_upper(native.file_hash().as_slice())
        )
    );
    Ok(())
}

#[test]
fn diagnostics_are_bounded_at_a_character_boundary() {
    let short = "GetBlockProof failed";
    assert_eq!(bounded_diagnostic(short), short);
    let long = "\u{00e9}".repeat(DIAGNOSTIC_LIMIT);
    let bounded = bounded_diagnostic(&long);
    assert!(bounded.len() <= DIAGNOSTIC_LIMIT + 3, "{}", bounded.len());
    assert!(bounded.ends_with("..."));
    assert!(bounded.trim_end_matches("...").chars().all(|c| c == '\u{00e9}'));
}
