use super::*;
use crate::{client_adnl::ToFromTL, operator_requests::*};
use tl_api::{AnyBoxedSerialize, IntoBoxed, deserialize_boxed, serialize_boxed};

fn id(n: u16) -> UInt256 {
    let mut bytes = [0; 32];
    bytes[..2].copy_from_slice(&n.to_be_bytes());
    UInt256::from(bytes)
}
fn block() -> BlockIdExt {
    BlockIdExt::with_params(
        chain_block::ShardIdent::masterchain(),
        0,
        UInt256::default(),
        UInt256::default(),
    )
}
fn elector() -> wire::electorstate::ElectorState {
    wire::electorstate::ElectorState { block: block(), ..Default::default() }
}
fn meta() -> wire::configproposalmeta::ConfigProposalMeta {
    wire::configproposalmeta::ConfigProposalMeta { hash: id(1), ..Default::default() }
}
fn error_contains<T>(result: anyhow::Result<T>, expected: &str) -> anyhow::Result<()> {
    let error = result.err().context("expected refusal")?;
    ensure!(
        format!("{error:#}").contains(expected),
        "wrong refusal: {error:#}; expected {expected}"
    );
    Ok(())
}

#[test]
fn coins_canonical_and_boundaries() -> anyhow::Result<()> {
    assert_eq!(CoinsAmount::from_bytes(&[])?.as_u128(), 0);
    assert_eq!(CoinsAmount::from_bytes(&[1])?.as_u128(), 1);
    let max =
        1u128.checked_shl(120).context("test shift")?.checked_sub(1).context("test subtraction")?;
    assert_eq!(CoinsAmount::from_bytes(&[255; 15])?.as_u128(), max);
    for bytes in [vec![0], vec![0, 1]] {
        error_contains(CoinsAmount::from_bytes(&bytes), "leading zero")?;
    }
    let mut too_large = vec![0; 16];
    too_large[0] = 1;
    error_contains(CoinsAmount::from_bytes(&too_large), "15 bytes")?;
    Ok(())
}
#[test]
fn coins_u64_checked() -> anyhow::Result<()> {
    assert_eq!(CoinsAmount::from_bytes(&u64::MAX.to_be_bytes())?.checked_u64("stake")?, u64::MAX);
    error_contains(
        CoinsAmount::from_bytes(&[1, 0, 0, 0, 0, 0, 0, 0, 0])?.checked_u64("stake"),
        "stake exceeds u64",
    )?;
    Ok(())
}
#[test]
fn unsigned_fields_and_frozen_weights() -> anyhow::Result<()> {
    let mut value = elector();
    value.elect_at = i32::MIN;
    value.elect_close = -1;
    value.participants.push(wire::electionparticipant::ElectionParticipant {
        max_factor: -1,
        algorithm: 2,
        ..Default::default()
    });
    let mut p = wire::pastelection::PastElection {
        election_id: -1,
        unfreeze_at: i32::MIN,
        stake_held: -1,
        ..Default::default()
    };
    for (n, weight) in [(1, i64::MIN), (2, -1)] {
        p.frozen.push(wire::frozenstake::FrozenStake {
            id: id(n),
            owner: id(9),
            weight,
            ..Default::default()
        });
    }
    value.past_elections.push(p);
    let bytes = serialize_boxed(&value.clone().into_boxed())?;
    let value = GetElectorStateRqRs::deserialize(deserialize_boxed(bytes)?)?;
    assert_eq!(value.elect_at, 1u32 << 31);
    assert_eq!(value.elect_close, u32::MAX);
    assert_eq!(value.participants[0].max_factor, u32::MAX);
    assert_eq!(value.participants[0].algorithm, 2);
    assert_eq!(value.past_elections[0].election_id, u32::MAX);
    assert_eq!(value.past_elections[0].unfreeze_at, 1u32 << 31);
    assert_eq!(value.past_elections[0].stake_held, u32::MAX);
    assert_eq!(value.past_elections[0].frozen[0].weight, 1u64 << 63);
    assert_eq!(value.past_elections[0].frozen[1].weight, u64::MAX);
    assert_ne!(value.past_elections[0].frozen[0].id, value.past_elections[0].frozen[0].owner);
    Ok(())
}
#[test]
fn wallet_requests_are_validated_before_serialization() -> anyhow::Result<()> {
    for count in [0, 16] {
        let request = ElectorStateRequest {
            wallets: (0..count).map(|i| *id(i).as_slice()).collect(),
            ..Default::default()
        };
        let serialized = GetElectorStateRqRs::serialize(&request)?;
        let request_wire = serialized
            .downcast::<tl_api::tos::rpc::engine::validator::GetElectorState>()
            .map_err(|_| anyhow::anyhow!("wrong request type"))?;
        assert_eq!(request_wire.wallets.len(), usize::from(count));
    }
    let too_many = ElectorStateRequest {
        wallets: (0..17).map(|i| *id(i).as_slice()).collect(),
        ..Default::default()
    };
    error_contains(GetElectorStateRqRs::serialize(&too_many), "more than 16")?;
    let duplicate = ElectorStateRequest { wallets: vec![[1; 32], [1; 32]], ..Default::default() };
    error_contains(GetElectorStateRqRs::serialize(&duplicate), "duplicate")?;
    Ok(())
}
#[test]
fn returned_wallets_match_count_order_and_address() -> anyhow::Result<()> {
    let request = ElectorStateRequest {
        wallets: vec![*id(1).as_slice(), *id(2).as_slice()],
        ..Default::default()
    };
    let mut value = elector();
    for n in [1, 2] {
        value.returned.push(wire::returnedstake::ReturnedStake { wallet: id(n), amount: vec![5] });
    }
    let state = ElectorState::try_from(value)?;
    state.validate_request(&request)?;
    let mut bad = state.clone();
    bad.returned.pop();
    error_contains(bad.validate_request(&request), "count")?;
    let mut bad = state.clone();
    bad.returned.push(state.returned[0].clone());
    error_contains(bad.validate_request(&request), "count")?;
    let mut bad = state.clone();
    bad.returned.reverse();
    error_contains(bad.validate_request(&request), "order or address")?;
    let mut bad = state.clone();
    bad.returned[0].wallet = [9; 32];
    error_contains(bad.validate_request(&request), "order or address")?;
    assert_eq!(state.returned[0].amount.as_u128(), 5);
    Ok(())
}
#[test]
fn request_block_identity_checks_all_components() -> anyhow::Result<()> {
    let state = ElectorState::try_from(elector())?;
    let mut request =
        ElectorStateRequest { block: Some(state.block.clone()), ..Default::default() };
    state.validate_request(&request)?;
    for bad in [
        BlockIdExt::with_params(
            state.block.shard().clone(),
            state.block.seq_no(),
            id(10),
            state.block.file_hash().clone(),
        ),
        BlockIdExt::with_params(
            state.block.shard().clone(),
            state.block.seq_no(),
            state.block.root_hash().clone(),
            id(10),
        ),
        BlockIdExt::with_params(
            state.block.shard().clone(),
            state.block.seq_no().checked_add(1).context("test seqno")?,
            state.block.root_hash().clone(),
            state.block.file_hash().clone(),
        ),
    ] {
        request.block = Some(bad);
        error_contains(state.validate_request(&request), "block identity")?;
    }
    let base = chain_block::ShardIdent::with_tagged_prefix(0, 1u64 << 63)?;
    request.block = Some(BlockIdExt::with_params(base, 0, id(1), id(2)));
    error_contains(request.validate(), "not masterchain")?;
    let mut bad_state = state;
    bad_state.block = request.block.context("test block")?;
    error_contains(bad_state.validate_request(&ElectorStateRequest::default()), "not masterchain")?;
    Ok(())
}
#[test]
fn metadata_preserves_optional_hash_and_checks_ranges() -> anyhow::Result<()> {
    let mut value = meta();
    value.expires = -1;
    value.param_id = -1;
    value.weight_remaining = i64::MIN;
    value.voters = vec![0, 65535];
    value.rounds_remaining = 255;
    value.wins = 255;
    value.losses = 255;
    let converted = ConfigProposalMeta::try_from(value.clone())?;
    assert_eq!(converted.expires, u32::MAX);
    assert_eq!(converted.param_id, -1);
    assert_eq!(converted.weight_remaining, i64::MIN);
    assert_eq!(converted.voters, vec![0, 65535]);
    assert_eq!(converted.rounds_remaining, 255);
    assert_eq!(converted.wins, 255);
    assert_eq!(converted.losses, 255);
    assert_eq!(converted.param_hash, None);
    value.param_hash = Some(UInt256::from([255; 32]));
    assert_eq!(ConfigProposalMeta::try_from(value.clone())?.param_hash, Some([255; 32]));
    for n in [256, -1] {
        let mut bad = value.clone();
        bad.rounds_remaining = n;
        error_contains(ConfigProposalMeta::try_from(bad), "rounds exceed")?;
        let mut bad = value.clone();
        bad.wins = n;
        error_contains(ConfigProposalMeta::try_from(bad), "wins exceed")?;
        let mut bad = value.clone();
        bad.losses = n;
        error_contains(ConfigProposalMeta::try_from(bad), "losses exceed")?;
    }
    for voters in [vec![65536], vec![-1]] {
        let mut bad = value.clone();
        bad.voters = voters;
        error_contains(ConfigProposalMeta::try_from(bad), "voter exceeds")?;
    }
    for voters in [vec![1, 1], vec![2, 1]] {
        let mut bad = value.clone();
        bad.voters = voters;
        error_contains(ConfigProposalMeta::try_from(bad), "strictly ascending")?;
    }
    Ok(())
}
#[test]
fn proposal_detail_presence_and_requested_hash() -> anyhow::Result<()> {
    let request = ConfigProposalRequest { block: Some(block()), hash: *id(1).as_slice() };
    let absent = ConfigProposalDetail { block: block(), meta: None, value: None };
    absent.validate_request(&request)?;
    let mut p = meta();
    p.has_value = true.into();
    let detail = wire::configproposaldetail::ConfigProposalDetail {
        block: block(),
        meta: Some(p.clone()),
        value: Some(vec![7]),
    };
    let converted = ConfigProposalDetail::try_from(detail.clone())?;
    converted.validate_request(&request)?;
    let mut bad = detail.clone();
    bad.value = None;
    error_contains(ConfigProposalDetail::try_from(bad), "value presence")?;
    let mut bad = detail.clone();
    bad.meta = None;
    error_contains(ConfigProposalDetail::try_from(bad), "value presence")?;
    let mut bad = detail.clone();
    p.has_value = false.into();
    bad.meta = Some(p.clone());
    error_contains(ConfigProposalDetail::try_from(bad), "value presence")?;
    let deletion =
        ConfigProposalDetail::try_from(wire::configproposaldetail::ConfigProposalDetail {
            block: block(),
            meta: Some(p),
            value: None,
        })?;
    deletion.validate_request(&request)?;
    let mut bad_request = request.clone();
    bad_request.hash = *id(2).as_slice();
    error_contains(converted.validate_request(&bad_request), "proposal hash")?;
    let mut bad_request = request;
    bad_request.block = Some(BlockIdExt::with_params(block().shard().clone(), 0, id(9), id(8)));
    error_contains(converted.validate_request(&bad_request), "block identity")?;
    Ok(())
}
#[test]
fn list_metadata_and_requests_round_trip() -> anyhow::Result<()> {
    let request = ConfigProposalsRequest { block: Some(block()) };
    let bytes = serialize_boxed(&GetConfigProposalsRqRs::serialize(&request)?)?;
    let decoded = deserialize_boxed(bytes)?
        .downcast::<tl_api::tos::rpc::engine::validator::GetConfigProposals>()
        .map_err(|_| anyhow::anyhow!("wrong list request"))?;
    assert_eq!(decoded.block, request.block);
    let mut p = meta();
    p.has_value = true.into();
    let value = wire::configproposals::ConfigProposals { block: block(), proposals: vec![p] };
    let state = GetConfigProposalsRqRs::deserialize(deserialize_boxed(serialize_boxed(
        &value.into_boxed(),
    )?)?)?;
    state.validate_request(&request)?;
    assert!(state.proposals[0].has_value);
    let detail_request = ConfigProposalRequest { block: Some(block()), hash: *id(1).as_slice() };
    let decoded =
        deserialize_boxed(serialize_boxed(&GetConfigProposalRqRs::serialize(&detail_request)?)?)?
            .downcast::<tl_api::tos::rpc::engine::validator::GetConfigProposal>()
            .map_err(|_| anyhow::anyhow!("wrong detail request"))?;
    assert_eq!(decoded.block, detail_request.block);
    assert_eq!(*decoded.hash.as_slice(), detail_request.hash);
    let mut bad = request;
    bad.block = Some(BlockIdExt::with_params(block().shard().clone(), 0, id(8), id(9)));
    error_contains(state.validate_request(&bad), "block identity")?;
    Ok(())
}
#[test]
fn unknown_flags_are_refused_by_generated_decoders() -> anyhow::Result<()> {
    let request = ElectorStateRequest::default();
    let list = ConfigProposalsRequest::default();
    let detail = ConfigProposalRequest { block: None, hash: [0; 32] };
    let objects = vec![
        GetElectorStateRqRs::serialize(&request)?,
        GetConfigProposalsRqRs::serialize(&list)?,
        GetConfigProposalRqRs::serialize(&detail)?,
        meta().into_boxed().into_tl_object(),
        wire::configproposaldetail::ConfigProposalDetail::default().into_boxed().into_tl_object(),
    ];
    for object in objects {
        let mut bytes = serialize_boxed(&object)?;
        let _valid = deserialize_boxed(&bytes)?;
        bytes[4..8].copy_from_slice(&0x80000000u32.to_le_bytes());
        error_contains(deserialize_boxed(bytes), "unknown control query flags")?;
    }
    Ok(())
}
#[test]
fn snapshot_sizes_and_sorted_identities_are_checked() -> anyhow::Result<()> {
    let mut value = elector();
    value.participants = (0..256)
        .map(|n| wire::electionparticipant::ElectionParticipant { id: id(n), ..Default::default() })
        .collect();
    assert_eq!(ElectorState::try_from(value.clone())?.participants.len(), 256);
    value
        .participants
        .push(wire::electionparticipant::ElectionParticipant { id: id(256), ..Default::default() });
    error_contains(ElectorState::try_from(value), "more than 256")?;
    let mut value = elector();
    value.past_elections = vec![wire::pastelection::PastElection::default(); 16];
    for p in &mut value.past_elections {
        p.frozen = (0..256)
            .map(|n| wire::frozenstake::FrozenStake { id: id(n), ..Default::default() })
            .collect();
    }
    assert_eq!(ElectorState::try_from(value.clone())?.past_elections.len(), 16);
    let mut bad = value.clone();
    bad.past_elections.push(wire::pastelection::PastElection::default());
    error_contains(ElectorState::try_from(bad), "more than 16 past")?;
    let mut bad = value.clone();
    bad.past_elections[0]
        .frozen
        .push(wire::frozenstake::FrozenStake { id: id(256), ..Default::default() });
    error_contains(ElectorState::try_from(bad), "more than 256 frozen")?;
    let mut bad = value;
    bad.past_elections[0].frozen.swap(0, 1);
    error_contains(ElectorState::try_from(bad), "frozen ids")?;
    let mut value = elector();
    value.participants = vec![wire::electionparticipant::ElectionParticipant::default(); 2];
    error_contains(ElectorState::try_from(value), "participant ids")?;
    let list = wire::configproposals::ConfigProposals {
        block: block(),
        proposals: (0..4096)
            .map(|n| wire::configproposalmeta::ConfigProposalMeta {
                hash: id(n),
                ..Default::default()
            })
            .collect(),
    };
    assert_eq!(ConfigProposals::try_from(list.clone())?.proposals.len(), 4096);
    let mut bad = list.clone();
    bad.proposals.push(meta());
    error_contains(ConfigProposals::try_from(bad), "more than 4096")?;
    let mut bad = list;
    bad.proposals.swap(0, 1);
    error_contains(ConfigProposals::try_from(bad), "proposal hashes")?;
    Ok(())
}
#[test]
fn upgrade_error_is_named_and_other_errors_remain_distinct() -> anyhow::Result<()> {
    for (code, message) in [
        (621, "query not supported"),
        (0, "Unknown query"),
        (0, "failed to parse validator query: Unknown constructor 123"),
    ] {
        let error = control_query_error("getElectorState", code, message).context("operator read");
        assert_eq!(
            error
                .downcast_ref::<UnsupportedControlQuery>()
                .context("missing typed upgrade error")?
                .query,
            "getElectorState"
        );
        assert!(error.to_string().contains("operator read"));
    }
    for message in ["permission denied", "busy", "failed to parse validator query: not enough data"]
    {
        let error = control_query_error("getElectorState", 621, message);
        assert!(error.downcast_ref::<UnsupportedControlQuery>().is_none());
    }
    Ok(())
}

#[test]
fn every_wire_amount_checks_canonicality_before_mapping() -> anyhow::Result<()> {
    for field in 0..7 {
        for bytes in [vec![], vec![255; 15], vec![0], vec![0, 1], vec![1; 16]] {
            let valid = bytes.is_empty() || bytes == vec![255; 15];
            let mut value = elector();
            value.participants.push(wire::electionparticipant::ElectionParticipant::default());
            value.past_elections.push(wire::pastelection::PastElection {
                frozen: vec![wire::frozenstake::FrozenStake::default()],
                ..Default::default()
            });
            value.returned.push(wire::returnedstake::ReturnedStake::default());
            match field {
                0 => value.min_stake = bytes,
                1 => value.total_stake = bytes,
                2 => value.participants[0].stake = bytes,
                3 => value.past_elections[0].total_stake = bytes,
                4 => value.past_elections[0].bonuses = bytes,
                5 => value.past_elections[0].frozen[0].stake = bytes,
                6 => value.returned[0].amount = bytes,
                _ => anyhow::bail!("invalid test field"),
            }
            if valid {
                let _decoded = ElectorState::try_from(value)?;
            } else {
                error_contains(ElectorState::try_from(value), "Coins")?;
            }
        }
    }
    Ok(())
}
#[test]
fn nested_flags_and_decoder_positions_are_checked() -> anyhow::Result<()> {
    use tl_api::BareSerialize;
    let mut p = meta();
    p.param_hash = Some(id(17));
    let meta_bytes = p.bare_serialized_bytes()?;
    let objects = vec![
        wire::configproposals::ConfigProposals { block: block(), proposals: vec![p.clone()] }
            .into_boxed()
            .into_tl_object(),
        wire::configproposaldetail::ConfigProposalDetail {
            block: block(),
            meta: Some(p),
            value: None,
        }
        .into_boxed()
        .into_tl_object(),
    ];
    for object in objects {
        let mut bytes = serialize_boxed(&object)?;
        let expected = bytes.len();
        bytes.extend_from_slice(&[1, 2, 3]);
        let (_, consumed) = tl_api::deserialize_boxed_with_suffix(&bytes)?;
        assert_eq!(consumed, expected);
        bytes.truncate(expected);
        let offset = bytes
            .windows(meta_bytes.len())
            .position(|w| w == meta_bytes)
            .context("missing nested metadata anchor")?;
        bytes[offset..offset + 4].copy_from_slice(&0x80000001u32.to_le_bytes());
        error_contains(deserialize_boxed(bytes), "unknown control query flags")?;
    }
    Ok(())
}
#[test]
fn wrong_response_types_are_refused() -> anyhow::Result<()> {
    let object =
        wire::configproposaldetail::ConfigProposalDetail::default().into_boxed().into_tl_object();
    error_contains(GetElectorStateRqRs::deserialize(object.clone()), "Wrong downcast")?;
    error_contains(GetConfigProposalsRqRs::deserialize(object), "Wrong downcast")?;
    error_contains(
        GetConfigProposalRqRs::deserialize(elector().into_boxed().into_tl_object()),
        "Wrong downcast",
    )?;
    Ok(())
}

#[test]
fn control_reply_dispatch_validates_requests_and_preserves_upgrade_error() -> anyhow::Result<()> {
    use crate::client_adnl::decode_control_reply;
    let request = ElectorStateRequest { wallets: vec![[1; 32]], ..Default::default() };
    let query = GetElectorStateRqRs::serialize(&request)?;
    error_contains(
        decode_control_reply::<GetElectorStateRqRs>(
            &request,
            &query,
            elector().into_boxed().into_tl_object(),
        ),
        "count",
    )?;
    let error = wire::controlqueryerror::ControlQueryError {
        code: 621,
        message: "query not supported".into(),
    }
    .into_boxed()
    .into_tl_object();
    let error = decode_control_reply::<GetElectorStateRqRs>(&request, &query, error)
        .err()
        .context("unsupported query accepted")?;
    assert_eq!(
        error.downcast_ref::<UnsupportedControlQuery>().context("upgrade type lost")?.query,
        "getElectorState"
    );
    let request = ConfigProposalsRequest {
        block: Some(BlockIdExt::with_params(block().shard().clone(), 0, id(8), id(9))),
    };
    let query = GetConfigProposalsRqRs::serialize(&request)?;
    let reply = wire::configproposals::ConfigProposals { block: block(), proposals: vec![] }
        .into_boxed()
        .into_tl_object();
    error_contains(
        decode_control_reply::<GetConfigProposalsRqRs>(&request, &query, reply),
        "block identity",
    )?;
    let request = ConfigProposalRequest { block: None, hash: *id(2).as_slice() };
    let query = GetConfigProposalRqRs::serialize(&request)?;
    let reply = wire::configproposaldetail::ConfigProposalDetail {
        block: block(),
        meta: Some(meta()),
        value: None,
    }
    .into_boxed()
    .into_tl_object();
    error_contains(
        decode_control_reply::<GetConfigProposalRqRs>(&request, &query, reply),
        "proposal hash",
    )?;
    Ok(())
}
