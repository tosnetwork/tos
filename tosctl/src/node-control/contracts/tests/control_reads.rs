use anyhow::Context;
use chain_block::{BlockIdExt, BuilderData, ShardIdent, UInt256, write_boc};
use contracts::control_reads::{ElectorSnapshot, config_proposal_from_detail};
use control_client::operator_reads::{ConfigProposalDetail, ConfigProposalMeta, ElectorState};
use tl_api::tos::engine::validator as wire;

fn block() -> BlockIdExt {
    BlockIdExt::with_params(
        ShardIdent::masterchain(),
        17,
        UInt256::from([8; 32]),
        UInt256::from([9; 32]),
    )
}
fn state() -> anyhow::Result<ElectorState> {
    let participant = wire::electionparticipant::ElectionParticipant {
        id: UInt256::from([1; 32]),
        adnl: UInt256::from([2; 32]),
        key_id: UInt256::from([3; 32]),
        algorithm: 2,
        stake: vec![7],
        max_factor: -1,
    };
    let frozen = wire::frozenstake::FrozenStake {
        id: UInt256::from([4; 32]),
        owner: UInt256::from([5; 32]),
        weight: -1,
        stake: vec![11],
        banned: true.into(),
    };
    let past = wire::pastelection::PastElection {
        election_id: -1,
        unfreeze_at: i32::MIN,
        stake_held: -1,
        vset_hash: UInt256::from([6; 32]),
        total_stake: vec![13],
        bonuses: vec![17],
        frozen: vec![frozen],
    };
    wire::electorstate::ElectorState {
        block: block(),
        elect_at: -1,
        elect_close: i32::MIN,
        min_stake: vec![3],
        total_stake: vec![7],
        failed: true.into(),
        finished: true.into(),
        participants: vec![participant],
        past_elections: vec![past],
        returned: vec![wire::returnedstake::ReturnedStake {
            wallet: UInt256::from([1; 32]),
            amount: vec![19],
        }],
    }
    .try_into()
}
fn meta() -> anyhow::Result<ConfigProposalMeta> {
    wire::configproposalmeta::ConfigProposalMeta {
        hash: UInt256::from([1; 32]),
        expires: -1,
        critical: true.into(),
        param_id: -1,
        param_hash: Some(UInt256::from([255; 32])),
        has_value: true.into(),
        vset_id: UInt256::from([2; 32]),
        voters: vec![1, 65535],
        weight_remaining: i64::MIN,
        rounds_remaining: 255,
        wins: 254,
        losses: 253,
    }
    .try_into()
}
#[test]
fn elector_snapshot_preserves_existing_shapes_and_full_identity() -> anyhow::Result<()> {
    let raw = state()?;
    assert_eq!(raw.participants[0].algorithm, 2);
    assert_eq!(raw.participants[0].key_id, [3; 32]);
    let snapshot = ElectorSnapshot::try_from(raw)?;
    assert_eq!(snapshot.block, block());
    assert_eq!(snapshot.elections.election_id, u64::from(u32::MAX));
    assert_eq!(snapshot.elections.elect_close, 1u64 << 31);
    assert_eq!(snapshot.elections.min_stake, 3);
    assert_eq!(snapshot.elections.total_stake, 7);
    assert!(snapshot.elections.failed);
    assert!(snapshot.elections.finished);
    let p = &snapshot.elections.participants[0];
    assert_eq!(p.pub_key, vec![1; 32]);
    assert_eq!(p.wallet_addr, vec![1; 32]);
    assert_eq!(p.adnl_addr, vec![2; 32]);
    assert_eq!(p.stake, 7);
    assert_eq!(p.max_factor, u32::MAX);
    assert_eq!(p.election_id, u64::from(u32::MAX));
    assert!(p.stake_message_boc.is_none());
    let past = &snapshot.past_elections[0];
    assert_eq!(past.election_id, u64::from(u32::MAX));
    assert_eq!(past.unfreeze_at, 1u64 << 31);
    assert_eq!(past.stake_held, u64::from(u32::MAX));
    assert_eq!(past.vset_hash, vec![6; 32]);
    assert_eq!(past.total_stake, 13);
    assert_eq!(past.bonuses, 17);
    let f = past.frozen_map.get(&[4; 32]).context("missing validator-keyed frozen entry")?;
    assert_eq!(f.wallet_addr, [5; 32]);
    assert_eq!(f.weight, u64::MAX);
    assert_eq!(f.stake, 11);
    assert!(f.banned);
    assert_eq!(snapshot.returned, vec![([1; 32], 19)]);
    Ok(())
}
#[test]
fn each_legacy_amount_accepts_u64_max_and_refuses_overflow() -> anyhow::Result<()> {
    let max = control_client::operator_reads::CoinsAmount::from_bytes(&u64::MAX.to_be_bytes())?;
    let too_large =
        control_client::operator_reads::CoinsAmount::from_bytes(&[1, 0, 0, 0, 0, 0, 0, 0, 0])?;
    let fields = [
        "minimum stake",
        "total stake",
        "participant stake",
        "past election total stake",
        "past election bonuses",
        "frozen stake",
        "returned stake",
    ];
    for (index, field) in fields.iter().enumerate() {
        for (amount, should_accept) in [(max, true), (too_large, false)] {
            let mut raw = state()?;
            match index {
                0 => raw.min_stake = amount,
                1 => raw.total_stake = amount,
                2 => raw.participants[0].stake = amount,
                3 => raw.past_elections[0].total_stake = amount,
                4 => raw.past_elections[0].bonuses = amount,
                5 => raw.past_elections[0].frozen[0].stake = amount,
                6 => raw.returned[0].amount = amount,
                _ => anyhow::bail!("invalid test field"),
            }
            let result = ElectorSnapshot::try_from(raw);
            if should_accept {
                let _snapshot = result?;
            } else {
                let error = result.err().context("overflow accepted")?;
                assert!(
                    format!("{error:#}").contains(&format!("{field} exceeds u64")),
                    "wrong refusal: {error:#}"
                );
            }
        }
    }
    Ok(())
}
#[test]
fn no_open_election_keeps_past_and_returned_stakes() -> anyhow::Result<()> {
    let mut raw = state()?;
    raw.elect_at = 0;
    raw.elect_close = 0;
    raw.participants.clear();
    raw.past_elections[0].frozen[0].weight = 1u64 << 63;
    let snapshot = ElectorSnapshot::try_from(raw)?;
    assert_eq!(snapshot.elections.election_id, 0);
    assert!(snapshot.elections.participants.is_empty());
    assert_eq!(
        snapshot.past_elections[0].frozen_map.get(&[4; 32]).context("missing frozen")?.weight,
        1u64 << 63
    );
    assert_eq!(snapshot.returned, vec![([1; 32], 19)]);
    Ok(())
}
#[test]
fn proposal_detail_maps_value_and_deletion_without_dropping_metadata() -> anyhow::Result<()> {
    let cell = BuilderData::new().into_cell()?;
    let boc = write_boc(&cell)?;
    let detail = ConfigProposalDetail { block: block(), meta: Some(meta()?), value: Some(boc) };
    let proposal = config_proposal_from_detail(detail)?.context("missing proposal")?;
    assert_eq!(proposal.hash, [1; 32]);
    assert_eq!(proposal.expires, u32::MAX);
    assert!(proposal.is_critical);
    assert_eq!(proposal.param.id, -1);
    assert_eq!(proposal.param.hash, Some([255; 32]));
    assert_eq!(proposal.param.cell.context("dropped value")?, cell);
    assert_eq!(proposal.vset_id, [2; 32]);
    assert_eq!(proposal.voters, vec![1, 65535]);
    assert_eq!(proposal.weight_remaining, i64::MIN);
    assert_eq!(proposal.rounds_remaining, 255);
    assert_eq!(proposal.wins, 254);
    assert_eq!(proposal.losses, 253);
    let mut deletion = meta()?;
    deletion.has_value = false;
    deletion.param_hash = None;
    let proposal = config_proposal_from_detail(ConfigProposalDetail {
        block: block(),
        meta: Some(deletion),
        value: None,
    })?
    .context("missing deletion")?;
    assert!(proposal.param.cell.is_none());
    assert!(proposal.param.hash.is_none());
    assert!(
        config_proposal_from_detail(ConfigProposalDetail {
            block: block(),
            meta: None,
            value: None
        })?
        .is_none()
    );
    Ok(())
}
#[test]
fn proposal_detail_refuses_invalid_boc_and_presence_combinations() -> anyhow::Result<()> {
    for detail in [
        ConfigProposalDetail { block: block(), meta: Some(meta()?), value: Some(vec![1, 2, 3]) },
        ConfigProposalDetail { block: block(), meta: Some(meta()?), value: None },
        ConfigProposalDetail { block: block(), meta: None, value: Some(vec![1]) },
    ] {
        assert!(config_proposal_from_detail(detail).is_err());
    }
    let mut deletion = meta()?;
    deletion.has_value = false;
    assert!(
        config_proposal_from_detail(ConfigProposalDetail {
            block: block(),
            meta: Some(deletion),
            value: Some(write_boc(&BuilderData::new().into_cell()?)?)
        })
        .is_err()
    );
    Ok(())
}
#[test]
fn duplicate_frozen_validator_is_refused_in_contract_adapter() -> anyhow::Result<()> {
    let mut raw = state()?;
    let f = raw.past_elections[0].frozen[0].clone();
    raw.past_elections[0].frozen.push(f);
    let error = ElectorSnapshot::try_from(raw).err().context("duplicate accepted")?;
    assert!(error.to_string().contains("duplicate frozen validator id"));
    Ok(())
}

#[test]
fn proposal_value_depth_has_accept_and_refuse_boundaries() -> anyhow::Result<()> {
    let mut cell = BuilderData::new().into_cell()?;
    for _ in 0..1023 {
        let mut builder = BuilderData::new();
        builder.checked_append_reference(cell)?;
        cell = builder.into_cell()?;
    }
    let value = config_proposal_from_detail(ConfigProposalDetail {
        block: block(),
        meta: Some(meta()?),
        value: Some(write_boc(&cell)?),
    })?;
    assert!(value.context("missing proposal")?.param.cell.is_some());
    let mut builder = BuilderData::new();
    builder.checked_append_reference(cell)?;
    let cell = builder.into_cell()?;
    let error = config_proposal_from_detail(ConfigProposalDetail {
        block: block(),
        meta: Some(meta()?),
        value: Some(write_boc(&cell)?),
    })
    .err()
    .context("deep value accepted")?;
    assert!(error.to_string().contains("1024-cell depth"), "wrong refusal: {error:#}");
    Ok(())
}
