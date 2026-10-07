//! Checked adapters for control snapshots; public getter readers remain separate.
use crate::{
    config_contract::{ConfigProposal, ProposedParam},
    elector::{ElectionsInfo, FrozenParticipant, Participant, PastElections},
};
use anyhow::{Context, ensure};
use chain_block::{BlockIdExt, read_single_root_boc};
pub use control_client::operator_reads::ConfigProposalMeta;
use control_client::operator_reads::{ConfigProposalDetail, ElectorState};
use std::collections::HashMap;

/// All elector facts used by one decision, from one returned block.
pub struct ElectorSnapshot {
    pub block: BlockIdExt,
    pub elections: ElectionsInfo,
    pub past_elections: Vec<PastElections>,
    pub returned: Vec<([u8; 32], u64)>,
}
impl TryFrom<ElectorState> for ElectorSnapshot {
    type Error = anyhow::Error;
    fn try_from(state: ElectorState) -> anyhow::Result<Self> {
        let election_id = u64::from(state.elect_at);
        let participants = state
            .participants
            .into_iter()
            .map(|p| {
                Ok(Participant {
                    // The getter keys participants by the account that controls the stake.
                    pub_key: p.id.to_vec(),
                    wallet_addr: p.id.to_vec(),
                    adnl_addr: p.adnl.to_vec(),
                    stake: p.stake.checked_u64("participant stake")?,
                    max_factor: p.max_factor,
                    election_id,
                    stake_message_boc: None,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let elections = ElectionsInfo {
            election_id,
            elect_close: u64::from(state.elect_close),
            min_stake: state.min_stake.checked_u64("minimum stake")?,
            total_stake: state.total_stake.checked_u64("total stake")?,
            failed: state.failed,
            finished: state.finished,
            participants,
        };
        let mut past_elections = Vec::with_capacity(state.past_elections.len());
        for p in state.past_elections {
            let mut frozen_map = HashMap::with_capacity(p.frozen.len());
            for f in p.frozen {
                let entry = FrozenParticipant {
                    wallet_addr: f.owner,
                    weight: f.weight,
                    stake: f.stake.checked_u64("frozen stake")?,
                    banned: f.banned,
                };
                ensure!(frozen_map.insert(f.id, entry).is_none(), "duplicate frozen validator id");
            }
            past_elections.push(PastElections {
                election_id: u64::from(p.election_id),
                unfreeze_at: u64::from(p.unfreeze_at),
                stake_held: u64::from(p.stake_held),
                vset_hash: p.vset_hash.to_vec(),
                frozen_map,
                total_stake: p.total_stake.checked_u64("past election total stake")?,
                bonuses: p.bonuses.checked_u64("past election bonuses")?,
            });
        }
        let returned = state
            .returned
            .into_iter()
            .map(|r| Ok((r.wallet, r.amount.checked_u64("returned stake")?)))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self { block: state.block, elections, past_elections, returned })
    }
}

/// A detail reply may describe deletion; metadata alone cannot produce this type.
///
/// ```compile_fail
/// fn drop_value(meta: control_client::operator_reads::ConfigProposalMeta)
///     -> contracts::config_contract::ConfigProposal {
///     meta.into()
/// }
/// ```
pub fn config_proposal_from_detail(
    detail: ConfigProposalDetail,
) -> anyhow::Result<Option<ConfigProposal>> {
    let Some(meta) = detail.meta else {
        ensure!(detail.value.is_none(), "proposal value without metadata");
        return Ok(None);
    };
    ensure!(
        meta.has_value == detail.value.is_some(),
        "proposal value presence does not match metadata"
    );
    let cell = detail
        .value
        .map(|boc| read_single_root_boc(&boc).context("invalid proposal value BOC"))
        .transpose()?;
    if let Some(value) = &cell {
        ensure!(value.repr_depth() < 1024, "proposal value exceeds 1024-cell depth limit");
    }
    Ok(Some(ConfigProposal {
        hash: meta.hash,
        expires: meta.expires,
        is_critical: meta.critical,
        param: ProposedParam { id: meta.param_id, cell, hash: meta.param_hash },
        vset_id: meta.vset_id,
        voters: meta.voters,
        weight_remaining: meta.weight_remaining,
        rounds_remaining: meta.rounds_remaining,
        wins: meta.wins,
        losses: meta.losses,
    }))
}
