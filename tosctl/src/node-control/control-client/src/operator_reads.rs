//! Validated snapshots from the authenticated operator control channel.
use anyhow::{Context, ensure};
use chain_block::{BlockIdExt, UInt256};
use std::{collections::HashSet, error::Error, fmt};
use tl_api::tos::engine::validator as wire;

pub const MAX_RETURNED_WALLETS: usize = 16;

/// A supported operator workflow requires a node that implements its control query.
/// Callers must propagate this error, never retry through a public getter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedControlQuery {
    pub query: &'static str,
}
impl fmt::Display for UnsupportedControlQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is unsupported; upgrade the node", self.query)
    }
}
impl Error for UnsupportedControlQuery {}

pub fn control_query_error(query: &'static str, code: i32, message: &str) -> anyhow::Error {
    let normalized = message.to_ascii_lowercase();
    if (code == 621 && normalized.contains("query not supported"))
        || normalized.contains("unknown query")
        || (normalized.contains("failed to parse validator query")
            && (normalized.contains("unknown constructor")
                || normalized.contains("unknown function")))
    {
        UnsupportedControlQuery { query }.into()
    } else {
        anyhow::anyhow!("{query}: control error {code}: {message}")
    }
}

/// Canonical Coins, kept wide until a consumer requests a narrower representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinsAmount(u128);
impl CoinsAmount {
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(bytes.len() <= 15, "Coins exceeds 15 bytes");
        ensure!(bytes.first() != Some(&0), "Coins has a leading zero byte");
        let mut amount = 0u128;
        for byte in bytes {
            amount = amount.checked_mul(256).context("Coins multiplication overflow")?;
            amount = amount.checked_add(u128::from(*byte)).context("Coins addition overflow")?;
        }
        Ok(Self(amount))
    }
    pub fn as_u128(self) -> u128 {
        self.0
    }
    pub fn checked_u64(self, field: &str) -> anyhow::Result<u64> {
        u64::try_from(self.0).with_context(|| format!("{field} exceeds u64"))
    }
}

pub fn unsigned_int(value: i32) -> u32 {
    u32::from_ne_bytes(value.to_ne_bytes())
}
pub fn unsigned_long(value: i64) -> u64 {
    u64::from_ne_bytes(value.to_ne_bytes())
}
fn hash(value: &UInt256) -> [u8; 32] {
    *value.as_slice()
}
fn check_block(requested: Option<&BlockIdExt>, actual: &BlockIdExt) -> anyhow::Result<()> {
    ensure!(actual.shard().is_masterchain(), "response block is not masterchain");
    if let Some(expected) = requested {
        ensure!(expected == actual, "response block identity does not match request");
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct ElectorStateRequest {
    pub block: Option<BlockIdExt>,
    pub wallets: Vec<[u8; 32]>,
}
impl ElectorStateRequest {
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(self.wallets.len() <= MAX_RETURNED_WALLETS, "more than 16 returned-stake wallets");
        let unique: HashSet<_> = self.wallets.iter().collect();
        ensure!(unique.len() == self.wallets.len(), "duplicate returned-stake wallet");
        if let Some(block) = &self.block {
            ensure!(block.shard().is_masterchain(), "requested block is not masterchain");
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Default)]
pub struct ConfigProposalsRequest {
    pub block: Option<BlockIdExt>,
}
#[derive(Debug, Clone)]
pub struct ConfigProposalRequest {
    pub block: Option<BlockIdExt>,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct ElectionParticipant {
    pub id: [u8; 32],
    pub stake: CoinsAmount,
    pub max_factor: u32,
    pub adnl: [u8; 32],
    pub algorithm: u32,
    pub key_id: [u8; 32],
}
#[derive(Debug, Clone)]
pub struct FrozenStake {
    pub id: [u8; 32],
    pub owner: [u8; 32],
    pub weight: u64,
    pub stake: CoinsAmount,
    pub banned: bool,
}
#[derive(Debug, Clone)]
pub struct PastElection {
    pub election_id: u32,
    pub unfreeze_at: u32,
    pub stake_held: u32,
    pub vset_hash: [u8; 32],
    pub total_stake: CoinsAmount,
    pub bonuses: CoinsAmount,
    pub frozen: Vec<FrozenStake>,
}
#[derive(Debug, Clone)]
pub struct ReturnedStake {
    pub wallet: [u8; 32],
    pub amount: CoinsAmount,
}
#[derive(Debug, Clone)]
pub struct ElectorState {
    pub block: BlockIdExt,
    pub elect_at: u32,
    pub elect_close: u32,
    pub min_stake: CoinsAmount,
    pub total_stake: CoinsAmount,
    pub failed: bool,
    pub finished: bool,
    pub participants: Vec<ElectionParticipant>,
    pub past_elections: Vec<PastElection>,
    pub returned: Vec<ReturnedStake>,
}
impl ElectorState {
    pub fn validate_request(&self, request: &ElectorStateRequest) -> anyhow::Result<()> {
        request.validate()?;
        check_block(request.block.as_ref(), &self.block)?;
        ensure!(
            self.returned.len() == request.wallets.len(),
            "returned wallet count does not match request"
        );
        for (entry, wallet) in self.returned.iter().zip(&request.wallets) {
            ensure!(
                &entry.wallet == wallet,
                "returned wallet order or address does not match request"
            );
        }
        Ok(())
    }
}
impl TryFrom<wire::electorstate::ElectorState> for ElectorState {
    type Error = anyhow::Error;
    fn try_from(value: wire::electorstate::ElectorState) -> anyhow::Result<Self> {
        ensure!(value.participants.len() <= 256, "more than 256 election participants");
        ensure!(value.past_elections.len() <= 16, "more than 16 past elections");
        ensure!(value.returned.len() <= MAX_RETURNED_WALLETS, "more than 16 returned stakes");
        let participants = value
            .participants
            .into_iter()
            .map(|p| {
                Ok(ElectionParticipant {
                    id: hash(&p.id),
                    stake: CoinsAmount::from_bytes(&p.stake)?,
                    max_factor: unsigned_int(p.max_factor),
                    adnl: hash(&p.adnl),
                    algorithm: unsigned_int(p.algorithm),
                    key_id: hash(&p.key_id),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        ensure!(
            participants.windows(2).all(|p| p[0].id < p[1].id),
            "participant ids are not strictly ascending"
        );
        let mut past_elections = Vec::with_capacity(value.past_elections.len());
        for p in value.past_elections {
            ensure!(p.frozen.len() <= 256, "more than 256 frozen entries in an election");
            let frozen = p
                .frozen
                .into_iter()
                .map(|f| {
                    Ok(FrozenStake {
                        id: hash(&f.id),
                        owner: hash(&f.owner),
                        weight: unsigned_long(f.weight),
                        stake: CoinsAmount::from_bytes(&f.stake)?,
                        banned: f.banned.into(),
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            ensure!(
                frozen.windows(2).all(|f| f[0].id < f[1].id),
                "frozen ids are not strictly ascending"
            );
            past_elections.push(PastElection {
                election_id: unsigned_int(p.election_id),
                unfreeze_at: unsigned_int(p.unfreeze_at),
                stake_held: unsigned_int(p.stake_held),
                vset_hash: hash(&p.vset_hash),
                total_stake: CoinsAmount::from_bytes(&p.total_stake)?,
                bonuses: CoinsAmount::from_bytes(&p.bonuses)?,
                frozen,
            });
        }
        let returned = value
            .returned
            .into_iter()
            .map(|r| {
                Ok(ReturnedStake {
                    wallet: hash(&r.wallet),
                    amount: CoinsAmount::from_bytes(&r.amount)?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self {
            block: value.block,
            elect_at: unsigned_int(value.elect_at),
            elect_close: unsigned_int(value.elect_close),
            min_stake: CoinsAmount::from_bytes(&value.min_stake)?,
            total_stake: CoinsAmount::from_bytes(&value.total_stake)?,
            failed: value.failed.into(),
            finished: value.finished.into(),
            participants,
            past_elections,
            returned,
        })
    }
}

/// Metadata deliberately has no conversion into a value-bearing contract proposal.
#[derive(Debug, Clone)]
pub struct ConfigProposalMeta {
    pub hash: [u8; 32],
    pub expires: u32,
    pub critical: bool,
    pub param_id: i32,
    pub param_hash: Option<[u8; 32]>,
    pub has_value: bool,
    pub vset_id: [u8; 32],
    pub voters: Vec<u16>,
    pub weight_remaining: i64,
    pub rounds_remaining: u8,
    pub wins: u8,
    pub losses: u8,
}
impl TryFrom<wire::configproposalmeta::ConfigProposalMeta> for ConfigProposalMeta {
    type Error = anyhow::Error;
    fn try_from(p: wire::configproposalmeta::ConfigProposalMeta) -> anyhow::Result<Self> {
        let voters = p
            .voters
            .into_iter()
            .map(|v| u16::try_from(unsigned_int(v)).context("proposal voter exceeds u16"))
            .collect::<anyhow::Result<Vec<_>>>()?;
        ensure!(
            voters.windows(2).all(|v| v[0] < v[1]),
            "proposal voters are not strictly ascending"
        );
        Ok(Self {
            hash: hash(&p.hash),
            expires: unsigned_int(p.expires),
            critical: p.critical.into(),
            param_id: p.param_id,
            param_hash: p.param_hash.as_ref().map(hash),
            has_value: p.has_value.into(),
            vset_id: hash(&p.vset_id),
            voters,
            weight_remaining: p.weight_remaining,
            rounds_remaining: u8::try_from(unsigned_int(p.rounds_remaining))
                .context("proposal rounds exceed u8")?,
            wins: u8::try_from(unsigned_int(p.wins)).context("proposal wins exceed u8")?,
            losses: u8::try_from(unsigned_int(p.losses)).context("proposal losses exceed u8")?,
        })
    }
}
#[derive(Debug, Clone)]
pub struct ConfigProposals {
    pub block: BlockIdExt,
    pub proposals: Vec<ConfigProposalMeta>,
}
impl ConfigProposals {
    pub fn validate_request(&self, request: &ConfigProposalsRequest) -> anyhow::Result<()> {
        check_block(request.block.as_ref(), &self.block)
    }
}
impl TryFrom<wire::configproposals::ConfigProposals> for ConfigProposals {
    type Error = anyhow::Error;
    fn try_from(p: wire::configproposals::ConfigProposals) -> anyhow::Result<Self> {
        ensure!(p.proposals.len() <= 4096, "more than 4096 proposals");
        let proposals = p
            .proposals
            .into_iter()
            .map(ConfigProposalMeta::try_from)
            .collect::<anyhow::Result<Vec<_>>>()?;
        ensure!(
            proposals.windows(2).all(|p| p[0].hash < p[1].hash),
            "proposal hashes are not strictly ascending"
        );
        Ok(Self { block: p.block, proposals })
    }
}
#[derive(Debug, Clone)]
pub struct ConfigProposalDetail {
    pub block: BlockIdExt,
    pub meta: Option<ConfigProposalMeta>,
    pub value: Option<Vec<u8>>,
}
impl ConfigProposalDetail {
    pub fn validate_request(&self, request: &ConfigProposalRequest) -> anyhow::Result<()> {
        check_block(request.block.as_ref(), &self.block)?;
        if let Some(meta) = &self.meta {
            ensure!(meta.hash == request.hash, "proposal hash does not match request");
            ensure!(
                meta.has_value == self.value.is_some(),
                "proposal value presence does not match metadata"
            );
        } else {
            ensure!(self.value.is_none(), "proposal value without metadata");
        }
        Ok(())
    }
}
impl TryFrom<wire::configproposaldetail::ConfigProposalDetail> for ConfigProposalDetail {
    type Error = anyhow::Error;
    fn try_from(p: wire::configproposaldetail::ConfigProposalDetail) -> anyhow::Result<Self> {
        let meta = p.meta.map(ConfigProposalMeta::try_from).transpose()?;
        ensure!(
            meta.as_ref().is_some_and(|m| m.has_value) == p.value.is_some(),
            "proposal value presence does not match metadata"
        );
        Ok(Self { block: p.block, meta, value: p.value })
    }
}

#[cfg(test)]
mod tests;
