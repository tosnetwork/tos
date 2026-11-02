/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! The pool's history, from the chain into the ledger.
//!
//! Two ways to learn where the pool is. The verified way reads the account
//! and the gas prices through the local proof verifier at one authenticated
//! masterchain block, binds the newest transaction to that state, and binds
//! each older transaction to the one after it. The unverified way takes the
//! same shape from a JSON-RPC endpoint and checks the same links locally, but
//! the head itself is whatever the endpoint said; everything built on it is
//! labelled so.
//!
//! Either way, every transaction is authenticated before it is decoded, so
//! what the replay keeps is the decoded event and not the transaction.

use anyhow::Context;
use base64::Engine;
use chain_block::{
    Cell, ConfigParamEnum, Deserializable, GasLimitsPrices, MsgAddressInt, Transaction,
    read_single_root_boc,
};
use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
use common::app_config::ProofVerifierConfig;
use contracts::MasterchainCheckpoint;
use contracts::proven_getters::{ProvenAccountState, ProvenGetterProvider, ReadPolicy};
use contracts::proven_transactions::ProvenTransaction;
use contracts::shielded_pool::{self, PoolState, PoolTransaction};
use shielded_pool_circuit::field::{Fr, fr_from_be, fr_to_be};
use shielded_pool_wallet::ledger::{Event, Ledger, Payout, Transact};
use std::time::{Duration, Instant};

use super::store::ChainIdentity;

/// The most transactions one sync will fetch. Past this the sync stops with
/// the previous state intact and says so.
pub const MAX_HISTORY_TRANSACTIONS: u64 = 50_000;
/// How long one sync may spend fetching history.
pub const HISTORY_DEADLINE: Duration = Duration::from_secs(600);
/// Transactions per page from the endpoint.
const PAGE: u32 = 50;
/// The largest transaction BOC accepted from the endpoint.
const MAX_TRANSACTION_BYTES: usize = 1 << 20;

/// Where the pool is now, by one of the two ways of knowing.
pub struct Head {
    pub verified: bool,
    pub global_id: i32,
    pub last_lt: u64,
    pub last_hash: [u8; 32],
    pub code_hash: [u8; 32],
    pub state: PoolState,
    pub gas: GasLimitsPrices,
    pub checkpoint: Option<MasterchainCheckpoint>,
    pub block_gen_utime: u32,
    pub chain: ChainIdentity,
    source: HeadSource,
}

enum HeadSource {
    Proven(Box<ProvenAccountState>),
    Rpc,
}

#[derive(serde::Deserialize)]
struct AnchorFile {
    root_hash: String,
    file_hash: String,
}

/// The pool and the gas prices at one authenticated live block.
pub async fn read_head_verified(
    verifier: &ProofVerifierConfig,
    pool: &MsgAddressInt,
) -> anyhow::Result<Head> {
    anyhow::ensure!(
        verifier.live_state_file.is_some(),
        "proof_verifier needs live_state_file and live_max_age_seconds for a live pool read"
    );
    let provider = ProvenGetterProvider::new(verifier)?;
    let proven = provider
        .read_account_with_config(pool, &[19, 21], &ReadPolicy::Live)
        .await
        .context("authenticated pool read")?;
    let account = proven.account();
    anyhow::ensure!(account.get_addr() == Some(pool), "the proven account is not the pool");
    let code_hash = *account.get_code_hash().context("the pool has no code")?.as_array();
    let data = account.get_data().context("the pool has no data")?;
    let state = PoolState::parse(&data).context("the pool's state cell")?;
    let global_id = match ConfigParamEnum::construct_from_cell_and_number(
        proven.config_param(19).context("config parameter 19 was not proven")?.clone(),
        19,
    )? {
        ConfigParamEnum::ConfigParam19(value) => value as i32,
        other => anyhow::bail!("config parameter 19 is not a global id: {other:?}"),
    };
    let gas = gas_prices(proven.config_param(21).context("config parameter 21 was not proven")?)?;
    let anchor_text =
        std::fs::read(&verifier.anchor_file).context("read the proof anchor for its identity")?;
    let anchor: AnchorFile = serde_json::from_slice(&anchor_text).context("proof anchor file")?;
    let chain = ChainIdentity {
        source: "proof-anchor".into(),
        root_hash: super::profile::word(&anchor.root_hash).context("anchor root_hash")?,
        file_hash: super::profile::word(&anchor.file_hash).context("anchor file_hash")?,
    };
    let evidence = proven.evidence();
    Ok(Head {
        verified: true,
        global_id,
        last_lt: evidence.account.last_trans_lt,
        last_hash: *proven.last_transaction_hash(),
        code_hash,
        state,
        gas,
        checkpoint: Some(evidence.checkpoint.clone()),
        block_gen_utime: evidence.block_gen_utime,
        chain,
        source: HeadSource::Proven(Box::new(proven)),
    })
}

/// The same, as an RPC endpoint reports it. Nothing here is authenticated.
pub async fn read_head_unverified(
    rpc: &ClientJsonRpc,
    pool: &MsgAddressInt,
) -> anyhow::Result<Head> {
    let info = rpc.get_address_information(pool).await.context("getAddressInformation")?;
    let code = info.code.as_deref().context("the pool has no code")?;
    let data = info.data.as_deref().context("the pool has no data")?;
    let code_hash = *read_single_root_boc(code).context("the pool's code")?.repr_hash().as_array();
    let state = PoolState::parse(&read_single_root_boc(data).context("the pool's data")?)
        .context("the pool's state cell")?;
    let last_hash: [u8; 32] = info
        .last_transaction_id
        .hash
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("a last transaction hash that is not 32 bytes"))?;
    let global_id = rpc.get_global_id().await.context("read the network global id")?;
    let gas = match rpc.get_config_param(21).await.context("getConfigParam(21)")? {
        ConfigParamEnum::ConfigParam21(value) => value,
        other => anyhow::bail!("config parameter 21 is not gas pricing: {other:?}"),
    };
    let master = rpc.get_masterchain_info().await.context("getMasterchainInfo")?;
    let init = master.init.context("the endpoint reports no init block")?;
    let chain = ChainIdentity {
        source: "rpc-init-block".into(),
        root_hash: init
            .root_hash
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("an init block root hash that is not 32 bytes"))?,
        file_hash: init
            .file_hash
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("an init block file hash that is not 32 bytes"))?,
    };
    Ok(Head {
        verified: false,
        global_id,
        last_lt: info.last_transaction_id.lt,
        last_hash,
        code_hash,
        state,
        gas,
        checkpoint: None,
        block_gen_utime: u32::try_from(info.sync_utime).unwrap_or(u32::MAX),
        chain,
        source: HeadSource::Rpc,
    })
}

fn gas_prices(cell: &Cell) -> anyhow::Result<GasLimitsPrices> {
    match ConfigParamEnum::construct_from_cell_and_number(cell.clone(), 21)? {
        ConfigParamEnum::ConfigParam21(value) => Ok(value),
        other => anyhow::bail!("config parameter 21 is not gas pricing: {other:?}"),
    }
}

impl Head {
    /// What the pool charges a bounce it accepts, under the gas prices at
    /// this head. A bounce in the history that executed under other prices
    /// shows up as a final checkpoint mismatch.
    pub fn recovery_charge(&self) -> anyhow::Result<u128> {
        shielded_pool::compute_fee(&self.gas, shielded_pool::BOUNCE_GAS_CEILING)
    }

    pub fn deposit_fee(&self) -> anyhow::Result<u128> {
        shielded_pool::compute_fee(&self.gas, shielded_pool::DEPOSIT_GAS_CEILING)
    }

    pub fn has_history(&self) -> bool {
        self.last_lt > 0 && self.last_hash != [0; 32]
    }
}

/// One authenticated transaction and the means to step to the one before it.
enum Link {
    Proven(ProvenTransaction),
    Plain { transaction: Transaction, address: MsgAddressInt, hash: [u8; 32] },
}

impl Link {
    fn latest(head: &Head, pool: &MsgAddressInt, root: Cell) -> anyhow::Result<Self> {
        match &head.source {
            HeadSource::Proven(proven) => {
                Ok(Self::Proven(ProvenTransaction::latest(proven, root)?))
            }
            HeadSource::Rpc => {
                let transaction = Self::bound(root, head.last_hash, head.last_lt, pool)?;
                Ok(Self::Plain { transaction, address: pool.clone(), hash: head.last_hash })
            }
        }
    }

    fn bound(
        root: Cell,
        expected_hash: [u8; 32],
        expected_lt: u64,
        address: &MsgAddressInt,
    ) -> anyhow::Result<Transaction> {
        anyhow::ensure!(root.repr_hash().as_array() == &expected_hash, "transaction hash mismatch");
        let transaction = Transaction::construct_from_cell(root)?;
        anyhow::ensure!(
            transaction.logical_time() == expected_lt,
            "transaction logical time mismatch"
        );
        anyhow::ensure!(
            transaction.account_id() == address.address(),
            "transaction account mismatch"
        );
        Ok(transaction)
    }

    fn previous(&self, root: Cell) -> anyhow::Result<Self> {
        match self {
            Self::Proven(proven) => Ok(Self::Proven(proven.previous(root)?)),
            Self::Plain { transaction, address, .. } => {
                let lt = transaction.prev_trans_lt();
                anyhow::ensure!(
                    lt > 0 && lt < transaction.logical_time(),
                    "invalid previous transaction time"
                );
                let hash = *transaction.prev_trans_hash().as_array();
                let previous = Self::bound(root, hash, lt, address)?;
                anyhow::ensure!(
                    previous.now() <= transaction.now(),
                    "transaction history time reversal"
                );
                anyhow::ensure!(
                    previous.read_state_update()?.new_hash
                        == transaction.read_state_update()?.old_hash,
                    "transaction state chain mismatch"
                );
                Ok(Self::Plain { transaction: previous, address: address.clone(), hash })
            }
        }
    }

    fn transaction(&self) -> &Transaction {
        match self {
            Self::Proven(proven) => proven.transaction(),
            Self::Plain { transaction, .. } => transaction,
        }
    }

    fn hash(&self) -> [u8; 32] {
        match self {
            Self::Proven(proven) => *proven.root().repr_hash().as_array(),
            Self::Plain { hash, .. } => *hash,
        }
    }
}

/// One authenticated transaction, decoded.
pub struct Step {
    pub lt: u64,
    pub hash: [u8; 32],
    /// `None` for a transaction that left the state as it found it.
    pub event: Option<Event>,
}

/// The history between a cursor and the head, oldest first.
pub struct History {
    pub steps: Vec<Step>,
}

/// Walks from the head back to `cursor` -- the exact LT and hash the last
/// replay stopped at -- or to the pool's first transaction, authenticating
/// each step before decoding it. A cursor the history never reaches is an
/// error: the stored state is from some other history.
pub async fn fetch_history(
    rpc: &ClientJsonRpc,
    pool: &MsgAddressInt,
    head: &Head,
    cursor: Option<(u64, [u8; 32])>,
) -> anyhow::Result<History> {
    let mut steps: Vec<Step> = Vec::new();
    if !head.has_history() {
        anyhow::ensure!(cursor.is_none(), "the pool has no history but the state has a cursor");
        return Ok(History { steps });
    }
    if let Some((lt, hash)) = cursor
        && lt == head.last_lt
    {
        anyhow::ensure!(hash == head.last_hash, "the cursor names another transaction at the head");
        return Ok(History { steps });
    }
    let started = Instant::now();
    let mut page = fetch_page(rpc, pool, head.last_lt, &head.last_hash).await?;
    let mut link = Link::latest(head, pool, page.next().context("the endpoint returned no head")?)?;
    let mut count = 0u64;
    loop {
        let transaction = link.transaction();
        let lt = transaction.logical_time();
        let hash = link.hash();
        if let Some((cursor_lt, cursor_hash)) = cursor {
            anyhow::ensure!(lt >= cursor_lt, "the history passed the cursor without meeting it");
            if lt == cursor_lt {
                anyhow::ensure!(hash == cursor_hash, "the cursor names another transaction");
                steps.reverse();
                return Ok(History { steps });
            }
        }
        count = count.checked_add(1).context("history count overflow")?;
        anyhow::ensure!(
            count <= MAX_HISTORY_TRANSACTIONS,
            "the history is longer than {MAX_HISTORY_TRANSACTIONS} transactions; this sync stops \
             with the previous state intact"
        );
        anyhow::ensure!(
            started.elapsed() <= HISTORY_DEADLINE,
            "fetching the history took longer than {}s; this sync stops with the previous state \
             intact",
            HISTORY_DEADLINE.as_secs()
        );
        steps.push(decode(transaction, lt, hash)?);
        if transaction.prev_trans_lt() == 0 {
            anyhow::ensure!(
                cursor.is_none(),
                "the history reached the pool's first transaction without meeting the cursor"
            );
            steps.reverse();
            return Ok(History { steps });
        }
        let next_root = match page.next() {
            Some(root) => root,
            None => {
                let prev_lt = transaction.prev_trans_lt();
                let prev_hash = *transaction.prev_trans_hash().as_array();
                page = fetch_page(rpc, pool, prev_lt, &prev_hash).await?;
                page.next().context("the endpoint returned an empty history page")?
            }
        };
        link = link.previous(next_root)?;
    }
}

async fn fetch_page(
    rpc: &ClientJsonRpc,
    pool: &MsgAddressInt,
    lt: u64,
    hash: &[u8; 32],
) -> anyhow::Result<std::vec::IntoIter<Cell>> {
    let result = rpc
        .get_transactions(pool, lt, &base64::engine::general_purpose::STANDARD.encode(hash), PAGE)
        .await?;
    let mut roots = Vec::with_capacity(result.transactions.len());
    for raw in result.transactions {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(raw.data)
            .context("a transaction that is not base64")?;
        anyhow::ensure!(bytes.len() <= MAX_TRANSACTION_BYTES, "a transaction larger than 1 MiB");
        roots.push(read_single_root_boc(bytes).context("a transaction that is not a BOC")?);
    }
    Ok(roots.into_iter())
}

fn decode(transaction: &Transaction, lt: u64, hash: [u8; 32]) -> anyhow::Result<Step> {
    let classified = shielded_pool::classify(transaction)
        .with_context(|| format!("pool transaction lt {lt} {}", hex::encode(hash)))?;
    let event = match classified {
        PoolTransaction::Deposit(body) => Some(Event::Deposit {
            amount: body.amount,
            owner_commitment: fr(&body.owner_commitment, "owner commitment")?,
            output_data: body.output_data,
        }),
        PoolTransaction::Transact { body, payout } => Some(Event::Transact(Box::new(Transact {
            nullifiers: [
                fr(&body.nullifiers[0], "nullifier")?,
                fr(&body.nullifiers[1], "nullifier")?,
            ],
            note_bodies: [
                fr(&body.note_bodies[0], "note body")?,
                fr(&body.note_bodies[1], "note body")?,
                fr(&body.note_bodies[2], "note body")?,
            ],
            payloads: body.payloads.clone(),
            public_amount_out: body.public_amount_out,
            withdrawal_fee: body.withdrawal_fee,
            recovery_owner_commitment: fr(&body.recovery_owner_commitment, "recovery owner")?,
            recovery_payload: body.recovery_payload.clone(),
            payout: payout.map(|payout| Payout {
                recipient: payout.recipient.to_string(),
                value: payout.value,
                body_hash: payout.body_hash,
            }),
        }))),
        PoolTransaction::Bounce { original_body_hash, sender, value } => {
            Some(Event::Bounce { original_body_hash, sender: sender.to_string(), value })
        }
        PoolTransaction::NoStateChange(_) => None,
    };
    Ok(Step { lt, hash, event })
}

fn fr(word: &[u8; 32], what: &str) -> anyhow::Result<Fr> {
    fr_from_be(word).map_err(|error| anyhow::anyhow!("{what} is not a field element: {error:?}"))
}

/// What a replay of a history produced.
pub struct Replay {
    pub ledger: Ledger,
    pub applied: u64,
    pub skipped: u64,
}

/// Applies a history to a ledger under one recovery charge, then requires
/// the result to be the state the chain shows.
pub fn replay(mut ledger: Ledger, history: &History, head: &Head) -> anyhow::Result<Replay> {
    let charge = head.recovery_charge()?;
    let mut applied = 0u64;
    let mut skipped = 0u64;
    let mut bounces = 0u64;
    for step in &history.steps {
        match &step.event {
            Some(event) => {
                if matches!(event, Event::Bounce { .. }) {
                    bounces = bounces.saturating_add(1);
                }
                ledger.apply(event, charge).map_err(|error| {
                    anyhow::anyhow!(
                        "replaying pool transaction lt {} {}: {error}",
                        step.lt,
                        hex::encode(step.hash)
                    )
                })?;
                applied = applied.saturating_add(1);
            }
            None => skipped = skipped.saturating_add(1),
        }
    }
    check_checkpoint(&ledger, &head.state, bounces)?;
    Ok(Replay { ledger, applied, skipped })
}

fn check_checkpoint(ledger: &Ledger, state: &PoolState, bounces: u64) -> anyhow::Result<()> {
    let have = ledger.checkpoint();
    let same = fr_to_be(&have.commitment_root) == state.commitment_root
        && have.commitment_next_index == state.commitment_next_index
        && have.reserved_recovery_leaves == u64::from(state.reserved_recovery_leaves)
        && fr_to_be(&have.nullifier_root) == state.nullifier_root
        && have.nullifier_next_index == state.nullifier_next_index
        && have.native_liability == state.native_liability;
    if same {
        return Ok(());
    }
    let hint = if bounces > 0 {
        " The history holds recovery bounces, and this client prices them at the current gas \
         prices; a bounce executed under earlier prices is a known limitation of this release, \
         not a fault in the pool."
    } else {
        ""
    };
    anyhow::bail!(
        "the replayed state differs from the pool's: replayed commitment root {} next {} reserved \
         {} nullifier root {} next {} liability {}, pool {} {} {} {} {} {}.{hint} The previous \
         state is kept and the sync is incomplete.",
        hex::encode(fr_to_be(&have.commitment_root)),
        have.commitment_next_index,
        have.reserved_recovery_leaves,
        hex::encode(fr_to_be(&have.nullifier_root)),
        have.nullifier_next_index,
        have.native_liability,
        hex::encode(state.commitment_root),
        state.commitment_next_index,
        state.reserved_recovery_leaves,
        hex::encode(state.nullifier_root),
        state.nullifier_next_index,
        state.native_liability,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::{AccountStatus, HashUpdate, Serializable, UInt256};
    use contracts::shielded_pool::PoolConfig;

    fn pool() -> MsgAddressInt {
        "0:aa76950cf26cb74c1d1b1a977d17bd3c96c6c9f28cb259fca297cdc8d33429fe".parse().expect("pool")
    }

    struct Built {
        cell: Cell,
        hash: [u8; 32],
        lt: u64,
    }

    fn transaction(
        address: &MsgAddressInt,
        lt: u64,
        now: u32,
        prev: Option<&Built>,
        old_state: UInt256,
        new_state: UInt256,
    ) -> Built {
        let mut transaction = Transaction::with_address_and_status(
            address.address().clone(),
            AccountStatus::AccStateActive,
        );
        transaction.set_logical_time(lt);
        transaction.set_now(now);
        if let Some(prev) = prev {
            transaction.set_prev_trans_lt(prev.lt);
            transaction.set_prev_trans_hash(UInt256::from(prev.hash));
        }
        transaction
            .write_state_update(&HashUpdate::with_hashes(old_state, new_state))
            .expect("state update");
        let cell = transaction.serialize().expect("serialize");
        let hash = *cell.repr_hash().as_array();
        Built { cell, hash, lt }
    }

    fn state(n: u8) -> UInt256 {
        UInt256::from([n; 32])
    }

    /// Three transactions, each linked to the one before it.
    fn chain() -> (Built, Built, Built) {
        let first = transaction(&pool(), 10, 100, None, state(0), state(1));
        let second = transaction(&pool(), 20, 110, Some(&first), state(1), state(2));
        let third = transaction(&pool(), 30, 120, Some(&second), state(2), state(3));
        (first, second, third)
    }

    fn plain(built: &Built) -> Link {
        let transaction =
            Link::bound(built.cell.clone(), built.hash, built.lt, &pool()).expect("bound");
        Link::Plain { transaction, address: pool(), hash: built.hash }
    }

    #[test]
    fn a_linked_history_walks_back_to_its_first_transaction() {
        let (first, second, third) = chain();
        let head = plain(&third);
        let middle = head.previous(second.cell.clone()).expect("second");
        assert_eq!(middle.hash(), second.hash);
        let start = middle.previous(first.cell.clone()).expect("first");
        assert_eq!(start.hash(), first.hash);
        assert_eq!(
            start.transaction().prev_trans_lt(),
            0,
            "the first transaction has no earlier one"
        );
    }

    #[test]
    fn a_gap_a_repeat_and_a_wrong_hash_are_refused() {
        let (first, second, third) = chain();
        let head = plain(&third);
        // A page that skips the second transaction, or repeats the third.
        assert!(head.previous(first.cell.clone()).is_err(), "a gap");
        assert!(head.previous(third.cell.clone()).is_err(), "a repeated transaction");
        // The right position with the wrong bytes.
        let forged = transaction(&pool(), 20, 110, Some(&first), state(1), state(2));
        let mut other = forged;
        other.hash = second.hash;
        assert_eq!(
            other.cell.repr_hash().as_array(),
            &second.hash,
            "the same transaction hashes the same"
        );
        let forged = transaction(&pool(), 20, 111, Some(&first), state(1), state(2));
        assert!(head.previous(forged.cell).is_err(), "a transaction with another hash");
    }

    #[test]
    fn a_broken_state_chain_a_time_reversal_and_another_account_are_refused() {
        let (first, _, _) = chain();
        let broken = transaction(&pool(), 20, 110, Some(&first), state(1), state(7));
        let third = transaction(&pool(), 30, 120, Some(&broken), state(2), state(3));
        assert!(
            plain(&third).previous(broken.cell).is_err(),
            "post-state is not the next pre-state"
        );

        let late = transaction(&pool(), 20, 130, Some(&first), state(1), state(2));
        let third = transaction(&pool(), 30, 120, Some(&late), state(2), state(3));
        assert!(plain(&third).previous(late.cell).is_err(), "an earlier transaction dated later");

        let backwards = transaction(&pool(), 40, 110, Some(&first), state(1), state(2));
        let third = transaction(&pool(), 30, 120, Some(&backwards), state(2), state(3));
        assert!(
            plain(&third).previous(backwards.cell).is_err(),
            "a previous LT not below the current"
        );

        let elsewhere: MsgAddressInt =
            "0:0000000000000000000000000000000000000000000000000000000000000001"
                .parse()
                .expect("address");
        let foreign = transaction(&elsewhere, 20, 110, Some(&first), state(1), state(2));
        let third = transaction(&pool(), 30, 120, Some(&foreign), state(2), state(3));
        assert!(plain(&third).previous(foreign.cell).is_err(), "another account's transaction");
        assert!(
            Link::bound(third.cell.clone(), third.hash, third.lt + 1, &pool()).is_err(),
            "a head whose LT is not the transaction's"
        );
    }

    fn head_with(state: PoolState) -> Head {
        Head {
            verified: false,
            global_id: 3,
            last_lt: 0,
            last_hash: [0; 32],
            code_hash: [0; 32],
            state,
            gas: GasLimitsPrices::default(),
            checkpoint: None,
            block_gen_utime: 0,
            chain: ChainIdentity { source: "test".into(), root_hash: [0; 32], file_hash: [0; 32] },
            source: HeadSource::Rpc,
        }
    }

    fn genesis_state() -> PoolState {
        let checkpoint = Ledger::genesis().checkpoint();
        PoolState {
            commitment_root: fr_to_be(&checkpoint.commitment_root),
            commitment_next_index: 0,
            reserved_recovery_leaves: 0,
            nullifier_root: fr_to_be(&checkpoint.nullifier_root),
            nullifier_next_index: 1,
            last_anchor_epoch: u32::MAX,
            native_liability: 0,
            reserve_floor: 1,
            config: PoolConfig {
                profile_hash: [0; 32],
                poseidon_manifest_hash: [0; 32],
                groth16_vk_hash: [0; 32],
                withdrawal_fee: 1,
                denominations: vec![1],
            },
            verifying_key: vec![0; 1248],
        }
    }

    #[test]
    fn transactions_without_state_change_leave_the_replay_where_it_was() {
        let history = History {
            steps: vec![
                Step { lt: 1, hash: [1; 32], event: None },
                Step { lt: 2, hash: [2; 32], event: None },
            ],
        };
        let replay =
            replay(Ledger::genesis(), &history, &head_with(genesis_state())).expect("replay");
        assert_eq!((replay.applied, replay.skipped), (0, 2));
        assert_eq!(replay.ledger.checkpoint(), Ledger::genesis().checkpoint());
    }

    #[test]
    fn a_replay_that_misses_the_pools_state_is_refused_and_says_where() {
        let mut state = genesis_state();
        state.native_liability = 5;
        let history = History { steps: Vec::new() };
        let text = match replay(Ledger::genesis(), &history, &head_with(state)) {
            Ok(_) => panic!("a liability from nowhere was accepted"),
            Err(error) => error.to_string(),
        };
        assert!(text.contains("differs") && text.contains("previous state is kept"), "{text}");
        assert!(!text.contains("recovery bounces"), "no bounce, no bounce hint: {text}");
    }
}
