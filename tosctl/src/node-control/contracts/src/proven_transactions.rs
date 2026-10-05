// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Bind untrusted transaction cells to authenticated account history. These
//! receipts prove ledger facts, not freshness, application intent or spendable
//! recipient balance. Account reads currently require active accounts.
use crate::proven_getters::ProvenAccountState;
use base64::Engine as _;
use chain_block::{
    Cell, CellType, Deserializable, MsgAddressInt, TrComputePhase, Transaction, TransactionDescr,
};
use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
use std::time::{Duration, Instant};

/// Locally approved payment fields, not values inferred from an RPC response.
/// Credit is the receiver's credit-phase amount, not its final spendable balance.
pub struct PaymentExpectation {
    pub recipient: MsgAddressInt,
    pub value: chain_block::CurrencyCollection,
    pub credited: chain_block::CurrencyCollection,
    pub bounce: bool,
    pub body: Option<Cell>,
    pub state_init: Option<chain_block::StateInit>,
}

pub struct ProvenTransaction {
    root: Cell,
    transaction: Transaction,
    address: MsgAddressInt,
    anchor_id: [u8; 32],
}

impl ProvenTransaction {
    /// Read-only JSON-RPC adapter. RPC metadata is not a trust source; the BOC
    /// must link to the proven account. One overall deadline includes failover,
    /// history traversal and decoding. Transport has its own 1 MiB body cap.
    pub async fn find_inbound_rpc(
        account: &ProvenAccountState,
        expected: &Cell,
        maximum: u32,
        timeout: Duration,
        rpc: &ClientJsonRpc,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !timeout.is_zero() && timeout <= Duration::from_secs(300),
            "invalid receipt lookup timeout"
        );
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| anyhow::anyhow!("receipt deadline overflow"))?;
        let lookup =
            Self::find_inbound(account, expected, maximum, |address, lt, hash| async move {
                let page = rpc
                    .get_transactions(
                        &address,
                        lt,
                        &base64::engine::general_purpose::STANDARD.encode(hash),
                        1,
                    )
                    .await?;
                anyhow::ensure!(
                    page.transactions.len() == 1,
                    "receipt RPC must return one transaction"
                );
                let raw = page
                    .transactions
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("receipt RPC transaction missing"))?;
                // Bound allocation before base64 decoding. Other RPC fields are
                // deliberately ignored; authenticated transaction fields prevail.
                anyhow::ensure!(raw.data.len() <= (1 << 20), "receipt BOC encoding too large");
                let bytes = base64::engine::general_purpose::STANDARD.decode(raw.data)?;
                let abort = || Instant::now() >= deadline;
                let root = chain_block::BocReader::new()
                    .set_abort(&abort)
                    .set_max_cell_depth(1024)
                    .read(&mut std::io::Cursor::new(bytes))?
                    .withdraw_single_root()?;
                anyhow::ensure!(Instant::now() < deadline, "receipt lookup deadline exceeded");
                Ok(root)
            });
        let result = tokio::time::timeout(timeout, lookup)
            .await
            .map_err(|_| anyhow::anyhow!("receipt lookup deadline exceeded"))??;
        anyhow::ensure!(Instant::now() < deadline, "receipt lookup deadline exceeded");
        Ok(result)
    }

    /// Fetch backwards from a proven head until the exact inbound message is
    /// found. The fetcher is untrusted: every returned cell is authenticated.
    /// A bounded miss is an error, never proof that a request was not executed.
    /// The caller must also bound transport time, response bytes and BOC decode
    /// resources. This operation does not broadcast or approve any message.
    pub async fn find_inbound<F, Fut>(
        account: &ProvenAccountState,
        expected: &Cell,
        maximum: u32,
        mut fetch: F,
    ) -> anyhow::Result<Self>
    where
        F: FnMut(MsgAddressInt, u64, [u8; 32]) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<Cell>>,
    {
        anyhow::ensure!((1..=1024).contains(&maximum), "invalid receipt history budget");
        let address = account
            .account()
            .get_addr()
            .ok_or_else(|| anyhow::anyhow!("proven account has no address"))?
            .clone();
        let mut lt = account.evidence().account.last_trans_lt;
        let mut hash = *account.last_transaction_hash();
        let mut current: Option<Self> = None;
        for _ in 0..maximum {
            anyhow::ensure!(lt > 0 && hash != [0; 32], "receipt history ended without message");
            let root = fetch(address.clone(), lt, hash).await?;
            let next = match current.as_ref() {
                Some(previous) => previous.previous(root)?,
                None => Self::latest(account, root)?,
            };
            if next
                .transaction
                .in_msg_cell()
                .is_some_and(|cell| cell.repr_hash() == expected.repr_hash())
            {
                return Ok(next);
            }
            lt = next.transaction.prev_trans_lt();
            hash = *next.transaction.prev_trans_hash().as_array();
            current = Some(next);
        }
        anyhow::bail!("receipt history budget exhausted without message")
    }

    /// Bind the latest transaction to the ShardAccount hash/LT proven by the
    /// native verifier, and its post-state to the proven raw Account root.
    pub fn latest(account: &ProvenAccountState, root: Cell) -> anyhow::Result<Self> {
        anyhow::ensure!(
            account.evidence().account.last_trans_lt > 0
                && account.last_transaction_hash() != &[0; 32],
            "account has no proven transaction"
        );
        let address = account
            .account()
            .get_addr()
            .ok_or_else(|| anyhow::anyhow!("proven account has no address"))?
            .clone();
        let result = Self::bound(
            root,
            *account.last_transaction_hash(),
            account.evidence().account.last_trans_lt,
            address,
            *account.anchor_id(),
        )?;
        anyhow::ensure!(
            result.transaction.now() <= account.evidence().account.gen_utime,
            "transaction is newer than account proof"
        );
        anyhow::ensure!(
            result.transaction.read_state_update()?.new_hash == account.root().repr_hash(),
            "transaction post-state differs from proven account"
        );
        Ok(result)
    }

    fn bound(
        root: Cell,
        expected_hash: [u8; 32],
        expected_lt: u64,
        address: MsgAddressInt,
        anchor_id: [u8; 32],
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            root.cell_type() == CellType::Ordinary && root.level() == 0,
            "ordinary transaction root required"
        );
        anyhow::ensure!(root.repr_hash().as_array() == &expected_hash, "transaction hash mismatch");
        let transaction = Transaction::construct_from_cell(root.clone())?;
        anyhow::ensure!(
            transaction.logical_time() == expected_lt,
            "transaction logical time mismatch"
        );
        anyhow::ensure!(
            transaction.account_id() == address.address(),
            "transaction account mismatch"
        );
        Ok(Self { root, transaction, address, anchor_id })
    }

    /// One backwards step through authenticated transaction and Account hashes.
    /// Callers fetching long histories must impose their own resource budget.
    pub fn previous(&self, root: Cell) -> anyhow::Result<Self> {
        let lt = self.transaction.prev_trans_lt();
        anyhow::ensure!(
            lt > 0 && lt < self.transaction.logical_time(),
            "invalid previous transaction time"
        );
        let previous = Self::bound(
            root,
            *self.transaction.prev_trans_hash().as_array(),
            lt,
            self.address.clone(),
            self.anchor_id,
        )?;
        anyhow::ensure!(
            previous.transaction.now() <= self.transaction.now(),
            "transaction history time reversal"
        );
        anyhow::ensure!(
            previous.transaction.read_state_update()?.new_hash
                == self.transaction.read_state_update()?.old_hash,
            "transaction state chain mismatch"
        );
        Ok(previous)
    }
    /// Authenticate a supplied pre-state preimage before interpreting which
    /// program/data actually executed. Current account code alone is insufficient.
    pub fn pre_account(&self, root: Cell) -> anyhow::Result<chain_block::Account> {
        anyhow::ensure!(
            root.repr_hash() == self.transaction.read_state_update()?.old_hash,
            "transaction pre-state hash mismatch"
        );
        let account = chain_block::Account::construct_from_cell(root)?;
        anyhow::ensure!(
            account.get_addr() == Some(&self.address),
            "transaction pre-state address mismatch"
        );
        Ok(account)
    }

    pub fn root(&self) -> &Cell {
        &self.root
    }
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    pub fn require_inbound(&self, expected: &Cell) -> anyhow::Result<()> {
        let actual = self
            .transaction
            .in_msg_cell()
            .ok_or_else(|| anyhow::anyhow!("transaction has no inbound message"))?;
        anyhow::ensure!(actual.repr_hash() == expected.repr_hash(), "inbound message mismatch");
        Ok(())
    }

    /// Strict whole-transaction success, including no silently skipped actions.
    /// This alone does not establish a downstream recipient's completion.
    pub fn require_complete_execution(&self) -> anyhow::Result<()> {
        let TransactionDescr::Ordinary(description) = self.transaction.read_description()? else {
            anyhow::bail!("ordinary transaction required");
        };
        anyhow::ensure!(
            !description.aborted && !description.destroyed && description.bounce.is_none(),
            "transaction aborted, destroyed or bounced"
        );
        let TrComputePhase::Vm(compute) = description.compute_ph else {
            anyhow::bail!("transaction compute was skipped");
        };
        anyhow::ensure!(
            compute.success && (compute.exit_code == 0 || compute.exit_code == 1),
            "transaction compute failed"
        );
        if let Some(action) = description.action {
            anyhow::ensure!(
                action.success
                    && action.valid
                    && !action.no_funds
                    && action.result_code == 0
                    && action.skipped_actions == 0,
                "transaction actions incomplete"
            );
        }
        Ok(())
    }

    /// Bind a payment to its originating request and locally approved message
    /// fields, then require exact delivery and the expected credit phase.
    /// Receiver execution may spend the credited value. Token balances and
    /// application state effects still require application-specific proofs.
    pub fn require_payment(
        &self,
        receiver: &Self,
        originating_request: &Cell,
        message_hash: &[u8; 32],
        expected: &PaymentExpectation,
    ) -> anyhow::Result<()> {
        self.require_inbound(originating_request)?;
        self.require_internal_delivery(receiver, message_hash)?;
        let message = receiver
            .transaction
            .read_in_msg()?
            .ok_or_else(|| anyhow::anyhow!("payment inbound missing"))?;
        let header =
            message.int_header().ok_or_else(|| anyhow::anyhow!("payment must be internal"))?;
        anyhow::ensure!(header.dst == expected.recipient, "payment recipient differs from intent");
        anyhow::ensure!(header.value == expected.value, "payment value differs from intent");
        anyhow::ensure!(
            !header.bounced && header.bounce == expected.bounce,
            "payment bounce flags differ from intent"
        );
        let body = message.body().cloned().map(|slice| slice.into_cell()).transpose()?;
        anyhow::ensure!(
            body.as_ref().map(|cell| cell.repr_hash())
                == expected.body.as_ref().map(|cell| cell.repr_hash()),
            "payment body differs from intent"
        );
        anyhow::ensure!(
            message.state_init() == expected.state_init.as_ref(),
            "payment state init differs from intent"
        );
        let TransactionDescr::Ordinary(description) = receiver.transaction.read_description()?
        else {
            anyhow::bail!("payment receiver must be ordinary");
        };
        let credit = description
            .credit_ph
            .ok_or_else(|| anyhow::anyhow!("payment receiver has no credit phase"))?;
        anyhow::ensure!(credit.credit == expected.credited, "payment credit differs from intent");
        Ok(())
    }

    /// Verify an actual internal message emitted here was processed by the
    /// receiver. Both executions must be complete. The original message cell
    /// is used, never a reserialization of parsed fields. Application outcomes
    /// (amounts, token credit, POP challenge, data changes) require further checks.
    pub fn require_internal_delivery(
        &self,
        receiver: &Self,
        message_hash: &[u8; 32],
    ) -> anyhow::Result<()> {
        anyhow::ensure!(self.anchor_id == receiver.anchor_id, "receipt trust anchors differ");
        self.require_complete_execution()?;
        receiver.require_complete_execution()?;
        let mut found = false;
        self.transaction.iterate_out_msgs_with_cells(|message, cell| {
            if cell.repr_hash().as_array() != message_hash {
                return Ok(true);
            }
            anyhow::ensure!(
                message.is_internal()
                    && message.src_ref() == Some(&self.address)
                    && message.dst_ref() == Some(&receiver.address),
                "delivery message parties mismatch"
            );
            receiver.require_inbound(&cell)?;
            anyhow::ensure!(
                receiver.transaction.logical_time() > self.transaction.logical_time(),
                "delivery logical time is not after send"
            );
            found = true;
            Ok(false)
        })?;
        anyhow::ensure!(found, "transaction did not emit expected message");
        Ok(())
    }
}
