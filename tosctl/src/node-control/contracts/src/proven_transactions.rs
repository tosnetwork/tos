// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Bind untrusted transaction cells to authenticated account history. These
//! receipts prove ledger facts, not freshness, application intent or spendable
//! recipient balance. Account reads currently require active accounts.
use crate::proven_getters::ProvenAccountState;
use chain_block::{
    Cell, CellType, Deserializable, MsgAddressInt, TrComputePhase, Transaction, TransactionDescr,
};

pub struct ProvenTransaction {
    root: Cell,
    transaction: Transaction,
    address: MsgAddressInt,
    anchor_id: [u8; 32],
}

impl ProvenTransaction {
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
