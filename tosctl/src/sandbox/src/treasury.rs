/*
 * Copyright (C) 2025-2026 TOS Blockchain Teams.
 * Licensed under the GNU General Public License v3.0.
 */

//! Pre-funded test wallet with an accept-all contract.
//!
//! A [`Treasury`] is a special account seeded with a large balance and a
//! trivial contract that unconditionally accepts all incoming messages.
//! It serves as the primary funding source in sandbox tests.

use chain_block::{
    Account, AccountId, AccountStorage, BuilderData, Cell, CurrencyCollection, GetRepresentationHash,
    Message, MsgAddressInt, StateInit, StorageInfo,
};
use crate::{
    error::{SandboxError, SandboxResult},
    message_builder::MessageBuilder,
};

/// Default balance assigned to every new treasury (1 billion coins).
const TREASURY_BALANCE: u64 = 1_000_000_000_000_000_000;

/// A pre-funded test wallet backed by an accept-all contract.
///
/// Treasuries are created via [`Blockchain::treasury`] and can send
/// arbitrary internal messages (including deploy messages with a
/// [`StateInit`]) to other contracts in the sandbox.
pub struct Treasury {
    address: MsgAddressInt,
    name: String,
}

impl Treasury {
    /// Create a new treasury and its matching [`Account`].
    ///
    /// The contract code is a single `ACCEPT` instruction compiled via
    /// `tos_assembler`.  The data cell stores a hash derived from `name` so
    /// that each treasury gets a unique address.
    ///
    /// Returns the `(Treasury, Account)` pair; the caller is responsible for
    /// inserting the account into the blockchain state.
    pub(crate) fn create(name: &str, workchain: i8) -> SandboxResult<(Self, Account)> {
        // 1. Compile the simplest possible contract: just ACCEPT.
        let code = tos_assembler::compile_code_to_cell("ACCEPT").map_err(|e| {
            SandboxError::Serialization(format!("failed to compile treasury code: {e}"))
        })?;

        // 2. Build a data cell containing a hash of the treasury name so that
        //    each treasury gets a distinct StateInit (and therefore a distinct
        //    address).
        let name_hash = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            name.hash(&mut hasher);
            hasher.finish()
        };
        let data = {
            let mut builder = BuilderData::new();
            builder
                .append_raw(&name_hash.to_be_bytes(), 64)
                .map_err(|e| SandboxError::Serialization(format!("data cell: {e}")))?;
            builder
                .into_cell()
                .map_err(|e| SandboxError::Serialization(format!("data cell finalize: {e}")))?
        };

        // 3. Build StateInit
        let state_init = StateInit::with_code_and_data(code, data);

        // 4. Compute address = hash(StateInit)
        let si_hash = GetRepresentationHash::hash(&state_init)
            .map_err(|e| SandboxError::Serialization(format!("StateInit hash: {e}")))?;
        let account_id: AccountId = si_hash.into();
        let address = MsgAddressInt::standard(workchain, account_id);

        // 5. Create an active account with a large balance
        let account = Account::with_storage(
            &address,
            &StorageInfo::with_values(0, None),
            &AccountStorage::active(
                0,
                CurrencyCollection::with_coins(TREASURY_BALANCE),
                state_init,
            ),
        );

        Ok((Treasury { address, name: name.to_owned() }, account))
    }

    /// The on-chain address of this treasury.
    pub fn address(&self) -> &MsgAddressInt {
        &self.address
    }

    /// The human-readable name given at creation time.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Build and return an internal message from this treasury to `to`.
    ///
    /// The message is **not** sent automatically; use
    /// [`Blockchain::send_message`](crate::blockchain::Blockchain::send_message)
    /// to execute it.
    pub fn build_message(
        &self,
        to: &MsgAddressInt,
        value: u64,
        bounce: bool,
        body: Option<Cell>,
    ) -> Message {
        let mut builder = MessageBuilder::internal(&self.address, to, value).bounce(bounce);
        if let Some(b) = body {
            builder = builder.body(b);
        }
        builder.build()
    }

    /// Build an internal deploy message (with [`StateInit`] attached).
    pub fn build_deploy_message(
        &self,
        to: &MsgAddressInt,
        value: u64,
        bounce: bool,
        body: Option<Cell>,
        state_init: StateInit,
    ) -> Message {
        let mut builder = MessageBuilder::internal(&self.address, to, value)
            .bounce(bounce)
            .state_init(state_init);
        if let Some(b) = body {
            builder = builder.body(b);
        }
        builder.build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn treasury_create_produces_valid_account() {
        let (treasury, account) = Treasury::create("test-wallet", 0).expect("create failed");

        // Address should be non-default
        assert_ne!(*treasury.address(), MsgAddressInt::default());
        assert_eq!(treasury.name(), "test-wallet");

        // Account should have the expected balance
        let balance = account.balance().expect("account should have balance");
        assert_eq!(balance.coins.as_u64(), Some(TREASURY_BALANCE));
    }

    #[test]
    fn different_names_yield_different_addresses() {
        let (t1, _) = Treasury::create("alice", 0).unwrap();
        let (t2, _) = Treasury::create("bob", 0).unwrap();
        assert_ne!(t1.address(), t2.address());
    }
}
