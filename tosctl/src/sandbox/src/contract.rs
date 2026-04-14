/*
 * Copyright (C) 2025-2026 TOS Blockchain Teams.
 * Licensed under the GNU General Public License v3.0.
 */

//! [`ContractProvider`] trait and [`SandboxContract`] typed wrapper.
//!
//! Every smart contract deployed to the sandbox is represented as a
//! `SandboxContract<T>` where `T: ContractProvider`.  The provider carries
//! the address and initial [`StateInit`]; the wrapper adds high-level helpers
//! for querying balance, sending messages, and running get-methods.

use chain_block::{Account, Cell, MsgAddressInt, SliceData, StateInit};
use tos_vm::stack::StackItem;
use crate::{
    result::{SendResult, GetMethodResult},
    blockchain::Blockchain,
    error::SandboxResult,
    message_builder::MessageBuilder,
    treasury::Treasury,
};

// ---------------------------------------------------------------------------
// ContractProvider trait
// ---------------------------------------------------------------------------

/// Trait implemented by anything that can describe a contract deployed to the
/// sandbox (address + initial state).
pub trait ContractProvider {
    /// The on-chain address of the contract.
    fn address(&self) -> &MsgAddressInt;
    /// The [`StateInit`] used when the contract was deployed.
    fn state_init(&self) -> StateInit;
}

// ---------------------------------------------------------------------------
// SandboxContract<T>
// ---------------------------------------------------------------------------

/// Typed wrapper around a contract living on the sandbox blockchain.
///
/// `T` is a [`ContractProvider`] that carries the contract's address and
/// initial state.  `SandboxContract` adds convenience methods for
/// interacting with the contract through a [`Blockchain`] handle.
///
/// # Examples
///
/// ```ignore
/// let contract: SandboxContract<MyProvider> = bc.deploy(provider, &treasury, 1_000_000)?;
/// let balance = contract.get_balance(&bc);
/// let result  = contract.get(&bc, "seqno", vec![])?;
/// ```
pub struct SandboxContract<T: ContractProvider> {
    provider: T,
}

impl<T: ContractProvider> SandboxContract<T> {
    /// Wrap a provider in a `SandboxContract`.
    ///
    /// Normally called internally by [`Blockchain`] deployment helpers; you
    /// should not need to call this directly.
    pub(crate) fn new(provider: T) -> Self {
        Self { provider }
    }

    /// The on-chain address of the underlying contract.
    pub fn address(&self) -> &MsgAddressInt {
        self.provider.address()
    }

    /// Borrow the underlying [`ContractProvider`].
    pub fn provider(&self) -> &T {
        &self.provider
    }

    /// Look up the account balance in the blockchain state.
    ///
    /// Returns `0` if the account does not exist.
    pub fn get_balance(&self, bc: &Blockchain) -> u64 {
        bc.get_account(self.address())
            .and_then(|acc| {
                acc.balance()
                    .and_then(|cc| cc.coins.as_u64())
            })
            .unwrap_or(0)
    }

    /// Send an internal message **from** a [`Treasury`] **to** this contract.
    ///
    /// `value` is denominated in nano-coins.  An optional `body` cell is
    /// attached as the message body.
    ///
    /// The message is routed through
    /// [`Blockchain::send_message`](Blockchain::send_message) which executes
    /// the resulting transaction(s) and returns the collected results.
    pub fn send(
        &self,
        bc: &mut Blockchain,
        from: &Treasury,
        value: u64,
        body: Option<Cell>,
    ) -> SandboxResult<SendResult> {
        let msg = from.build_message(self.address(), value, true, body);
        bc.send_message(msg)
    }

    /// Send an external inbound message to this contract.
    ///
    /// External messages have no source address and carry no value.
    pub fn send_external(
        &self,
        bc: &mut Blockchain,
        body: Option<SliceData>,
    ) -> SandboxResult<SendResult> {
        let mut builder = MessageBuilder::external(self.address());
        if let Some(b) = body {
            builder = builder.body_slice(b);
        }
        let msg = builder.build();
        bc.send_message(msg)
    }

    /// Execute a get-method on this contract.
    ///
    /// `method` is the method name (e.g. `"seqno"`).  `args` are pushed onto
    /// the TVM stack before execution.
    pub fn get(
        &self,
        bc: &Blockchain,
        method: &str,
        args: Vec<StackItem>,
    ) -> SandboxResult<GetMethodResult> {
        bc.run_get_method(self.address(), method, args)
    }
}
