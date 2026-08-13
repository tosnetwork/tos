/*
 * Copyright (C) 2025-2026 TOS Blockchain Teams.
 * Licensed under the GNU General Public License v3.0.
 */

//! Core [`Blockchain`] struct — a local, in-process blockchain simulator.
//!
//! Manages a collection of accounts in a [`HashMap`], processes messages by
//! invoking the TOS executor, and routes internal output messages to their
//! destinations in a BFS loop until all cascading transactions settle.

use std::collections::{HashMap, VecDeque};
use std::mem;

use chain_block::{
    tos_method_id, Account, ConfigParams, CurrencyCollection, Deserializable, McStateExtra,
    MerkleProof, Message, MsgAddressInt, Serializable, ShardIdent, ShardStateUnsplit, Transaction,
};
use tos_executor::{
    BlockchainConfig, ExecuteParams, OrdinaryTransactionExecutor, TransactionExecutor,
};
use tos_vm::{
    executor::{gas::gas_state::Gas, Engine},
    stack::{savelist::SaveList, Stack, StackItem},
    SmartContractInfo,
};

use crate::{
    error::{SandboxError, SandboxResult},
    result::{GetMethodResult, SendResult},
    snapshot::BlockchainSnapshot,
    treasury::Treasury,
};

/// Default block unix-time used by the sandbox (approximately 2023-11-15).
const DEFAULT_BLOCK_UNIXTIME: u32 = 1_700_000_000;

/// Default starting logical time, matching executor test constants.
const DEFAULT_BLOCK_LT: u64 = 2_000_000_000;

/// Default maximum message routing depth (BFS iterations).
const DEFAULT_MAX_MESSAGE_DEPTH: usize = 256;

/// A local, single-process blockchain simulator.
///
/// [`Blockchain`] holds all account states and configuration needed to execute
/// transactions.  Messages are processed one-by-one; internal output messages
/// produced by a transaction are automatically enqueued and executed in BFS
/// order until all cascading transactions are completed or the depth limit is
/// reached.
///
/// # Example
/// ```ignore
/// let mut bc = Blockchain::new()?;
/// let treasury = bc.treasury("deployer", 1_000_000_000)?;
/// let msg = treasury.build_message(&contract_addr, 100_000_000, false, None);
/// let result = bc.send_message(msg)?;
/// result.expect_success();
/// ```
pub struct Blockchain {
    accounts: HashMap<String, Account>,
    config: BlockchainConfig,
    mc_state_cell: chain_block::Cell,
    next_lt: u64,
    block_unixtime: u32,
    max_message_depth: usize,
    workchain: i8,
    transaction_log: Vec<(MsgAddressInt, Transaction)>,
}

impl Blockchain {
    // ------------------------------------------------------------------
    // Constructors
    // ------------------------------------------------------------------

    /// Create a new [`Blockchain`] with the default blockchain configuration.
    ///
    /// Uses `BlockchainConfig::default()` which provides sensible gas prices,
    /// forwarding fees, and storage parameters suitable for testing.
    pub fn new() -> SandboxResult<Self> {
        let config = BlockchainConfig::default();
        let mc_state_cell = Self::build_mc_state_cell(config.raw_config())?;
        Ok(Self {
            accounts: HashMap::new(),
            config,
            mc_state_cell,
            next_lt: DEFAULT_BLOCK_LT,
            block_unixtime: DEFAULT_BLOCK_UNIXTIME,
            max_message_depth: DEFAULT_MAX_MESSAGE_DEPTH,
            workchain: 0,
            transaction_log: Vec::new(),
        })
    }

    /// Create a new [`Blockchain`] with a custom [`ConfigParams`].
    pub fn with_config(config: ConfigParams) -> SandboxResult<Self> {
        let bc_config = BlockchainConfig::with_config(config).map_err(|e| {
            SandboxError::ConfigError(format!("failed to create BlockchainConfig: {e}"))
        })?;
        let mc_state_cell = Self::build_mc_state_cell(bc_config.raw_config())?;
        Ok(Self {
            accounts: HashMap::new(),
            config: bc_config,
            mc_state_cell,
            next_lt: DEFAULT_BLOCK_LT,
            block_unixtime: DEFAULT_BLOCK_UNIXTIME,
            max_message_depth: DEFAULT_MAX_MESSAGE_DEPTH,
            workchain: 0,
            transaction_log: Vec::new(),
        })
    }

    // ------------------------------------------------------------------
    // Account management
    // ------------------------------------------------------------------

    /// Create a pre-funded treasury account.
    ///
    /// A treasury is a special account with a trivially simple contract
    /// (single `ACCEPT` instruction) and a large balance.  It serves as the
    /// primary funding source in sandbox tests.
    ///
    /// The `balance` parameter specifies additional coins to add.  If you
    /// only need the default treasury balance, pass `0`.
    /// Override the workchain used for treasuries created after this call.
    ///
    /// The default sandbox config carries no workchain descriptors, so
    /// action-phase sends to basechain destinations are rejected with
    /// action code 36; masterchain (`-1`) destinations skip that check.
    pub fn set_workchain(&mut self, workchain: i8) {
        self.workchain = workchain;
    }

    pub fn treasury(&mut self, name: &str, balance: u64) -> SandboxResult<Treasury> {
        let (treasury, mut account) = Treasury::create(name, self.workchain)?;

        // If the caller provided a non-zero balance override, rebuild the
        // account with that balance instead.
        if balance > 0 {
            // Replace the balance on the existing account.
            if let Some(bal) = account.balance().cloned() {
                let _ = bal; // drop old
            }
            // The simplest approach: create a fresh account with the requested
            // balance.  Treasury::create already built the StateInit we need.
            let state_init = account
                .state_init()
                .cloned()
                .ok_or_else(|| SandboxError::Serialization("treasury has no StateInit".into()))?;
            account = Account::active(
                treasury.address().clone(),
                CurrencyCollection::with_coins(balance),
                0,
                self.block_unixtime,
                state_init,
                chain_block::DICT_HASH_MIN_CELLS,
            )
            .map_err(|e| SandboxError::Serialization(format!("account creation: {e}")))?;
        }

        self.accounts.insert(treasury.address().to_string(), account);
        Ok(treasury)
    }

    /// Insert or replace an account at the given address.
    pub fn set_account(&mut self, address: MsgAddressInt, account: Account) {
        self.accounts.insert(address.to_string(), account);
    }

    /// Look up an account by address.
    pub fn get_account(&self, address: &MsgAddressInt) -> Option<&Account> {
        self.accounts.get(&address.to_string())
    }

    // ------------------------------------------------------------------
    // Block time / logical time accessors
    // ------------------------------------------------------------------

    /// Current block unix-time used for transaction execution.
    pub fn now(&self) -> u32 {
        self.block_unixtime
    }

    /// Set the block unix-time.  All subsequent transactions will use this
    /// value in their `now` field.
    pub fn set_now(&mut self, t: u32) {
        self.block_unixtime = t;
    }

    /// Current logical time counter.
    pub fn lt(&self) -> u64 {
        self.next_lt
    }

    // ------------------------------------------------------------------
    // Snapshots
    // ------------------------------------------------------------------

    /// Take a snapshot of the current blockchain state.
    ///
    /// The snapshot includes all accounts, the logical time, block unix-time,
    /// and the transaction log.  It can be restored later with [`restore`].
    pub fn snapshot(&self) -> BlockchainSnapshot {
        BlockchainSnapshot {
            accounts: self.accounts.clone(),
            next_lt: self.next_lt,
            block_unixtime: self.block_unixtime,
            transaction_log: self.transaction_log.clone(),
        }
    }

    /// Restore a previously taken snapshot, replacing the current state.
    pub fn restore(&mut self, snap: BlockchainSnapshot) {
        self.accounts = snap.accounts;
        self.next_lt = snap.next_lt;
        self.block_unixtime = snap.block_unixtime;
        self.transaction_log = snap.transaction_log;
    }

    // ------------------------------------------------------------------
    // Message execution
    // ------------------------------------------------------------------

    /// Send a message into the blockchain and execute all resulting
    /// transactions.
    ///
    /// The message is placed into a BFS queue.  Each transaction may produce
    /// output messages; internal output messages are enqueued for further
    /// processing while external outbound messages are collected separately.
    ///
    /// Returns a [`SendResult`] containing every transaction produced in the
    /// cascade, plus any external outbound messages.
    ///
    /// # Errors
    /// - [`SandboxError::MaxDepthExceeded`] if the total number of
    ///   transactions exceeds `max_message_depth`.
    /// - [`SandboxError::ExecutionFailed`] if the executor fails.
    pub fn send_message(&mut self, msg: Message) -> SandboxResult<SendResult> {
        let mut queue: VecDeque<Message> = VecDeque::new();
        queue.push_back(msg);

        let mut all_txs: Vec<(MsgAddressInt, Transaction)> = Vec::new();
        let mut ext_outs: Vec<Message> = Vec::new();

        while let Some(m) = queue.pop_front() {
            if all_txs.len() >= self.max_message_depth {
                return Err(SandboxError::MaxDepthExceeded(self.max_message_depth));
            }

            let (addr, tx, outs) = self.execute_one(m)?;
            self.transaction_log.push((addr.clone(), tx.clone()));
            all_txs.push((addr, tx));

            for out in outs {
                if out.is_internal() {
                    queue.push_back(out);
                } else {
                    ext_outs.push(out);
                }
            }
        }

        Ok(SendResult { transactions: all_txs, external_out_messages: ext_outs })
    }

    /// Execute a single message against its destination account.
    fn execute_one(
        &mut self,
        msg: Message,
    ) -> SandboxResult<(MsgAddressInt, Transaction, Vec<Message>)> {
        // 1. Determine destination address.
        let addr = msg.dst().ok_or_else(|| {
            SandboxError::InvalidMessage("message has no destination address".into())
        })?;

        // 2. Look up or create a default (uninit) account.
        let addr_key = addr.to_string();
        let mut account = self.accounts.get(&addr_key).cloned().unwrap_or_default();

        // 3. Serialize message to a Cell.
        let msg_cell = msg.serialize().map_err(|e| {
            SandboxError::Serialization(format!("failed to serialize message: {e}"))
        })?;

        // 4. Build executor and params.
        let executor = OrdinaryTransactionExecutor::new(self.config.clone());
        let params = self.execute_params();

        // 5. Execute.
        let transaction = executor
            .execute_with_params(Some(msg_cell), &mut account, params)
            .map_err(|e| SandboxError::ExecutionFailed(e.into()))?;

        // 6. Collect output messages.
        let mut out_messages: Vec<Message> = Vec::new();
        transaction
            .iterate_out_msgs(|out_msg| {
                out_messages.push(out_msg);
                Ok(true)
            })
            .map_err(|e| {
                SandboxError::Serialization(format!("failed to iterate out messages: {e}"))
            })?;

        // 7. Store the updated account back.
        self.accounts.insert(addr_key, account);

        // 8. Advance logical time past the transaction's lt.
        let tx_lt = transaction.logical_time();
        if tx_lt >= self.next_lt {
            self.next_lt = tx_lt + 1;
        }

        Ok((addr, transaction, out_messages))
    }

    // ------------------------------------------------------------------
    // Get-methods
    // ------------------------------------------------------------------

    /// Run a named get-method on a contract.
    ///
    /// The method name is hashed using the standard TOS method-ID algorithm
    /// (`crc16(name) | 0x10000`).  Additional arguments are passed as a
    /// [`Vec<StackItem>`].
    ///
    /// # Errors
    /// - [`SandboxError::AccountNotFound`] if no account exists at `address`.
    /// - [`SandboxError::NoCode`] if the account has no contract code.
    pub fn run_get_method(
        &self,
        address: &MsgAddressInt,
        method: &str,
        args: Vec<StackItem>,
    ) -> SandboxResult<GetMethodResult> {
        let account = self
            .get_account(address)
            .ok_or_else(|| SandboxError::AccountNotFound(address.to_string()))?;

        let code = account.get_code().ok_or(SandboxError::NoCode)?;
        let data = account.get_data().unwrap_or_default();

        let method_id = tos_method_id(method);

        // Unwrap the MerkleProof to get the raw state cell.
        let mc_proof = MerkleProof::construct_from_cell(self.mc_state_cell.clone())
            .map_err(|e| SandboxError::ExecutionFailed(e.into()))?;
        let mc_state_root = mc_proof.proof.clone();

        // Build SmartContractInfo from the account and the raw mc state.
        let mut smc_info =
            SmartContractInfo::with_params(Some(account), None, Some(mc_state_root.clone()))
                .map_err(|e| SandboxError::ExecutionFailed(e.into()))?;

        smc_info.unix_time = self.block_unixtime;
        smc_info.block_lt = self.next_lt;
        smc_info.trans_lt = self.next_lt;

        // Build the VM stack: [args..., method_id].
        let mut storage: Vec<StackItem> = args;
        storage.push(StackItem::int(method_id));
        let stack = Stack::with_storage(storage);

        // Set up control registers.
        let mut ctrls = SaveList::new();
        ctrls
            .put(7, smc_info.as_temp_data_item())
            .map_err(|e| SandboxError::ExecutionFailed(e.into()))?;
        ctrls.put(4, StackItem::Cell(data)).map_err(|e| SandboxError::ExecutionFailed(e.into()))?;

        // Gas: generous limit for get-methods.
        let gas = Gas::new(1_000_000, 0, 1_000_000, 1_000_000);

        // Libraries from the account and mc state.
        let mc_state = ShardStateUnsplit::construct_from_cell(mc_state_root)
            .map_err(|e| SandboxError::ExecutionFailed(e.into()))?;

        let libraries = vec![account.libraries().inner(), mc_state.libraries().clone().inner()];

        let caps = smc_info.config_params.capabilities();
        let mut vm = Engine::with_capabilities(caps)
            .setup_checked(code, ctrls, stack, gas, libraries)
            .map_err(|e| SandboxError::ExecutionFailed(e.into()))?;

        let block_version =
            smc_info.config_params.get_global_version().map(|gv| gv.version).unwrap_or(0);
        vm.set_block_version(block_version);

        let result = vm.execute();
        let mut result_stack = mem::take(&mut vm.withdraw_stack().storage);

        let exit_code = match result {
            Ok(code) => code,
            Err(err) => {
                result_stack.pop();
                log::debug!(target: "sandbox", "get-method VM exception: {}", err);
                tos_vm::error::tvm_exception_or_custom_code(&err)
            }
        };

        Ok(GetMethodResult { exit_code, gas_used: vm.gas_used(), stack: result_stack })
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// Build [`ExecuteParams`] from the current blockchain state.
    fn execute_params(&self) -> ExecuteParams {
        ExecuteParams {
            block_unixtime: self.block_unixtime,
            block_lt: self.next_lt - self.next_lt % 1_000_000,
            last_tr_lt: self.next_lt,
            ..ExecuteParams::default()
        }
    }

    /// Build a minimal masterchain state proof cell from [`ConfigParams`].
    ///
    /// This follows the pattern from the executor test utilities: create a
    /// `ShardStateUnsplit` for the masterchain, populate `McStateExtra` with
    /// the config and fake previous-block references, then wrap it in a
    /// `MerkleProof`.
    fn build_mc_state_cell(config: &ConfigParams) -> SandboxResult<chain_block::Cell> {
        let mc_seqno: u32 = 1_234_567;

        let mut mc_state = ShardStateUnsplit::with_ident(ShardIdent::masterchain());
        mc_state.set_seq_no(mc_seqno);
        mc_state.set_global_id(42);

        let mut extra = McStateExtra { config: config.clone(), ..Default::default() };

        // Populate fake previous-block references so that prev_blocks_info
        // lookups inside the VM succeed.
        for i in 0..16 {
            extra
                .prev_blocks
                .add_fake_id(mc_seqno - i, false)
                .map_err(|e| SandboxError::ConfigError(format!("prev_blocks: {e}")))?;
            extra
                .prev_blocks
                .add_fake_id((mc_seqno / 100) * 100 - i * 100, false)
                .map_err(|e| SandboxError::ConfigError(format!("prev_blocks_100: {e}")))?;
        }
        extra
            .prev_blocks
            .add_fake_id(0, true)
            .map_err(|e| SandboxError::ConfigError(format!("prev_blocks genesis: {e}")))?;
        extra
            .prev_blocks
            .add_fake_id(mc_seqno - 30, true)
            .map_err(|e| SandboxError::ConfigError(format!("prev_blocks key: {e}")))?;

        extra.last_key_block =
            extra.prev_blocks.get_prev_key_block(mc_seqno).ok().flatten().map(|r| r.into());

        mc_state
            .write_custom(Some(&extra))
            .map_err(|e| SandboxError::ConfigError(format!("write_custom: {e}")))?;

        // Wrap the state in a MerkleProof.
        let proof_cell = mc_state
            .serialize()
            .map_err(|e| SandboxError::Serialization(format!("mc state serialize: {e}")))?;
        let merkle_proof =
            MerkleProof { hash: proof_cell.hash(0), depth: proof_cell.depth(0), proof: proof_cell };
        merkle_proof
            .serialize()
            .map_err(|e| SandboxError::Serialization(format!("merkle proof serialize: {e}")))
    }
}
