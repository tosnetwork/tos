/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The token bridge's mint and burn across three contracts, with real action
//! and bounce phases.
//!
//! A mint is bridge -> minter -> wallet and a burn is wallet -> minter ->
//! bridge, and nothing makes either atomic. These tests deliver every message
//! through the executor, stop between transactions where a failure can occur,
//! cause that failure the way the chain would, and check that the outcome
//! reaches the contract that has to act on it.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use chain_block::{
    BuilderData, Cell, Coins, ConfigParamEnum, Deserializable, IBitstring, Message, MsgAddressExt,
    MsgAddressInt, Serializable, SliceData, StateInit, TrBouncePhase, TrComputePhase, Transaction,
    TransactionDescr, UInt256,
};
use tos_sandbox::{Blockchain, MessageBuilder, Treasury};
use tos_vm::stack::StackItem;
use tos_vm::stack::integer::IntegerData;

const TOS: u64 = 1_000_000_000;
const MINT_FEE: u64 = 2 * TOS;
const BURN_FEE: u64 = 2 * TOS;
const WALLET_MIN_STORAGE: u64 = TOS / 20;
const MINTER_MIN_STORAGE: u64 = TOS / 10;
const CHAIN_ID: u32 = 1;
const CONFIG_PARAM: u32 = 79;

const OP_EXECUTE_VOTING: u32 = 4;
const OP_PAY_SWAP: u32 = 8;
const OP_EXCESSES: u32 = 0xd532_76db;
const OP_BURN: u32 = 0x595f_07bc;
const OP_TRANSFER: u32 = 0x0f8a_7ea5;
const OP_INTERNAL_TRANSFER: u32 = 0x178d_4519;
const OP_MINT: u32 = 21;
const OP_MINT_CREDITED: u32 = 22;
const OP_MINT_COMPLETED: u32 = 23;
const OP_MINT_FAILED: u32 = 24;
const OP_RETRY_MINT: u32 = 25;
const OP_BURN_RECORDED: u32 = 26;
const OP_RETRY_REFUND: u32 = 27;
const OP_BURN_NOTIFICATION: u32 = 0x7bdd_97de;

const LOG_BURN: u32 = 0xc047_0ccf;
const LOG_MINT_ON_MINTER: u32 = 0xc066_0ccf;
const LOG_MINT_FAILED: u32 = 0xc088_0ccf;
const LOG_BURN_REFUND_FAILED: u32 = 0xc099_0ccf;

const MINT_IN_FLIGHT: i128 = 0;
const MINT_FAILED: i128 = 1;
const BURN_REFUND_FAILED: i128 = 2;
const NOTHING: i128 = -1;

const ERR_ORACLES_SENDER: i32 = 400;
const ERR_MINTER_NOT_SENDER: i32 = 402;
const ERR_BRIDGE_NOT_SENDER: i32 = 403;
const ERR_MINT_FEE_NOT_MATCHED: i32 = 407;
const ERR_CREDIT_UNDERFUNDED: i32 = 395;
const ERR_NOTHING_TO_RETRY: i32 = 393;
const ERR_NOT_ENOUGH_FUNDS: i32 = 706;
const ERR_OPERATION_SUSPENDED: i32 = 704;
const STATE_SWAPS_SUSPENDED: u8 = 2;
const ERR_BURN_UNDERFUNDED: i32 = 394;
const ERR_MINT_IDS_EXHAUSTED: i32 = 391;
const ERR_BURN_IDS_EXHAUSTED: i32 = 390;

const MAX_SUPPLY: u128 = (1 << 120) - 1;

/// Where to record every transaction for replay in the native engine, if set.
fn trace_dir() -> Option<PathBuf> {
    std::env::var_os("TOKEN_BRIDGE_TRACE_DIR").map(PathBuf::from)
}

fn repo_root() -> PathBuf {
    std::env::var("TOS_ROOT").map(PathBuf::from).unwrap_or_else(|_| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("repository root above the contracts crate")
            .to_path_buf()
    })
}

fn contracts_dir() -> PathBuf {
    repo_root().join("crosschain/token-bridge/tvm/contracts")
}

struct Codes {
    bridge: Cell,
    minter: Cell,
    wallet: Cell,
}

/// The three contracts, compiled from source for the Ethereum parameters. The
/// sources include `params.fc`, which lives per network, so they are staged
/// the way the bridge's own build stages them.
fn codes() -> &'static Codes {
    static CODES: OnceLock<Codes> = OnceLock::new();
    CODES.get_or_init(|| {
        let stage =
            std::env::temp_dir().join(format!("tos-token-bridge-sandbox-{}", std::process::id()));
        std::fs::create_dir_all(&stage).expect("a staging directory");
        let mut staged = 0;
        for entry in std::fs::read_dir(contracts_dir()).expect("the bridge contracts") {
            let path = entry.expect("a directory entry").path();
            if path.extension().is_some_and(|ext| ext == "fc") {
                std::fs::copy(&path, stage.join(path.file_name().expect("a file name")))
                    .expect("a staged source");
                staged += 1;
            }
        }
        assert!(staged > 5, "found only {staged} bridge sources under {:?}", contracts_dir());
        std::fs::copy(
            repo_root().join("crosschain/token-bridge/tvm/params/ethereum.fc"),
            stage.join("params.fc"),
        )
        .expect("the network parameters");
        let compile = |name: &str| {
            tos_sandbox::compile_func(&[stage.join(name)])
                .unwrap_or_else(|e| panic!("{name} compiles: {e}"))
        };
        Codes {
            bridge: compile("jetton-bridge.fc"),
            minter: compile("jetton-minter.fc"),
            wallet: compile("jetton-wallet.fc"),
        }
    })
}

/// A gas constant as the contracts declare it, so the measurement below is held
/// against the number the fee budget is priced from rather than a copy of it.
fn declared_gas(name: &str) -> u64 {
    let source =
        std::fs::read_to_string(contracts_dir().join("settlement.fc")).expect("settlement.fc");
    let prefix = format!("const int {name} = ");
    let line = source
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("settlement.fc declares {name}"));
    line[prefix.len()..].trim_end_matches(';').trim().parse().expect("a gas constant")
}

fn cell(build: impl FnOnce(&mut BuilderData)) -> Cell {
    let mut b = BuilderData::new();
    build(&mut b);
    b.into_cell().expect("a cell")
}

fn coins(b: &mut BuilderData, amount: u128) {
    amount.to_string().parse::<Coins>().expect("coins").write_to(b).expect("coins");
}

fn account_hash(addr: &MsgAddressInt) -> Vec<u8> {
    addr.address().get_bytestring(0)
}

fn wrapped_token_data() -> Cell {
    cell(|b| {
        b.append_u32(CHAIN_ID).unwrap();
        b.append_raw(&[0x5a; 20], 160).unwrap();
        b.append_u8(18).unwrap();
    })
}

fn swap_key(ext_chain_hash: &[u8; 32], internal_index: i16) -> Vec<u8> {
    cell(|b| {
        b.append_raw(ext_chain_hash, 256).unwrap();
        b.append_i16(internal_index).unwrap();
    })
    .repr_hash()
    .as_slice()
    .to_vec()
}

fn int_arg(value: u64) -> StackItem {
    StackItem::integer(IntegerData::from_u64(value))
}

/// The bridge, a minter for one wrapped token, and the accounts around them.
struct Bridge {
    bc: Blockchain,
    oracles: Treasury,
    deployer: Treasury,
    user: Treasury,
    stranger: Treasury,
    bridge: MsgAddressInt,
    minter: MsgAddressInt,
    queue: VecDeque<Message>,
    delivered: Vec<(MsgAddressInt, Transaction)>,
    logs: Vec<(MsgAddressInt, u32, Message)>,
    next_index: i16,
    burn_fee: u64,
    traced: usize,
}

#[derive(Clone, Copy)]
struct Prices {
    mint_fee: u64,
    burn_fee: u64,
    wallet_min_storage: u64,
    minter_min_storage: u64,
    state_flags: u8,
}

impl Default for Prices {
    fn default() -> Self {
        Self {
            mint_fee: MINT_FEE,
            burn_fee: BURN_FEE,
            wallet_min_storage: WALLET_MIN_STORAGE,
            minter_min_storage: MINTER_MIN_STORAGE,
            state_flags: 0,
        }
    }
}

impl Bridge {
    fn new() -> Self {
        let mut bc = Blockchain::with_global_version_and_base_workchain(14).expect("a chain");
        bc.set_workchain(-1);
        let oracles = bc.treasury("token-bridge-oracles", 1_000 * TOS).expect("oracles");
        let deployer = bc.treasury("token-bridge-deployer", 1_000 * TOS).expect("deployer");
        bc.set_workchain(0);
        let user = bc.treasury("token-bridge-user", 1_000 * TOS).expect("user");
        let stranger = bc.treasury("token-bridge-stranger", 1_000 * TOS).expect("stranger");

        let collector =
            MsgAddressInt::with_params(0, UInt256::from([0x42; 32])).expect("collector");
        let data = cell(|b| {
            collector.write_to(b).unwrap();
            b.checked_append_reference(codes().minter.clone()).unwrap();
            b.checked_append_reference(codes().wallet.clone()).unwrap();
            b.append_bit_zero().unwrap(); // paid_swaps
            b.append_u64(0).unwrap(); // next_mint_id
            b.append_bit_zero().unwrap(); // pending_mints
        });
        let init = StateInit::with_code_and_data(codes().bridge.clone(), data);
        let bridge_hash = init.serialize().expect("a state init").repr_hash();
        let bridge = MsgAddressInt::with_params(-1, bridge_hash).expect("the bridge address");

        let mut this = Self {
            bc,
            oracles,
            deployer,
            user,
            stranger,
            bridge: bridge.clone(),
            minter: bridge.clone(),
            queue: VecDeque::new(),
            delivered: Vec::new(),
            logs: Vec::new(),
            next_index: 1,
            burn_fee: BURN_FEE,
            traced: 0,
        };
        this.configure(&bridge, Prices::default());

        let deploy = MessageBuilder::internal(this.deployer.address(), &bridge, 50 * TOS)
            .bounce(false)
            .state_init(init)
            .body(cell(|b| {
                b.append_u32(OP_EXCESSES).unwrap().append_u64(0).unwrap();
            }))
            .build();
        this.send(deploy);
        assert!(this.bc.get_account(&bridge).and_then(|a| a.get_code()).is_some(), "deployed");

        let minter =
            this.get(&bridge, "get_minter_address", vec![StackItem::cell(wrapped_token_data())]);
        this.minter = MsgAddressInt::construct_from(&mut minter.slice_at(0)).expect("a minter");
        this
    }

    /// ConfigParam 79, naming `bridge` as the bridge.
    fn configure(&mut self, bridge: &MsgAddressInt, prices: Prices) {
        let oracles = self.oracles.address().clone();
        let param = cell(|b| {
            b.append_u8(0).unwrap();
            b.append_raw(&account_hash(bridge), 256).unwrap();
            b.append_raw(&account_hash(&oracles), 256).unwrap();
            b.append_bit_zero().unwrap(); // oracle keys, unused on this side
            b.append_u8(prices.state_flags).unwrap();
            b.checked_append_reference(cell(|p| {
                coins(p, prices.burn_fee.into());
                coins(p, prices.mint_fee.into());
                coins(p, prices.wallet_min_storage.into());
                coins(p, (TOS / 50).into());
                coins(p, prices.minter_min_storage.into());
                coins(p, (TOS / 100).into());
            }))
            .unwrap();
        });
        self.burn_fee = prices.burn_fee;
        let mut config = self.bc.config_params().clone();
        config.set_config(ConfigParamEnum::ConfigParamAny(CONFIG_PARAM, param)).expect("param 79");
        // A configuration the sandbox rebuilds needs the fundamental-contract list.
        if config.config(31).expect("param 31").is_none() {
            config
                .set_config(ConfigParamEnum::ConfigParam31(chain_block::ConfigParam31 {
                    fundamental_smc_addr: chain_block::FundamentalSmcAddresses::default(),
                }))
                .expect("the fundamental contracts are listed");
        }
        self.bc.set_config(config).expect("the chain adopts it");
    }

    fn set_basechain_gas_price(&mut self, gas_price: u64) {
        let mut config = self.bc.config_params().clone();
        let mut prices = config.gas_prices(false).expect("basechain gas prices");
        prices.gas_price = gas_price;
        config.set_config(ConfigParamEnum::ConfigParam21(prices)).expect("param 21");
        self.bc.set_config(config).expect("the chain adopts it");
    }

    fn basechain_gas_price(&self) -> u64 {
        self.bc.config_params().gas_prices(false).expect("basechain gas prices").gas_price
    }

    // ---- delivery ----

    fn deliver_one(&mut self) -> (MsgAddressInt, Transaction) {
        let msg = self.queue.pop_front().expect("a message to deliver");
        let before = trace_dir().map(|dir| {
            let dst = msg.dst().expect("a destination");
            (dir, msg.clone(), self.bc.get_account(&dst).cloned().unwrap_or_default())
        });
        let (addr, tx, outs) = self.bc.execute_one(msg).expect("the executor runs");
        if let Some((dir, msg, account)) = before {
            self.record(&dir, &msg, &account, &addr, &tx);
        }
        for out in outs {
            if out.is_internal() {
                self.queue.push_back(out);
            } else {
                let header = out.ext_out_header().expect("an external header");
                let topic = match &header.dst {
                    MsgAddressExt::AddrExtern(ext) => {
                        let bytes = ext.external_address.get_bytestring(0);
                        u32::from_be_bytes(bytes[bytes.len() - 4..].try_into().expect("a topic"))
                    }
                    MsgAddressExt::AddrNone => 0,
                };
                self.logs.push((addr.clone(), topic, out));
            }
        }
        self.delivered.push((addr.clone(), tx.clone()));
        (addr, tx)
    }

    /// Writes this transaction, as input and as outcome, for the native
    /// transaction engine to replay (scripts/replay-token-bridge-trace.py).
    fn record(
        &mut self,
        dir: &Path,
        msg: &Message,
        account: &chain_block::Account,
        addr: &MsgAddressInt,
        tx: &Transaction,
    ) {
        use chain_block::{HashmapType, ShardAccount, TrActionPhase, base64_encode, write_boc};
        let test = std::thread::current().name().unwrap_or("unnamed").replace("::", "-");
        let dir = dir.join(test);
        std::fs::create_dir_all(&dir).expect("a trace directory");
        self.traced += 1;

        let config = HashmapType::data(&self.bc.config_params().config_params)
            .cloned()
            .expect("a configuration");
        let shard_account =
            ShardAccount::with_params(account, UInt256::default(), 0).expect("a shard account");
        let boc = |c: Cell| base64_encode(write_boc(&c).expect("a boc"));

        let d = match tx.read_description().expect("a description") {
            TransactionDescr::Ordinary(d) => d,
            other => panic!("not an ordinary transaction: {other:?}"),
        };
        let (exit_code, skipped) = match &d.compute_ph {
            TrComputePhase::Vm(vm) => (Some(vm.exit_code), false),
            TrComputePhase::Skipped(_) => (None, true),
        };
        let action = d.action.as_ref().map(|a: &TrActionPhase| {
            serde_json::json!({"success": a.success, "result_code": a.result_code, "skipped": a.skipped_actions})
        });
        let bounce = match &d.bounce {
            None => "none",
            Some(TrBouncePhase::Ok(_)) => "ok",
            Some(TrBouncePhase::Nofunds(_)) => "nofunds",
            Some(TrBouncePhase::Negfunds) => "negfunds",
        };
        let mut out = Vec::new();
        tx.iterate_out_msgs(|m| {
            let body = m
                .body()
                .map(|b| b.clone().into_cell().expect("a body cell").repr_hash().as_hex_string())
                .unwrap_or_default();
            if let Some(h) = m.int_header() {
                out.push(serde_json::json!({
                    "kind": "internal",
                    "dst": h.dst.to_string(),
                    "value": h.value.coins.as_u128().to_string(),
                    "bounce": h.bounce,
                    "bounced": h.bounced,
                    "fwd_fee": h.fwd_fee.as_u128().to_string(),
                    "body": body,
                }));
            } else if let Some(h) = m.ext_out_header() {
                let topic = match &h.dst {
                    MsgAddressExt::AddrExtern(ext) => ext.external_address.as_hex_string(),
                    MsgAddressExt::AddrNone => String::new(),
                };
                out.push(serde_json::json!({"kind": "external", "topic": topic, "body": body}));
            }
            Ok(true)
        })
        .expect("the outgoing messages");
        let after = self.bc.get_account(addr);
        let record = serde_json::json!({
            "unixtime": self.bc.now(),
            "config": boc(config),
            "shard_account": boc(shard_account.serialize().expect("a shard account cell")),
            "message": boc(msg.serialize().expect("a message cell")),
            "expect": {
                "aborted": d.aborted,
                "exit_code": exit_code,
                "compute_skipped": skipped,
                "action": action,
                "bounce": bounce,
                "out": out,
                "balance": after.and_then(|a| a.balance().cloned()).map(|b| b.coins.as_u128().to_string()),
                "data": after.and_then(|a| a.get_data_hash()).map(|h| h.as_hex_string()),
                "code": after.and_then(|a| a.get_code_hash()).map(|h| h.as_hex_string()),
            },
        });
        std::fs::write(dir.join(format!("{:04}.json", self.traced)), record.to_string())
            .expect("a trace record");
    }

    fn send(&mut self, msg: Message) -> Transaction {
        self.queue.push_back(msg);
        let (_, tx) = self.deliver_one();
        self.settle();
        tx
    }

    fn settle(&mut self) {
        let mut steps = 0;
        while !self.queue.is_empty() {
            steps += 1;
            assert!(steps < 64, "the cascade does not end");
            self.deliver_one();
        }
    }

    /// Delivers until the next message is one `stop` names, and leaves it queued.
    fn deliver_until(&mut self, stop: impl Fn(&Message) -> bool) {
        let mut steps = 0;
        while let Some(next) = self.queue.front() {
            if stop(next) {
                return;
            }
            steps += 1;
            assert!(steps < 64, "the cascade does not end");
            self.deliver_one();
        }
        panic!("the cascade ended before the awaited message");
    }

    fn get(
        &self,
        addr: &MsgAddressInt,
        method: &str,
        args: Vec<StackItem>,
    ) -> tos_sandbox::GetMethodResult {
        let result = self.bc.run_get_method(addr, method, args).expect("the get-method runs");
        result.expect_success();
        result
    }

    // ---- what the contracts hold ----

    fn supply(&self) -> u128 {
        self.get(&self.minter, "get_jetton_data", vec![]).int_at(0) as u128
    }

    fn in_flight(&self) -> u128 {
        self.get(&self.minter, "get_in_flight", vec![]).int_at(0) as u128
    }

    fn pending_mint(&self, mint_id: u64) -> i128 {
        self.get(&self.bridge, "get_pending_mint", vec![int_arg(mint_id)]).int_at(0)
    }

    fn pending_burn(&self, burn_id: u64) -> i128 {
        self.get(&self.minter, "get_pending_burn", vec![int_arg(burn_id)]).int_at(0)
    }

    fn tokens(&self, owner: &MsgAddressInt) -> u128 {
        let wallet = self.wallet_of(owner);
        match self.bc.get_account(&wallet).and_then(|a| a.get_data()) {
            Some(data) => {
                let mut s = SliceData::load_cell(data).expect("wallet data");
                Coins::construct_from(&mut s).expect("a balance").as_u128()
            }
            None => 0,
        }
    }

    fn wallet_of(&self, owner: &MsgAddressInt) -> MsgAddressInt {
        let arg = SliceData::load_cell(cell(|b| owner.write_to(b).unwrap())).expect("a slice");
        let result = self.get(&self.minter, "get_wallet_address", vec![StackItem::Slice(arg)]);
        MsgAddressInt::construct_from(&mut result.slice_at(0)).expect("a wallet")
    }

    fn logs_from(&self, addr: &MsgAddressInt, topic: u32) -> usize {
        self.logs.iter().filter(|(a, t, _)| a == addr && *t == topic).count()
    }

    // ---- the operations ----

    /// Pays for and votes one swap of `amount` to the user, leaving every
    /// resulting message queued.
    fn start_swap(&mut self, amount: u128) {
        let user = self.user.address().clone();
        self.start_swap_to(&user, amount);
    }

    fn start_swap_to(&mut self, recipient: &MsgAddressInt, amount: u128) {
        let ext_chain_hash = [0x61; 32];
        let index = self.next_index;
        self.next_index += 1;
        let key = swap_key(&ext_chain_hash, index);
        let pay = MessageBuilder::internal(self.stranger.address(), &self.bridge, MINT_FEE)
            .body(cell(|b| {
                b.append_u32(OP_PAY_SWAP).unwrap().append_u64(0).unwrap();
                b.append_raw(&key, 256).unwrap();
            }))
            .build();
        self.send(pay);
        let user = account_hash(recipient);
        let vote = MessageBuilder::internal(self.oracles.address(), &self.bridge, TOS)
            .body(cell(|b| {
                b.append_u32(OP_EXECUTE_VOTING).unwrap().append_u64(index as u64).unwrap();
                b.append_u8(0).unwrap();
                b.append_raw(&ext_chain_hash, 256).unwrap();
                b.append_i16(index).unwrap();
                b.append_raw(&user, 256).unwrap();
                coins(b, amount);
                b.checked_append_reference(wrapped_token_data()).unwrap();
                coins(b, 0);
            }))
            .build();
        self.queue.push_back(vote);
    }

    fn swap(&mut self, amount: u128) {
        self.start_swap(amount);
        self.settle();
    }

    fn start_burn(&mut self, amount: u128) {
        let user = self.user.address().clone();
        self.start_burn_from(&user, amount);
    }

    fn start_burn_from(&mut self, owner: &MsgAddressInt, amount: u128) {
        let wallet = self.wallet_of(owner);
        let user = owner.clone();
        let burn = MessageBuilder::internal(&user, &wallet, self.burn_fee)
            .body(cell(|b| {
                b.append_u32(OP_BURN).unwrap().append_u64(7).unwrap();
                coins(b, amount);
                user.write_to(b).unwrap();
                b.append_bit_one().unwrap();
                b.checked_append_reference(cell(|d| {
                    d.append_raw(&[0x77; 20], 160).unwrap();
                }))
                .unwrap();
            }))
            .build();
        self.queue.push_back(burn);
    }

    fn retry_mint_message(&self, from: &MsgAddressInt, mint_id: u64, value: u64) -> Message {
        MessageBuilder::internal(from, &self.bridge, value)
            .body(cell(|b| {
                b.append_u32(OP_RETRY_MINT)
                    .unwrap()
                    .append_u64(0)
                    .unwrap()
                    .append_u64(mint_id)
                    .unwrap();
            }))
            .build()
    }

    fn retry_mint(&mut self, from: &MsgAddressInt, mint_id: u64, value: u64) -> Transaction {
        let msg = self.retry_mint_message(from, mint_id, value);
        self.send(msg)
    }

    fn retry_refund_message(&self, burn_id: u64, value: u64) -> Message {
        MessageBuilder::internal(self.stranger.address(), &self.minter, value)
            .body(cell(|b| {
                b.append_u32(OP_RETRY_REFUND)
                    .unwrap()
                    .append_u64(0)
                    .unwrap()
                    .append_u64(burn_id)
                    .unwrap();
            }))
            .build()
    }

    fn retry_refund(&mut self, burn_id: u64, value: u64) -> Transaction {
        let msg = self.retry_refund_message(burn_id, value);
        self.send(msg)
    }

    /// The user's wallet sends `amount` to `to`'s wallet.
    fn transfer(&mut self, to: &MsgAddressInt, amount: u128) {
        let wallet = self.wallet_of(self.user.address());
        let user = self.user.address().clone();
        let msg = MessageBuilder::internal(&user, &wallet, TOS)
            .body(cell(|b| {
                b.append_u32(OP_TRANSFER).unwrap().append_u64(3).unwrap();
                coins(b, amount);
                to.write_to(b).unwrap();
                user.write_to(b).unwrap();
                b.append_bit_zero().unwrap(); // no custom payload
                coins(b, 0);
                b.append_bit_zero().unwrap(); // no forward payload
            }))
            .build();
        let tx = self.send(msg);
        assert!(!outcome(&tx).aborted, "the transfer is accepted");
    }

    fn data_hash(&self, addr: &MsgAddressInt) -> Vec<u8> {
        self.bc.get_account(addr).unwrap().get_data_hash().unwrap().as_slice().to_vec()
    }
}

fn body_op(msg: &Message) -> Option<u32> {
    msg.body().and_then(|b| b.clone().get_next_u32().ok())
}

fn is_to(msg: &Message, addr: &MsgAddressInt) -> bool {
    msg.dst_ref() == Some(addr)
}

struct Outcome {
    aborted: bool,
    exit_code: Option<i32>,
    gas_used: u64,
    bounced: bool,
}

fn outcome(tx: &Transaction) -> Outcome {
    match tx.read_description().expect("a description") {
        TransactionDescr::Ordinary(d) => {
            let (exit_code, gas_used) = match d.compute_ph {
                TrComputePhase::Vm(vm) => (Some(vm.exit_code), vm.gas_used.as_u64()),
                TrComputePhase::Skipped(_) => (None, 0),
            };
            Outcome {
                aborted: d.aborted,
                exit_code,
                gas_used,
                bounced: matches!(d.bounce, Some(TrBouncePhase::Ok(_))),
            }
        }
        other => panic!("not an ordinary transaction: {other:?}"),
    }
}

fn refused_with(tx: &Transaction, code: i32) {
    let o = outcome(tx);
    assert!(o.aborted, "expected a refusal with {code}, but the transaction succeeded");
    assert_eq!(o.exit_code, Some(code), "refused for another reason");
}

// ---------------------------------------------------------------------------
// Mint
// ---------------------------------------------------------------------------

#[test]
fn a_mint_counts_toward_supply_only_once_the_wallet_confirms_it() {
    let mut b = Bridge::new();
    let minter = b.minter.clone();
    b.start_swap(1_000);

    // The bridge has spent the payment and recorded the mint; the minter has
    // dispatched the credit. Nothing is counted yet.
    b.deliver_until(|m| body_op(m) == Some(OP_INTERNAL_TRANSFER));
    assert_eq!(b.pending_mint(0), MINT_IN_FLIGHT);
    assert_eq!(b.supply(), 0, "supply counted a credit no wallet has");
    assert_eq!(b.in_flight(), 1_000);

    // The wallet holds the tokens; supply follows only its confirmation.
    b.deliver_until(|m| body_op(m) == Some(OP_MINT_CREDITED));
    assert_eq!(b.tokens(b.user.address()), 1_000);
    assert_eq!(b.supply(), 0);
    let bridge = b.bridge.clone();
    b.deliver_until(|m| body_op(m) == Some(OP_MINT_COMPLETED) && is_to(m, &bridge));
    assert_eq!((b.supply(), b.in_flight()), (1_000, 0));
    assert_eq!(b.pending_mint(0), MINT_IN_FLIGHT, "the bridge has not heard yet");

    b.settle();
    assert_eq!(b.pending_mint(0), NOTHING, "a completed mint is forgotten");
    assert_eq!(b.get(&b.bridge, "get_next_mint_id", vec![]).int_at(0), 1);
    assert_eq!(b.get(&minter, "get_jetton_data", vec![]).int_at(0), 1_000);
}

#[test]
fn a_credit_the_wallet_refuses_is_reported_failed_and_anyone_can_retry_it() {
    let mut b = Bridge::new();
    b.start_swap(500);
    b.deliver_until(|m| body_op(m) == Some(OP_INTERNAL_TRANSFER));

    // Between the minter's transaction and the wallet's, basechain gas becomes
    // dear enough that the wallet cannot fund its confirmation. It refuses the
    // credit and the refusal bounces with value to spare.
    let credit_value = b.queue.front().unwrap().get_value().unwrap().coins.as_u128() as u64;
    let price = b.basechain_gas_price();
    // The new price makes the wallet's declared gas cost a little more than the
    // whole credit.
    let raised = (u128::from(credit_value) * 65_536 * 11
        / (10 * u128::from(declared_gas("WALLET_CREDIT_GAS")))) as u64;
    assert!(raised > price, "the raised price must be dearer than the current one");
    b.set_basechain_gas_price(raised);
    let (_, wallet_tx) = b.deliver_one();
    let o = outcome(&wallet_tx);
    assert!(o.aborted && o.bounced, "the wallet refuses and bounces");
    // The price falls back for the blocks that carry the bounce on. A price that
    // stayed this high would starve those steps as well: no budget priced
    // before a rise can fund every step after it.
    b.set_basechain_gas_price(price);
    b.settle();

    assert_eq!(b.pending_mint(0), MINT_FAILED);
    assert_eq!(b.logs_from(&b.bridge, LOG_MINT_FAILED), 1);
    assert_eq!((b.supply(), b.in_flight(), b.tokens(b.user.address())), (0, 0, 0));

    // A retry needs the fee and a failed mint, and comes from anyone but the oracles.
    let stranger = b.stranger.address().clone();
    let oracles = b.oracles.address().clone();
    refused_with(&b.retry_mint(&stranger, 0, MINT_FEE - 1), ERR_MINT_FEE_NOT_MATCHED);
    refused_with(&b.retry_mint(&oracles, 0, MINT_FEE), ERR_ORACLES_SENDER);
    refused_with(&b.retry_mint(&stranger, 9, MINT_FEE), ERR_NOTHING_TO_RETRY);
    // Suspending swaps suspends their retries too.
    let bridge = b.bridge.clone();
    b.configure(&bridge, Prices { state_flags: STATE_SWAPS_SUSPENDED, ..Prices::default() });
    refused_with(&b.retry_mint(&stranger, 0, MINT_FEE), ERR_OPERATION_SUSPENDED);
    b.configure(&bridge, Prices::default());

    let retry = b.retry_mint(&stranger, 0, MINT_FEE);
    assert!(!outcome(&retry).aborted);
    assert_eq!(b.pending_mint(0), NOTHING);
    assert_eq!((b.supply(), b.tokens(b.user.address())), (500, 500));
    refused_with(&b.retry_mint(&stranger, 0, MINT_FEE), ERR_NOTHING_TO_RETRY);
}

#[test]
fn a_mint_the_minter_refuses_bounces_to_the_bridge_and_stays_retryable() {
    let mut b = Bridge::new();
    b.swap(MAX_SUPPLY - 10);
    assert_eq!(b.supply(), MAX_SUPPLY - 10);

    // Eleven more, to another holder, would exceed what supply can hold. That
    // wallet could take them, and its confirmation would then reach a minter
    // unable to store the new supply. The minter refuses before anything
    // reaches a wallet, and the mint bounces to the bridge.
    let stranger = b.stranger.address().clone();
    b.start_swap_to(&stranger, 11);
    b.settle();
    assert_eq!(b.pending_mint(1), MINT_FAILED);
    assert_eq!((b.supply(), b.in_flight(), b.tokens(&stranger)), (MAX_SUPPLY - 10, 0, 0));

    // Once burns make room, the same mint goes through on a retry.
    b.start_burn(100);
    b.settle();
    assert_eq!(b.supply(), MAX_SUPPLY - 110);
    assert!(!outcome(&b.retry_mint(&stranger, 1, MINT_FEE)).aborted);
    assert_eq!(b.pending_mint(1), NOTHING);
    assert_eq!(b.supply(), MAX_SUPPLY - 99);
    assert_eq!(b.tokens(&stranger), 11);
}

#[test]
fn an_underfunded_credit_is_refused_by_the_minter_not_sent() {
    let mut b = Bridge::new();
    // The wallet storage reserve has grown beyond what the mint fee can fund.
    // The minter refuses rather than send a credit whose outcome it could not
    // pay to report, and the refusal bounces to the bridge.
    let bridge = b.bridge.clone();
    b.configure(&bridge, Prices { wallet_min_storage: 20 * TOS, ..Prices::default() });
    b.swap(5);
    let minter_txs: Vec<_> = b.delivered.iter().filter(|(a, _)| *a == b.minter).collect();
    assert_eq!(minter_txs.len(), 1, "one minter transaction, and no credit after it");
    refused_with(&minter_txs[0].1, ERR_CREDIT_UNDERFUNDED);
    assert!(outcome(&minter_txs[0].1).bounced);
    assert_eq!(b.pending_mint(0), MINT_FAILED);
    assert_eq!(b.logs_from(&b.bridge, LOG_MINT_FAILED), 1);

    // Once the reserve is back, the mint goes through on a retry.
    b.configure(&bridge, Prices::default());
    let stranger = b.stranger.address().clone();
    assert!(!outcome(&b.retry_mint(&stranger, 0, MINT_FEE)).aborted);
    assert_eq!((b.pending_mint(0), b.supply()), (NOTHING, 5));
}

#[test]
fn only_the_mints_own_minter_can_settle_it() {
    let mut b = Bridge::new();
    b.start_swap(300);
    b.deliver_until(|m| body_op(m) == Some(OP_INTERNAL_TRANSFER));
    let before = b.data_hash(&b.bridge);

    // A mint still in flight cannot be sent a second time: its credit may yet
    // arrive, and a retry would credit the same swap twice.
    let stranger = b.stranger.address().clone();
    let retry = b.retry_mint_message(&stranger, 0, MINT_FEE);
    b.queue.push_front(retry);
    let (_, tx) = b.deliver_one();
    refused_with(&tx, ERR_NOTHING_TO_RETRY);

    for op in [OP_MINT_COMPLETED, OP_MINT_FAILED] {
        let stranger = b.stranger.address().clone();
        let bridge = b.bridge.clone();
        let forged = MessageBuilder::internal(&stranger, &bridge, TOS)
            .body(cell(|x| {
                x.append_u32(op).unwrap().append_u64(0).unwrap();
            }))
            .build();
        b.queue.push_front(forged);
        let (_, tx) = b.deliver_one();
        refused_with(&tx, ERR_MINTER_NOT_SENDER);
    }
    assert_eq!(b.data_hash(&b.bridge), before);
    assert_eq!(b.pending_mint(0), MINT_IN_FLIGHT);

    // Only the bridge can tell the minter to mint, and only wallets confirm.
    let minter = b.minter.clone();
    let stranger = b.stranger.address().clone();
    for (op, code) in [(OP_MINT, ERR_BRIDGE_NOT_SENDER), (OP_BURN_RECORDED, ERR_BRIDGE_NOT_SENDER)]
    {
        let forged = MessageBuilder::internal(&stranger, &minter, TOS)
            .body(cell(|x| {
                x.append_u32(op).unwrap().append_u64(0).unwrap();
            }))
            .build();
        b.queue.push_front(forged);
        let (_, tx) = b.deliver_one();
        refused_with(&tx, code);
    }
    let confirm = MessageBuilder::internal(&stranger, &minter, TOS)
        .body(cell(|x| {
            x.append_u32(OP_MINT_CREDITED).unwrap().append_u64(0).unwrap();
            coins(x, 300);
            stranger.write_to(x).unwrap();
        }))
        .build();
    b.queue.push_front(confirm);
    let (_, tx) = b.deliver_one();
    refused_with(&tx, 404);
    assert_eq!(b.supply(), 0);

    b.settle();
    assert_eq!((b.supply(), b.pending_mint(0)), (300, NOTHING));
}

#[test]
fn a_transfer_between_wallets_is_not_a_credit_and_leaves_supply_alone() {
    let mut b = Bridge::new();
    b.swap(1_000);
    let stranger = b.stranger.address().clone();
    b.transfer(&stranger, 250);
    assert_eq!((b.tokens(b.user.address()), b.tokens(&stranger)), (750, 250));
    assert_eq!((b.supply(), b.in_flight()), (1_000, 0));
    let minter = b.minter.clone();
    let confirmations = b.delivered.iter().filter(|(a, _)| *a == minter).count();
    assert_eq!(confirmations, 2, "the minter saw the mint and its confirmation only");
}

// ---------------------------------------------------------------------------
// Burn
// ---------------------------------------------------------------------------

#[test]
fn a_burn_is_logged_once_and_then_forgotten() {
    let mut b = Bridge::new();
    b.swap(1_000);
    b.start_burn(400);
    let bridge = b.bridge.clone();
    b.deliver_until(|m| body_op(m) == Some(OP_BURN_NOTIFICATION) && is_to(m, &bridge));
    assert_eq!(b.supply(), 600);
    assert_eq!(b.pending_burn(0), 0, "awaiting the bridge");

    // A burn the bridge may still log cannot be refunded: it would be released
    // on the counterparty chain and credited back here.
    let refund = b.retry_refund_message(0, 40 * TOS);
    b.queue.push_front(refund);
    let (_, tx) = b.deliver_one();
    refused_with(&tx, ERR_NOTHING_TO_RETRY);

    b.settle();
    assert_eq!(b.logs_from(&b.bridge, LOG_BURN), 1);
    assert_eq!(b.pending_burn(0), NOTHING);
    assert_eq!((b.supply(), b.tokens(b.user.address())), (600, 600));

    let (_, _, log) = b.logs.iter().find(|(_, t, _)| *t == LOG_BURN).unwrap();
    // The event is the message body, which the log carries in a reference.
    assert_eq!(log.body().expect("the event").remaining_bits(), 704);
}

#[test]
fn a_burn_the_bridge_does_not_log_is_credited_back_to_its_owner() {
    let mut b = Bridge::new();
    b.swap(1_000);

    // The configured bridge moves to an address with nothing deployed, as in a
    // migration landing between the minter's transaction and the bridge's.
    let nowhere = MsgAddressInt::with_params(-1, UInt256::from([0x99; 32])).unwrap();
    b.configure(&nowhere, Prices::default());
    b.start_burn(400);
    b.deliver_until(|m| body_op(m) == Some(OP_BURN_NOTIFICATION) && is_to(m, &nowhere));
    assert_eq!((b.supply(), b.tokens(b.user.address())), (600, 600));
    let (_, refused) = b.deliver_one();
    assert!(outcome(&refused).bounced, "the notification bounces");

    b.settle();
    assert_eq!(b.logs.iter().filter(|(_, t, _)| *t == LOG_BURN).count(), 0);
    assert_eq!(b.pending_burn(0), NOTHING);
    assert_eq!((b.supply(), b.in_flight()), (1_000, 0));
    assert_eq!(b.tokens(b.user.address()), 1_000, "the owner has the tokens back");
}

#[test]
fn a_refund_the_minter_cannot_fund_waits_and_anyone_can_retry_it() {
    let mut b = Bridge::new();
    b.swap(1_000);

    // The bridge does not log the burn, and while the notification is on its way
    // the wallet storage reserve grows beyond what the notification was priced
    // to fund. (A burn priced under the larger reserve would have been refused.)
    // The refund is recorded as failed instead of being sent.
    let nowhere = MsgAddressInt::with_params(-1, UInt256::from([0x99; 32])).unwrap();
    b.configure(&nowhere, Prices::default());
    b.start_burn(400);
    b.deliver_until(|m| body_op(m) == Some(OP_BURN_NOTIFICATION) && is_to(m, &nowhere));
    b.configure(&nowhere, Prices { wallet_min_storage: 20 * TOS, ..Prices::default() });
    b.settle();
    assert_eq!(b.pending_burn(0), BURN_REFUND_FAILED);
    assert_eq!(b.logs_from(&b.minter, LOG_BURN_REFUND_FAILED), 1);
    // No credit went out: an underfunded one could fail with nothing left to
    // bounce, and the record of what is owed would wait for it forever.
    let wallet = b.wallet_of(b.user.address());
    let credits = b.delivered.iter().filter(|(a, _)| *a == wallet).count();
    assert_eq!(credits, 2, "the wallet saw the mint and the burn, and no refund");
    assert_eq!((b.supply(), b.tokens(b.user.address())), (600, 600));

    refused_with(&b.retry_refund(0, TOS), ERR_CREDIT_UNDERFUNDED);
    refused_with(&b.retry_refund(5, 40 * TOS), ERR_NOTHING_TO_RETRY);
    assert_eq!(b.pending_burn(0), BURN_REFUND_FAILED);

    assert!(!outcome(&b.retry_refund(0, 40 * TOS)).aborted);
    assert_eq!(b.pending_burn(0), NOTHING);
    assert_eq!((b.supply(), b.tokens(b.user.address())), (1_000, 1_000));
    refused_with(&b.retry_refund(0, 40 * TOS), ERR_NOTHING_TO_RETRY);
}

#[test]
fn a_burn_that_overtakes_its_credits_confirmation_is_refused_and_returned() {
    let mut b = Bridge::new();
    b.start_swap(1_000);
    b.deliver_until(|m| body_op(m) == Some(OP_MINT_CREDITED));
    // The wallet holds the tokens and its confirmation is still on its way.
    let held: Vec<Message> = b.queue.drain(..).collect();
    assert_eq!((b.tokens(b.user.address()), b.supply()), (1_000, 0));

    // The tokens move to another wallet, whose burn reaches the minter first.
    // Messages from different wallets are not ordered, so the minter cannot
    // count on having seen the credit.
    let stranger = b.stranger.address().clone();
    b.transfer(&stranger, 1_000);
    b.start_burn_from(&stranger, 1_000);
    b.settle();
    let minter = b.minter.clone();
    let refusal = b.delivered.iter().rev().find(|(a, _)| *a == minter).expect("the minter ran");
    refused_with(&refusal.1, ERR_NOT_ENOUGH_FUNDS);
    assert_eq!(b.tokens(&stranger), 1_000, "the burning wallet has its tokens back");
    assert_eq!(b.get(&minter, "get_next_burn_id", vec![]).int_at(0), 0);

    b.queue.extend(held);
    b.settle();
    assert_eq!((b.supply(), b.in_flight(), b.pending_mint(0)), (1_000, 0, NOTHING));

    // Once the minter has the confirmation, the same burn goes through.
    b.start_burn_from(&stranger, 1_000);
    b.settle();
    assert_eq!((b.supply(), b.tokens(&stranger)), (0, 0));
    assert_eq!(b.logs_from(&b.bridge, LOG_BURN), 1);
}

#[test]
fn a_burn_that_cannot_fund_its_report_is_refused_and_the_wallet_keeps_its_tokens() {
    let mut b = Bridge::new();
    b.swap(1_000);
    // A burn fee too small to carry the bridge's step and the answer or bounce
    // back. Sent on, the notification could fail with nothing left to return
    // it; refused, it bounces to the wallet while the tokens are still there.
    let bridge = b.bridge.clone();
    b.configure(&bridge, Prices { burn_fee: TOS / 5, ..Prices::default() });
    b.start_burn(400);
    b.settle();
    let minter = b.minter.clone();
    let refusal = b.delivered.iter().rev().find(|(a, _)| *a == minter).expect("the minter ran");
    refused_with(&refusal.1, ERR_BURN_UNDERFUNDED);
    assert_eq!((b.supply(), b.tokens(b.user.address())), (1_000, 1_000));
    assert_eq!(b.logs.iter().filter(|(_, t, _)| *t == LOG_BURN).count(), 0);
}

#[test]
fn ids_stop_short_of_the_refund_flag() {
    let mut b = Bridge::new();
    b.swap(1_000);
    // Mint ids and refund ids share the credit's query_id, told apart by its top
    // bit. An id that reached that bit would make a mint look like a refund.
    let flag = 1u64 << 63;
    let supply = b.supply();
    let minter_data = cell(|x| {
        coins(x, supply);
        coins(x, 0);
        x.checked_append_reference(wrapped_token_data()).unwrap();
        x.checked_append_reference(codes().wallet.clone()).unwrap();
        x.append_u64(flag).unwrap();
        x.append_bit_zero().unwrap();
    });
    let collector = MsgAddressInt::with_params(0, UInt256::from([0x42; 32])).unwrap();
    let bridge_data = cell(|x| {
        collector.write_to(x).unwrap();
        x.checked_append_reference(codes().minter.clone()).unwrap();
        x.checked_append_reference(codes().wallet.clone()).unwrap();
        x.append_bit_zero().unwrap();
        x.append_u64(flag).unwrap();
        x.append_bit_zero().unwrap();
    });
    for (addr, data) in [(b.minter.clone(), minter_data), (b.bridge.clone(), bridge_data)] {
        let mut account = b.bc.get_account(&addr).unwrap().clone();
        assert!(account.set_data(data));
        b.bc.set_account(addr, account);
    }
    b.delivered.clear();

    b.start_swap(10);
    b.settle();
    let bridge = b.bridge.clone();
    let vote = b
        .delivered
        .iter()
        .find(|(a, tx)| *a == bridge && outcome(tx).aborted)
        .expect("the vote is refused");
    refused_with(&vote.1, ERR_MINT_IDS_EXHAUSTED);

    b.start_burn(10);
    b.settle();
    let minter = b.minter.clone();
    let refusal = b.delivered.iter().rev().find(|(a, _)| *a == minter).expect("the minter ran");
    refused_with(&refusal.1, ERR_BURN_IDS_EXHAUSTED);
    assert_eq!((b.supply(), b.tokens(b.user.address())), (1_000, 1_000));
}

// ---------------------------------------------------------------------------
// Budgets at their exact thresholds
// ---------------------------------------------------------------------------

fn address_arg(addr: &MsgAddressInt) -> StackItem {
    StackItem::Slice(SliceData::load_cell(cell(|b| addr.write_to(b).unwrap())).unwrap())
}

const DESTINATION_HEX: &str = "7777777777777777777777777777777777777777";

impl Bridge {
    fn set_balance(&mut self, addr: &MsgAddressInt, balance: u64) {
        let mut account = self.bc.get_account(addr).expect("deployed").clone();
        account.set_balance(chain_block::CurrencyCollection::with_coins(balance));
        self.bc.set_account(addr.clone(), account);
    }

    fn balance(&self, addr: &MsgAddressInt) -> u64 {
        self.bc
            .get_account(addr)
            .and_then(|a| a.balance().cloned())
            .map(|b| b.coins.as_u128() as u64)
            .unwrap_or(0)
    }

    fn credit_cost(&self, owner: &MsgAddressInt, amount: u64, credit_id: u64) -> u64 {
        let args = vec![address_arg(owner), int_arg(amount), int_arg(credit_id)];
        self.get(&self.minter, "get_credit_cost", args).int_at(0) as u64
    }

    fn burn_cost(&self, owner: &MsgAddressInt, amount: u64, burn_id: u64) -> u64 {
        let destination =
            StackItem::integer(IntegerData::from_str_radix(DESTINATION_HEX, 16).unwrap());
        let args = vec![address_arg(owner), int_arg(amount), destination, int_arg(burn_id)];
        self.get(&self.minter, "get_burn_cost", args).int_at(0) as u64
    }

    /// Delivers `msg` and everything it causes, and returns the first transaction.
    fn deliver(&mut self, msg: Message) -> Transaction {
        self.queue.push_back(msg);
        let (_, tx) = self.deliver_one();
        self.settle();
        tx
    }

    /// The transactions the bridge ran on reports of `op`, by outcome.
    fn bridge_reports(&self, op: u32) -> Vec<Outcome> {
        let bridge = self.bridge.clone();
        let mut outcomes = Vec::new();
        for (addr, tx) in &self.delivered {
            if *addr != bridge {
                continue;
            }
            let in_op = tx
                .in_msg_cell()
                .and_then(|c| Message::construct_from_cell(c).ok())
                .and_then(|m| body_op(&m));
            if in_op == Some(op) {
                outcomes.push(outcome(tx));
            }
        }
        outcomes
    }
}

fn mint_body(mint_id: u64, to: &MsgAddressInt, amount: u64) -> Cell {
    cell(|b| {
        b.append_u32(OP_MINT).unwrap().append_u64(mint_id).unwrap();
        to.write_to(b).unwrap();
        coins(b, amount.into());
        coins(b, 0);
    })
}

/// A credit sent at exactly what the minter must hold leaves the minter at its
/// bare reserve, reaches a new wallet with exactly what it needs, and is still
/// confirmed and reported to the bridge. One unit less and nothing is sent.
#[test]
fn a_credit_at_exactly_its_cost_completes_and_one_short_is_not_sent() {
    let mut b = Bridge::new();
    b.swap(1_000);
    let fresh = b.bc.treasury("token-bridge-fresh", TOS).unwrap().address().clone();
    let (minter, bridge) = (b.minter.clone(), b.bridge.clone());
    b.set_balance(&minter, MINTER_MIN_STORAGE);
    let cost = b.credit_cost(&fresh, 777, 4_242);
    let start = b.bc.snapshot();

    b.delivered.clear();
    let short = MessageBuilder::internal(&bridge, &minter, cost - 1)
        .body(mint_body(4_242, &fresh, 777))
        .build();
    refused_with(&b.deliver(short), ERR_CREDIT_UNDERFUNDED);
    assert_eq!((b.tokens(&fresh), b.supply(), b.in_flight()), (0, 1_000, 0));

    b.bc.restore(start);
    b.delivered.clear();
    let exact = MessageBuilder::internal(&bridge, &minter, cost)
        .body(mint_body(4_242, &fresh, 777))
        .build();
    assert!(!outcome(&b.deliver(exact)).aborted);
    assert_eq!((b.tokens(&fresh), b.supply(), b.in_flight()), (777, 1_777, 0));
    let reports = b.bridge_reports(OP_MINT_COMPLETED);
    assert_eq!(reports.len(), 1, "the completion reached the bridge");
    assert!(
        !reports[0].aborted && reports[0].exit_code == Some(0),
        "and the bridge could act on it"
    );
    assert!(b.balance(&minter) >= MINTER_MIN_STORAGE, "the minter kept its reserve");
}

/// A credit that reaches a new wallet with exactly what it needs is confirmed
/// and reported; one unit less is refused, and its bounce still carries the
/// minter's report of the failure to the bridge.
#[test]
fn a_wallet_credited_with_exactly_its_need_confirms_and_one_short_reports_failure() {
    let mut b = Bridge::new();
    b.swap(1_000);
    let fresh = b.bc.treasury("token-bridge-fresh", TOS).unwrap().address().clone();
    let (minter, bridge) = (b.minter.clone(), b.bridge.clone());
    let need = b.get(&minter, "get_wallet_need", vec![]).int_at(0) as u64;
    let wallet = b.wallet_of(&fresh);
    let init = StateInit::with_code_and_data(
        codes().wallet.clone(),
        cell(|x| {
            coins(x, 0);
            fresh.write_to(x).unwrap();
            minter.write_to(x).unwrap();
            x.checked_append_reference(codes().wallet.clone()).unwrap();
        }),
    );
    let credit = |value: u64| {
        MessageBuilder::internal(&minter, &wallet, value)
            .bounce(true)
            .state_init(init.clone())
            .body(cell(|x| {
                x.append_u32(OP_INTERNAL_TRANSFER).unwrap().append_u64(5_151).unwrap();
                coins(x, 300);
                x.append_bits(0, 2).unwrap(); // from: none, the minter
                bridge.write_to(x).unwrap();
                coins(x, 0);
                x.append_bit_zero().unwrap();
            }))
            .build()
    };
    // The minter has these 300 in flight, as it would after sending the credit.
    let set_in_flight = |b: &mut Bridge| {
        let data = cell(|x| {
            coins(x, 1_000);
            coins(x, 300);
            x.checked_append_reference(wrapped_token_data()).unwrap();
            x.checked_append_reference(codes().wallet.clone()).unwrap();
            x.append_u64(0).unwrap();
            x.append_bit_zero().unwrap();
        });
        let mut account = b.bc.get_account(&b.minter).unwrap().clone();
        assert!(account.set_data(data));
        b.bc.set_account(b.minter.clone(), account);
    };
    set_in_flight(&mut b);
    let start = b.bc.snapshot();

    b.delivered.clear();
    let short = b.deliver(credit(need - 1));
    let o = outcome(&short);
    assert!(o.aborted && o.bounced && o.exit_code == Some(709), "the wallet refuses and bounces");
    let reports = b.bridge_reports(OP_MINT_FAILED);
    assert_eq!(reports.len(), 1, "the failure reached the bridge");
    assert!(
        !reports[0].aborted && reports[0].exit_code == Some(0),
        "and the bridge could act on it"
    );
    assert_eq!((b.tokens(&fresh), b.supply(), b.in_flight()), (0, 1_000, 0));

    b.bc.restore(start);
    b.delivered.clear();
    assert!(!outcome(&b.deliver(credit(need))).aborted);
    assert_eq!((b.tokens(&fresh), b.supply(), b.in_flight()), (300, 1_300, 0));
    let reports = b.bridge_reports(OP_MINT_COMPLETED);
    assert_eq!(reports.len(), 1, "the completion reached the bridge");
    assert!(
        !reports[0].aborted && reports[0].exit_code == Some(0),
        "and the bridge could act on it"
    );
}

/// A burn notification sent at exactly what the minter must hold completes
/// either way it can end: logged and answered, or bounced and credited back.
/// One unit less is refused while the wallet still has the tokens.
#[test]
fn a_burn_at_exactly_its_cost_completes_either_way_and_one_short_is_refused() {
    let mut b = Bridge::new();
    b.swap(1_000);
    let (minter, bridge) = (b.minter.clone(), b.bridge.clone());
    let user = b.user.address().clone();
    let wallet = b.wallet_of(&user);
    b.set_balance(&minter, MINTER_MIN_STORAGE);
    let cost = b.burn_cost(&user, 400, 0);
    let notification = |value: u64| {
        MessageBuilder::internal(&wallet, &minter, value)
            .body(cell(|x| {
                x.append_u32(OP_BURN_NOTIFICATION).unwrap().append_u64(7).unwrap();
                coins(x, 400);
                user.write_to(x).unwrap();
                user.write_to(x).unwrap();
                x.append_raw(&hex_bytes(DESTINATION_HEX), 160).unwrap();
            }))
            .build()
    };
    let start = b.bc.snapshot();

    b.delivered.clear();
    refused_with(&b.deliver(notification(cost - 1)), ERR_BURN_UNDERFUNDED);
    assert_eq!(b.get(&minter, "get_next_burn_id", vec![]).int_at(0), 0);

    // Logged and answered.
    b.bc.restore(b.bc.snapshot());
    b.bc.restore(start.clone());
    b.delivered.clear();
    b.logs.clear();
    assert!(!outcome(&b.deliver(notification(cost))).aborted);
    assert_eq!(b.logs_from(&bridge, LOG_BURN), 1);
    assert_eq!((b.pending_burn(0), b.supply()), (NOTHING, 600));
    assert!(b.balance(&minter) >= MINTER_MIN_STORAGE, "the minter kept its reserve");

    // Bounced, because no bridge is there, and credited back.
    b.bc.restore(start);
    b.delivered.clear();
    b.logs.clear();
    let nowhere = MsgAddressInt::with_params(-1, UInt256::from([0x99; 32])).unwrap();
    b.configure(&nowhere, Prices::default());
    assert!(!outcome(&b.deliver(notification(cost))).aborted);
    assert_eq!(b.logs.iter().filter(|(_, t, _)| *t == LOG_BURN).count(), 0);
    assert_eq!(
        (b.pending_burn(0), b.supply(), b.in_flight()),
        (NOTHING, 1_000, 0),
        "the refund completed"
    );
    b.configure(&bridge, Prices::default());
}

/// The bridge logs and answers a burn from what the notification carries, not
/// from its own balance: emptied, it still does both.
#[test]
fn a_bridge_with_nothing_of_its_own_still_logs_and_answers_a_burn() {
    let mut b = Bridge::new();
    b.swap(1_000);
    let bridge = b.bridge.clone();
    b.start_burn(400);
    b.deliver_until(|m| body_op(m) == Some(OP_BURN_NOTIFICATION) && is_to(m, &bridge));
    b.set_balance(&bridge, 0);
    let (_, tx) = b.deliver_one();
    assert!(!outcome(&tx).aborted, "the bridge logged and answered");
    b.settle();
    assert_eq!(b.logs_from(&bridge, LOG_BURN), 1);
    assert_eq!((b.pending_burn(0), b.supply()), (NOTHING, 600));
}

/// A log is a record for observers. One the minter cannot pay for is skipped,
/// and the supply it would have recorded is counted all the same.
#[test]
fn a_log_the_minter_cannot_pay_for_is_skipped_not_allowed_to_undo_the_supply() {
    let mut b = Bridge::new();
    let bridge = b.bridge.clone();
    b.start_swap(500);
    b.deliver_until(|m| body_op(m) == Some(OP_MINT_CREDITED));
    // Nothing left for the minter's own records: no reserve and no balance.
    b.configure(&bridge, Prices { minter_min_storage: 0, ..Prices::default() });
    let minter = b.minter.clone();
    b.set_balance(&minter, 0);
    let (_, tx) = b.deliver_one();
    assert!(!outcome(&tx).aborted, "the confirmation is taken");
    b.settle();
    assert_eq!(b.logs_from(&minter, LOG_MINT_ON_MINTER), 0, "the log was skipped");
    assert_eq!((b.supply(), b.in_flight(), b.pending_mint(0)), (500, 0, NOTHING));
}

/// A confirmation can reach the minter with less than its report needs, as
/// after a rise in gas prices on its way. The report is then skipped; it is not
/// allowed to undo the supply, which nothing could bounce back to restore.
#[test]
fn a_report_the_minter_cannot_fund_is_skipped_and_the_supply_still_counted() {
    let mut b = Bridge::new();
    b.start_swap(500);
    b.deliver_until(|m| body_op(m) == Some(OP_MINT_CREDITED));
    let mut confirmation = b.queue.pop_front().expect("the confirmation");
    let minter = b.minter.clone();
    b.set_balance(&minter, MINTER_MIN_STORAGE);
    confirmation.set_value(chain_block::CurrencyCollection::with_coins(TOS / 10_000));
    b.queue.push_front(confirmation);
    let (_, tx) = b.deliver_one();
    assert!(!outcome(&tx).aborted, "the confirmation is taken");
    b.settle();
    assert_eq!((b.supply(), b.in_flight()), (500, 0), "the supply is counted");
    assert_eq!(b.bridge_reports(OP_MINT_COMPLETED).len(), 0, "the report was not sent");
    assert_eq!(
        b.pending_mint(0),
        MINT_IN_FLIGHT,
        "the bridge still waits, which is the documented residual"
    );
}

/// What forwarding a message as sent costs: every cell but the root, at the
/// prices of the masterchain if either end is on it.
fn forwarding_fee(bc: &Blockchain, message: &Cell, masterchain: bool) -> u128 {
    fn visit(
        c: &Cell,
        seen: &mut std::collections::HashSet<UInt256>,
        cells: &mut u128,
        bits: &mut u128,
    ) {
        for i in 0..c.references_count() {
            let child = c.reference(i).expect("a reference");
            if seen.insert(child.repr_hash()) {
                *cells += 1;
                *bits += child.bit_length() as u128;
                visit(&child, seen, cells, bits);
            }
        }
    }
    let (mut cells, mut bits) = (0u128, 0u128);
    visit(message, &mut std::collections::HashSet::new(), &mut cells, &mut bits);
    let prices = bc.config_params().fwd_prices(masterchain).expect("forward prices");
    u128::from(prices.lump_price)
        + ((u128::from(prices.bit_price) * bits + u128::from(prices.cell_price) * cells + 0xffff)
            >> 16)
}

/// Confirmations, completion and failure reports, burn answers and bounces are
/// priced as one small message. Each one these flows send, at the widest values
/// a bridge can carry, costs no more to forward than that allowance.
#[test]
fn every_small_message_fits_its_forwarding_allowance() {
    let mut b = Bridge::new();
    let bridge = b.bridge.clone();
    let nowhere = MsgAddressInt::with_params(-1, UInt256::from([0x99; 32])).unwrap();

    // A credit refused by its wallet: the bounce and the failure report.
    b.start_swap(MAX_SUPPLY / 2);
    b.deliver_until(|m| body_op(m) == Some(OP_INTERNAL_TRANSFER));
    let credit_value = b.queue.front().unwrap().get_value().unwrap().coins.as_u128() as u64;
    let price = b.basechain_gas_price();
    b.set_basechain_gas_price(
        (u128::from(credit_value) * 65_536 * 11
            / (10 * u128::from(declared_gas("WALLET_CREDIT_GAS")))) as u64,
    );
    b.deliver_one();
    b.set_basechain_gas_price(price);
    b.settle();
    assert_eq!(b.pending_mint(0), MINT_FAILED);
    // The widest mint: its confirmation and completion report.
    b.swap(MAX_SUPPLY - 10);
    // The widest burn, logged and answered; then one bounced and refunded.
    b.start_burn(MAX_SUPPLY - 1_000);
    b.settle();
    b.configure(&nowhere, Prices::default());
    b.start_burn(500);
    b.settle();
    b.configure(&bridge, Prices::default());

    let allowance = |is_mc: bool| {
        let arg = StackItem::integer(IntegerData::from_i32(if is_mc { -1 } else { 0 }));
        b.get(&b.minter, "get_small_message_fee", vec![arg]).int_at(0) as u128
    };
    let mut seen = std::collections::BTreeMap::new();
    for (addr, tx) in &b.delivered {
        tx.iterate_out_msgs_with_cells(|m, cell| {
            let Some(h) = m.int_header() else { return Ok(true) };
            let kind = if h.bounced {
                "bounce"
            } else {
                match body_op(&m) {
                    Some(OP_MINT_CREDITED) => "confirmation",
                    Some(OP_MINT_COMPLETED) => "completion",
                    Some(OP_MINT_FAILED) => "failure report",
                    Some(OP_BURN_RECORDED) => "burn answer",
                    _ => return Ok(true),
                }
            };
            let masterchain = addr.workchain_id() == -1 || h.dst.workchain_id() == -1;
            let fee = forwarding_fee(&b.bc, &cell, masterchain);
            assert!(
                fee <= allowance(masterchain),
                "a {kind} costs {fee} to forward, over the allowance of {}",
                allowance(masterchain)
            );
            *seen.entry(kind).or_insert(0) += 1;
            Ok(true)
        })
        .expect("the outgoing messages");
    }
    for kind in ["confirmation", "completion", "failure report", "burn answer", "bounce"] {
        assert!(seen.contains_key(kind), "no {kind} was checked: {seen:?}");
    }
}

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

// ---------------------------------------------------------------------------
// Fees
// ---------------------------------------------------------------------------

/// A dictionary of `count` entries under sequential 64-bit ids, as the
/// contracts key their pending mints and burns.
fn pending_dict(count: u64, entry: impl Fn() -> BuilderData) -> Option<Cell> {
    let mut dict = chain_block::HashmapE::with_bit_len(64);
    for id in 0..count {
        let key =
            SliceData::load_builder(BuilderData::with_raw(id.to_be_bytes().to_vec(), 64).unwrap())
                .unwrap();
        dict.set_builder(key, &entry()).unwrap();
    }
    chain_block::HashmapType::data(&dict).cloned()
}

fn store_dict(b: &mut BuilderData, dict: Option<Cell>) {
    match dict {
        Some(root) => {
            b.append_bit_one().unwrap();
            b.checked_append_reference(root).unwrap();
        }
        None => {
            b.append_bit_zero().unwrap();
        }
    }
}

impl Bridge {
    /// Ages the bridge and the minter: each holds `count` unresolved entries, as
    /// it would after a long outage. Their dictionaries are as deep as they will
    /// plausibly get, and every lookup in them costs the most it will.
    fn age(&mut self, count: u64) {
        assert_eq!((self.in_flight(), self.pending_mint(0)), (0, NOTHING), "age a settled bridge");
        let supply = self.supply();
        let user = self.user.address().clone();
        let burns = pending_dict(count, || {
            let mut e = BuilderData::new();
            e.append_bits(0, 2).unwrap();
            user.write_to(&mut e).unwrap();
            coins(&mut e, 1);
            e
        });
        let minter_data = cell(|b| {
            coins(b, supply);
            coins(b, 0);
            b.checked_append_reference(wrapped_token_data()).unwrap();
            b.checked_append_reference(codes().wallet.clone()).unwrap();
            b.append_u64(count).unwrap();
            store_dict(b, burns);
        });
        let mints = pending_dict(count, || {
            let mut e = BuilderData::new();
            e.append_bit_zero().unwrap();
            e.append_raw(&[0x11; 32], 256).unwrap();
            e.append_raw(&[0x22; 32], 256).unwrap();
            coins(&mut e, 1);
            e.checked_append_reference(wrapped_token_data()).unwrap();
            e
        });
        let collector = MsgAddressInt::with_params(0, UInt256::from([0x42; 32])).unwrap();
        let bridge_data = cell(|b| {
            collector.write_to(b).unwrap();
            b.checked_append_reference(codes().minter.clone()).unwrap();
            b.checked_append_reference(codes().wallet.clone()).unwrap();
            b.append_bit_zero().unwrap();
            b.append_u64(count).unwrap();
            store_dict(b, mints);
        });
        for (addr, data) in [(self.minter.clone(), minter_data), (self.bridge.clone(), bridge_data)]
        {
            let mut account = self.bc.get_account(&addr).expect("deployed").clone();
            assert!(account.set_data(data), "the data is replaced");
            self.bc.set_account(addr, account);
        }
        assert_eq!(self.get(&self.minter, "get_next_burn_id", vec![]).int_at(0), count as i128);
        assert_eq!(self.get(&self.bridge, "get_next_mint_id", vec![]).int_at(0), count as i128);
        self.delivered.clear();
    }

    /// Every transaction of the bridge, the minter and the wallets so far, held
    /// against the gas the fee budget prices it at.
    fn gas_by_contract(&self) -> (u64, u64, u64) {
        let mut measured = (0, 0, 0);
        for (addr, tx) in &self.delivered {
            let gas = outcome(tx).gas_used;
            if *addr == self.minter {
                measured.1 = measured.1.max(gas);
            } else if *addr == self.bridge {
                measured.2 = measured.2.max(gas);
            } else if *addr == self.wallet_of(self.user.address()) {
                measured.0 = measured.0.max(gas);
            }
        }
        measured
    }
}

/// The fee budget is priced from declared gas. A step that uses more than its
/// declaration underprices the budget, and the outcome it was meant to fund
/// may not arrive. Measured on a bridge and minter that each hold 65536
/// unresolved entries, because a fresh contract is the cheapest it will be.
#[test]
fn every_completion_step_fits_the_gas_it_is_priced_at() {
    const AGE: u64 = 1 << 16;
    let declared = (
        declared_gas("WALLET_CREDIT_GAS"),
        declared_gas("MINTER_STEP_GAS"),
        declared_gas("BRIDGE_STEP_GAS"),
    );

    let mut b = Bridge::new();
    b.swap(1_000);
    let fresh = b.gas_by_contract();
    b.age(AGE);
    let bridge = b.bridge.clone();
    let stranger = b.stranger.address().clone();

    // A mint and a burn that complete.
    b.swap(1_000);
    assert_eq!(b.pending_mint(AGE), NOTHING);
    b.start_burn(100);
    b.settle();
    assert_eq!(b.pending_burn(AGE), NOTHING);

    // A mint the minter refuses, and its retry.
    b.configure(&bridge, Prices { wallet_min_storage: 20 * TOS, ..Prices::default() });
    b.swap(10);
    assert_eq!(b.pending_mint(AGE + 1), MINT_FAILED);
    b.configure(&bridge, Prices::default());
    assert!(!outcome(&b.retry_mint(&stranger, AGE + 1, MINT_FEE)).aborted);

    // A credit the wallet refuses.
    b.start_swap(10);
    b.deliver_until(|m| body_op(m) == Some(OP_INTERNAL_TRANSFER));
    let credit_value = b.queue.front().unwrap().get_value().unwrap().coins.as_u128() as u64;
    let price = b.basechain_gas_price();
    b.set_basechain_gas_price(
        (u128::from(credit_value) * 65_536 * 11 / (10 * u128::from(declared.0))) as u64,
    );
    b.deliver_one();
    b.set_basechain_gas_price(price);
    b.settle();
    assert_eq!(b.pending_mint(AGE + 2), MINT_FAILED);

    // A burn the bridge does not log, refunded, and one whose refund waits.
    let nowhere = MsgAddressInt::with_params(-1, UInt256::from([0x99; 32])).unwrap();
    b.configure(&nowhere, Prices::default());
    b.start_burn(100);
    b.settle();
    assert_eq!(b.pending_burn(AGE + 1), NOTHING);
    b.start_burn(100);
    b.deliver_until(|m| body_op(m) == Some(OP_BURN_NOTIFICATION) && is_to(m, &nowhere));
    b.configure(&nowhere, Prices { wallet_min_storage: 20 * TOS, ..Prices::default() });
    b.settle();
    assert_eq!(b.pending_burn(AGE + 2), BURN_REFUND_FAILED);
    assert!(!outcome(&b.retry_refund(AGE + 2, 40 * TOS)).aborted);

    let aged = b.gas_by_contract();
    eprintln!(
        "gas fresh {fresh:?}, aged by {AGE} entries {aged:?}, declared {declared:?} \
         (wallet, minter, bridge)"
    );
    assert!(aged.0 > 0 && aged.1 > 0 && aged.2 > 0, "every contract ran");
    assert!(aged.1 > fresh.1 && aged.2 > fresh.2, "the aged dictionaries cost more to search");
    assert!(aged.0 <= declared.0, "the wallet uses {} gas", aged.0);
    assert!(aged.1 <= declared.1, "the minter uses {} gas", aged.1);
    assert!(aged.2 <= declared.2, "the bridge uses {} gas", aged.2);
}
