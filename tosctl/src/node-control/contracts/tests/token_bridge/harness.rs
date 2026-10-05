/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The bridge, its minters and wallets on one sandbox chain, with every message
//! delivered one at a time through the executor so a test can stop, drop,
//! duplicate, hold, reorder or forge any of them. Every transaction is recorded
//! for replay in the native engine and checked against the independent model.

#![allow(dead_code)]

use std::collections::{BTreeMap, VecDeque};
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

use crate::model::Model;

pub const TOS: u64 = 1_000_000_000;
pub const MINT_FEE: u64 = 5 * TOS;
pub const BURN_FEE: u64 = 3 * TOS;
pub const CHAIN_ID: u32 = 1;
pub const CONFIG_PARAM: u32 = 79;
/// The EVM bridge this TOS bridge serves: where the Hardhat suite's coupled
/// vector test deploys `Bridge.sol` (crosschain/token-bridge/tests/vectors).
pub const EVM_BRIDGE: [u8; 20] = [0xd3, 0x25, 0x53, 0x46, 0xb2, 0xed, 0x5b, 0xc6, 0x23, 0x70, 0x8c, 0x33, 0x4b, 0x1d, 0x56, 0xda, 0x1a, 0xd9, 0xd6, 0x3a];
pub const GENERATION: u32 = 1;
pub const DESTINATION: [u8; 20] = [0x77; 20];

pub const OP_EXECUTE_VOTING: u32 = 4;
pub const OP_PAY_SWAP: u32 = 8;
pub const OP_EXCESSES: u32 = 0xd532_76db;
pub const OP_BURN: u32 = 0x595f_07bc;
pub const OP_TRANSFER: u32 = 0x0f8a_7ea5;
pub const OP_INTERNAL_TRANSFER: u32 = 0x178d_4519;
pub const LOG_BURN: u32 = 0xc047_0ccf;

/// Every settlement opcode, from settlement.fc.
pub mod op {
    pub const PREPARE: u32 = 40;
    pub const PREPARED: u32 = 41;
    pub const REFUSED: u32 = 42;
    pub const COMMIT: u32 = 43;
    pub const CREDIT: u32 = 44;
    pub const CREDIT_RECORDED: u32 = 45;
    pub const MINT_COMPLETED: u32 = 46;
    pub const MINT_STRANDED: u32 = 47;
    pub const OPEN: u32 = 48;
    pub const OPENED: u32 = 49;
    pub const OPEN_REFUSED: u32 = 50;
    pub const OPEN_REQUEST: u32 = 51;
    pub const OPEN_DENIED: u32 = 52;
    pub const BURN_ADMIT: u32 = 53;
    pub const ADMIT_REFUSED: u32 = 54;
    pub const BURN_NOTICE: u32 = 55;
    pub const BURN_RESULT: u32 = 56;
    pub const BURN_OUTCOME: u32 = 57;
    pub const REFUND: u32 = 58;
    pub const REFUND_RECORDED: u32 = 59;
    pub const ADVANCE: u32 = 60;
    pub const SYNC_FLOOR: u32 = 61;
    pub const SYNC_ACK: u32 = 62;
    pub const CANCEL_BURN: u32 = 63;
}

pub mod advance {
    pub const MINT: u8 = 1;
    pub const BURN: u8 = 2;
    pub const BURN_RESULT: u8 = 3;
    pub const STRAND: u8 = 4;
    pub const OPEN: u8 = 5;
    pub const REPORT: u8 = 6;
    pub const SYNC: u8 = 7;
}

pub mod channel {
    pub const C1: u8 = 1;
    pub const C2: u8 = 2;
    pub const C3: u8 = 3;
    pub const C4: u8 = 4;
}

pub mod mint_status {
    pub const AWAITING_OPEN: i128 = 0;
    pub const RESERVED: i128 = 1;
    pub const CREDITING: i128 = 2;
    pub const COUNTED: i128 = 3;
    pub const REFUSED: i128 = 4;
    pub const STRANDED: i128 = 5;
}

pub mod burn_status {
    pub const AWAITING_BRIDGE: i128 = 0;
    pub const RECORDED: i128 = 1;
    pub const REFUNDING: i128 = 2;
    pub const REFUNDED: i128 = 3;
    pub const ADMIT_REFUSED: i128 = 4;
    pub const STRANDED: i128 = 5;
}

pub mod swap_state {
    pub const PAID: i128 = 0;
    pub const PREPARING: i128 = 1;
    pub const CONSUMED: i128 = 2;
    pub const CANCELLED: i128 = 3;
}

pub mod holder_state {
    pub const NEW: i128 = 0;
    pub const OPENING: i128 = 1;
    pub const OPEN: i128 = 2;
    pub const DEAD: i128 = 3;
}

pub const OUTCOME_RECORDED: i128 = 0;
pub const OUTCOME_CANCELLED: i128 = 1;

pub const MAX_SEQ: u64 = 0xffff_ffff_ffff_fffe;
pub const MAX_SUPPLY: u128 = (1 << 120) - 1;

// ---------------------------------------------------------------------------
// Sources and constants
// ---------------------------------------------------------------------------

pub fn repo_root() -> PathBuf {
    std::env::var("TOS_ROOT").map(PathBuf::from).unwrap_or_else(|_| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("repository root above the contracts crate")
            .to_path_buf()
    })
}

pub fn contracts_dir() -> PathBuf {
    repo_root().join("crosschain/token-bridge/tvm/contracts")
}

/// A constant as settlement.fc or errors.fc declares it. The tests read limits,
/// windows, gas and error codes from the contract sources, never from a copy.
pub fn declared(name: &str) -> i128 {
    for file in ["settlement.fc", "errors.fc"] {
        let source = std::fs::read_to_string(contracts_dir().join(file)).expect("a source");
        let prefix = format!("const int {name} = ");
        if let Some(line) = source.lines().find(|line| line.trim_start().starts_with(&prefix)) {
            let value = line.trim_start()[prefix.len()..]
                .split(';')
                .next()
                .expect("a value")
                .trim()
                .to_string();
            return if let Some(hex) = value.strip_prefix("0x") {
                i128::from_str_radix(hex, 16).expect("a hex constant")
            } else {
                value.parse().expect("a constant")
            };
        }
    }
    panic!("no declaration of {name}")
}

pub fn err(name: &str) -> i32 {
    declared(&format!("error::{name}")) as i32
}

pub struct Codes {
    pub bridge: Cell,
    pub minter: Cell,
    pub wallet: Cell,
}

/// The three contracts, compiled from source for the Ethereum parameters.
pub fn codes() -> &'static Codes {
    static CODES: OnceLock<Codes> = OnceLock::new();
    CODES.get_or_init(|| {
        let stage =
            std::env::temp_dir().join(format!("tos-token-bridge-sandbox-{}", std::process::id()));
        stage_sources(&stage);
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

pub fn stage_sources(stage: &Path) {
    std::fs::create_dir_all(stage).expect("a staging directory");
    let mut staged = 0;
    for entry in std::fs::read_dir(contracts_dir()).expect("the bridge contracts") {
        let path = entry.expect("a directory entry").path();
        if path.extension().is_some_and(|ext| ext == "fc" || ext == "fif") {
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
}

/// A toolchain binary: the environment's override, else this checkout's build,
/// else the shared checkout's, the order `tos_sandbox::compile_func` uses.
pub fn tool(env: &str, name: &str) -> PathBuf {
    if let Some(path) = std::env::var_os(env) {
        return PathBuf::from(path);
    }
    let local = repo_root().join("build/crypto").join(name);
    if local.exists() {
        return local;
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).expect("HOME or a tool override");
    home.join("tos/build/crypto").join(name)
}

/// The creation message `new-bridge.fif` writes for the test namespace.
pub fn new_bridge_script_message() -> Message {
    let stage =
        std::env::temp_dir().join(format!("tos-token-bridge-new-bridge-{}", std::process::id()));
    stage_sources(&stage);
    let run = |cmd: &mut std::process::Command, what: &str| {
        let out = cmd.current_dir(&stage).output().unwrap_or_else(|e| panic!("{what}: {e}"));
        assert!(
            out.status.success(),
            "{what} failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let func = tool("FUNC_PATH", "func");
    for contract in ["jetton-bridge", "jetton-minter", "jetton-wallet", "votes-collector"] {
        run(
            std::process::Command::new(&func)
                .arg("-PS")
                .arg("-o")
                .arg(format!("{contract}.fif"))
                .arg(format!("{contract}.fc")),
            &format!("func {contract}.fc"),
        );
    }
    let includes = format!("{}:{}", repo_root().join("crypto/fift/lib").display(), stage.display());
    let evm_bridge = format!("0x{}", hex::encode(EVM_BRIDGE));
    run(
        std::process::Command::new(tool("FIFT_PATH", "fift")).args([
            "-I",
            &includes,
            "-s",
            "new-bridge.fif",
            &CHAIN_ID.to_string(),
            &evm_bridge,
        ]),
        "fift new-bridge.fif",
    );
    let boc = std::fs::read(stage.join("bridge-create.boc")).expect("the creation query");
    let _ = std::fs::remove_dir_all(&stage);
    let root = chain_block::read_single_root_boc(boc).expect("a creation query boc");
    Message::construct_from_cell(root).expect("an external creation message")
}

// ---------------------------------------------------------------------------
// Cells
// ---------------------------------------------------------------------------

pub fn cell(build: impl FnOnce(&mut BuilderData)) -> Cell {
    let mut b = BuilderData::new();
    build(&mut b);
    b.into_cell().expect("a cell")
}

pub fn coins(b: &mut BuilderData, amount: u128) {
    amount.to_string().parse::<Coins>().expect("coins").write_to(b).expect("coins");
}

pub fn account_hash(addr: &MsgAddressInt) -> Vec<u8> {
    addr.address().get_bytestring(0)
}

pub fn account_int(addr: &MsgAddressInt) -> IntegerData {
    IntegerData::from_str_radix(&hex::encode(account_hash(addr)), 16).expect("an address hash")
}

pub fn int_arg(value: u64) -> StackItem {
    StackItem::integer(IntegerData::from_u64(value))
}

pub fn addr_arg(addr: &MsgAddressInt) -> StackItem {
    StackItem::integer(account_int(addr))
}

pub fn slice_arg(addr: &MsgAddressInt) -> StackItem {
    StackItem::Slice(SliceData::load_cell(cell(|b| addr.write_to(b).unwrap())).unwrap())
}

pub fn wrapped_token_data(token: u8) -> Cell {
    cell(|b| {
        b.append_u32(CHAIN_ID).unwrap();
        b.append_raw(&[token; 20], 160).unwrap();
        b.append_u8(18).unwrap();
    })
}

pub fn body_op(msg: &Message) -> Option<u32> {
    let body = msg.body()?;
    let mut s = body.clone();
    if s.remaining_bits() >= 32 {
        return s.get_next_u32().ok();
    }
    if s.remaining_references() > 0 {
        let inner = s.reference(0).ok()?;
        return SliceData::load_cell(inner).ok()?.get_next_u32().ok();
    }
    None
}

/// The body of a settlement message: the message's own body, or the cell it
/// carries by reference, as every settlement send stores it.
pub fn settlement_body(msg: &Message) -> SliceData {
    let body = msg.body().expect("a body");
    if body.remaining_bits() == 0 && body.remaining_references() > 0 {
        SliceData::load_cell(body.reference(0).expect("a body reference")).expect("a body")
    } else {
        body.clone()
    }
}

pub fn is_to(msg: &Message, addr: &MsgAddressInt) -> bool {
    msg.dst_ref() == Some(addr)
}

pub fn value_of(msg: &Message) -> u128 {
    msg.get_value().map(|v| v.coins.as_u128()).unwrap_or(0)
}

pub struct Outcome {
    pub aborted: bool,
    pub exit_code: Option<i32>,
    pub gas_used: u64,
    pub bounced: bool,
    pub action_ok: bool,
    pub storage_fees: u128,
}

pub fn outcome(tx: &Transaction) -> Outcome {
    match tx.read_description().expect("a description") {
        TransactionDescr::Ordinary(d) => {
            let (exit_code, gas_used) = match &d.compute_ph {
                TrComputePhase::Vm(vm) => (Some(vm.exit_code), vm.gas_used.as_u64()),
                TrComputePhase::Skipped(_) => (None, 0),
            };
            Outcome {
                aborted: d.aborted,
                exit_code,
                gas_used,
                bounced: matches!(d.bounce, Some(TrBouncePhase::Ok(_))),
                action_ok: d.action.as_ref().map(|a| a.success).unwrap_or(true),
                storage_fees: d
                    .storage_ph
                    .as_ref()
                    .map(|s| s.storage_fees_collected.as_u128())
                    .unwrap_or(0),
            }
        }
        other => panic!("not an ordinary transaction: {other:?}"),
    }
}

pub fn refused_with(tx: &Transaction, code: i32) {
    let o = outcome(tx);
    assert!(o.aborted, "expected a refusal with {code}, but the transaction succeeded");
    assert_eq!(o.exit_code, Some(code), "refused for another reason");
}

pub fn succeeded(tx: &Transaction) {
    let o = outcome(tx);
    assert!(!o.aborted, "the transaction failed with exit code {:?}", o.exit_code);
}

// ---------------------------------------------------------------------------
// The network
// ---------------------------------------------------------------------------

/// What one delivered transaction did.
pub struct Delivery {
    pub balance_before: u128,
    pub addr: MsgAddressInt,
    pub msg: Message,
    pub tx: Transaction,
    pub outs: Vec<Message>,
}

pub struct Net {
    pub bc: Blockchain,
    pub oracles: Treasury,
    pub deployer: Treasury,
    pub users: Vec<Treasury>,
    pub stranger: Treasury,
    pub bridge: MsgAddressInt,
    /// Minters by token byte.
    pub minters: BTreeMap<u8, MsgAddressInt>,
    pub queue: VecDeque<Message>,
    pub delivered: Vec<Delivery>,
    pub logs: Vec<(MsgAddressInt, u32, Message)>,
    pub model: Model,
    /// The most gas each (contract, opcode, advance kind) used in this run.
    pub gas_seen: BTreeMap<(&'static str, u32, u8), u64>,
    pub next_nonce: u64,
    pub burn_fee: u64,
    pub mint_fee: u64,
    pub traced: usize,
    pub state_flags: u8,
}

/// How the bridge account comes to exist.
pub enum Deployment {
    /// A StateInit this suite builds itself, sent with an internal message.
    Direct,
    /// The external creation message `new-bridge.fif` writes.
    Script,
}

pub fn initial_bridge_data() -> Cell {
    let collector = MsgAddressInt::with_params(0, UInt256::from([0x42; 32])).expect("collector");
    cell(|b| {
        b.append_u64(0).unwrap(); // born_lt
        b.append_u32(CHAIN_ID).unwrap();
        b.append_raw(&EVM_BRIDGE, 160).unwrap();
        b.append_u32(0).unwrap(); // generation
        b.append_u64(0).unwrap(); // generation_start
        b.append_bits(0, 2).unwrap(); // generation_state
        collector.write_to(b).unwrap();
        b.checked_append_reference(codes().minter.clone()).unwrap();
        b.checked_append_reference(codes().wallet.clone()).unwrap();
        b.checked_append_reference(cell(|s| {
            s.append_u64(0).unwrap(); // swap_watermark
            s.append_bit_zero().unwrap(); // swaps
            s.append_bit_zero().unwrap(); // channels
            s.append_u32(0).unwrap(); // channels_count
        }))
        .unwrap();
    })
}

impl Net {
    pub fn new() -> Self {
        Self::deployed(Deployment::Direct)
    }

    pub fn deployed(how: Deployment) -> Self {
        let mut net = Self::unactivated(how);
        net.activate(GENERATION, 0);
        net
    }

    /// A deployed bridge that no source generation has activated yet.
    pub fn unactivated(how: Deployment) -> Self {
        let mut bc = Blockchain::with_global_version_and_base_workchain(14).expect("a chain");
        bc.set_workchain(-1);
        let oracles = bc.treasury("token-bridge-oracles", 10_000 * TOS).expect("oracles");
        let deployer = bc.treasury("token-bridge-deployer", 10_000 * TOS).expect("deployer");
        bc.set_workchain(0);
        let users = (0..4)
            .map(|i| bc.treasury(&format!("token-bridge-user-{i}"), 10_000 * TOS).expect("user"))
            .collect::<Vec<_>>();
        let stranger = bc.treasury("token-bridge-stranger", 100_000 * TOS).expect("stranger");

        let (bridge, fund, deploy) = match how {
            Deployment::Direct => {
                let init = StateInit::with_code_and_data(codes().bridge.clone(), initial_bridge_data());
                let bridge_hash = init.serialize().expect("a state init").repr_hash();
                let bridge = MsgAddressInt::with_params(-1, bridge_hash).expect("the bridge address");
                let deploy = MessageBuilder::internal(deployer.address(), &bridge, 50 * TOS)
                    .bounce(false)
                    .state_init(init)
                    .body(cell(|b| {
                        b.append_u32(OP_EXCESSES).unwrap().append_u64(0).unwrap();
                    }))
                    .build();
                (bridge, None, deploy)
            }
            Deployment::Script => {
                let create = new_bridge_script_message();
                let bridge = create.dst().expect("the creation message names the bridge");
                let fund = MessageBuilder::internal(deployer.address(), &bridge, 50 * TOS)
                    .bounce(false)
                    .build();
                (bridge, Some(fund), create)
            }
        };

        let mut net = Self {
            bc,
            oracles,
            deployer,
            users,
            stranger,
            bridge: bridge.clone(),
            minters: BTreeMap::new(),
            queue: VecDeque::new(),
            delivered: Vec::new(),
            logs: Vec::new(),
            model: Model { enabled: true, ..Model::default() },
            gas_seen: BTreeMap::new(),
            next_nonce: 0,
            burn_fee: BURN_FEE,
            mint_fee: MINT_FEE,
            traced: 0,
            state_flags: 0,
        };
        net.configure();
        net.configure_limits(65_536, 65_536);
        if let Some(fund) = fund {
            net.send(fund);
        }
        let tx = net.send(deploy);
        succeeded(&tx);
        if matches!(how, Deployment::Script) {
            // The script's stub only installs the code; the bridge's first
            // internal transaction fixes its life.
            let poke = MessageBuilder::internal(net.deployer.address(), &bridge, TOS)
                .bounce(false)
                .body(cell(|b| {
                    b.append_u32(OP_EXCESSES).unwrap().append_u64(0).unwrap();
                }))
                .build();
            succeeded(&net.send(poke));
        }
        let code = net.bc.get_account(&bridge).and_then(|a| a.get_code()).expect("deployed");
        assert_eq!(code.repr_hash(), codes().bridge.repr_hash(), "the bridge runs jetton-bridge.fc");
        net
    }

    /// ConfigParam 79, naming this bridge, the oracles and the counterparty.
    pub fn configure(&mut self) {
        let bridge = self.bridge.clone();
        self.configure_with(&bridge, self.state_flags, self.burn_fee, self.mint_fee, Some(EVM_BRIDGE));
    }

    pub fn configure_with(
        &mut self,
        bridge: &MsgAddressInt,
        state_flags: u8,
        burn_fee: u64,
        mint_fee: u64,
        external: Option<[u8; 20]>,
    ) {
        let oracles = self.oracles.address().clone();
        let param = cell(|b| {
            b.append_u8(0).unwrap();
            b.append_raw(&account_hash(bridge), 256).unwrap();
            b.append_raw(&account_hash(&oracles), 256).unwrap();
            b.append_bit_zero().unwrap(); // oracle keys, unused on this side
            b.append_u8(state_flags).unwrap();
            b.checked_append_reference(cell(|p| {
                coins(p, burn_fee.into());
                coins(p, mint_fee.into());
                coins(p, (TOS / 20).into());
                coins(p, (TOS / 50).into());
                coins(p, (TOS / 10).into());
                coins(p, (TOS / 100).into());
            }))
            .unwrap();
            if let Some(external) = external {
                b.append_raw(&[0u8; 12], 96).unwrap();
                b.append_raw(&external, 160).unwrap();
            }
        });
        self.burn_fee = burn_fee;
        self.mint_fee = mint_fee;
        let mut config = self.bc.config_params().clone();
        config.set_config(ConfigParamEnum::ConfigParamAny(CONFIG_PARAM, param)).expect("param 79");
        // The native replay completes the configuration with ConfigParam 0;
        // stating it here keeps both engines' dictionaries, and so the gas of
        // every configuration lookup, identical.
        if config.config(0).expect("param 0").is_none() {
            let config_addr = config.config_addr.clone();
            config
                .set_config(ConfigParamEnum::ConfigParam0(chain_block::ConfigParam0 { config_addr }))
                .expect("param 0");
        }
        if config.config(31).expect("param 31").is_none() {
            config
                .set_config(ConfigParamEnum::ConfigParam31(chain_block::ConfigParam31 {
                    fundamental_smc_addr: chain_block::FundamentalSmcAddresses::default(),
                }))
                .expect("the fundamental contracts are listed");
        }
        self.bc.set_config(config).expect("the chain adopts it");
    }

    /// Removes ConfigParam 79 (and -79): the bridge's configuration is gone.
    pub fn remove_config(&mut self) {
        let mut config = self.bc.config_params().clone();
        let mut k = BuilderData::new();
        k.append_u32(CONFIG_PARAM).unwrap();
        config.config_params.remove(SliceData::load_builder(k).unwrap()).expect("remove 79");
        self.bc.set_config(config).expect("the chain adopts it");
    }

    /// ConfigParam 43's account cell limits, set explicitly so both engines
    /// read the same value instead of each one's default.
    pub fn configure_limits(&mut self, basechain: u32, masterchain: u32) {
        let mut config = self.bc.config_params().clone();
        let mut limits = config.size_limits_config().expect("size limits");
        limits.max_acc_state_cells = basechain;
        limits.max_mc_acc_state_cells = masterchain;
        config.set_config(ConfigParamEnum::ConfigParam43(limits)).expect("param 43");
        self.bc.set_config(config).expect("the chain adopts it");
    }

    /// ConfigParam 8: the global version, keeping the capabilities.
    pub fn set_global_version(&mut self, version: u32) {
        let mut config = self.bc.config_params().clone();
        let mut gv = config.get_global_version().expect("param 8");
        gv.version = version;
        config
            .set_config(ConfigParamEnum::ConfigParam8(chain_block::ConfigParam8 { global_version: gv }))
            .expect("param 8");
        self.bc.set_config(config).expect("the chain adopts it");
    }

    pub fn set_gas_price(&mut self, masterchain: bool, gas_price: u64) {
        let mut config = self.bc.config_params().clone();
        let mut prices = config.gas_prices(masterchain).expect("gas prices");
        prices.gas_price = gas_price;
        let param = if masterchain {
            ConfigParamEnum::ConfigParam20(prices)
        } else {
            ConfigParamEnum::ConfigParam21(prices)
        };
        config.set_config(param).expect("gas prices");
        self.bc.set_config(config).expect("the chain adopts it");
    }

    pub fn gas_price(&self, masterchain: bool) -> u64 {
        self.bc.config_params().gas_prices(masterchain).expect("gas prices").gas_price
    }

    /// Lists `addr` among the special accounts (ConfigParam 31), or removes it.
    pub fn set_special(&mut self, addr: &MsgAddressInt, special: bool) {
        let mut config = self.bc.config_params().clone();
        let mut list = config.fundamental_smc_addr().expect("param 31");
        let key = UInt256::from_slice(&account_hash(addr));
        if special {
            list.add_key(&key).expect("listed");
        } else {
            list.remove(&key).expect("unlisted");
        }
        config
            .set_config(ConfigParamEnum::ConfigParam31(chain_block::ConfigParam31 {
                fundamental_smc_addr: list,
            }))
            .expect("param 31");
        self.bc.set_config(config).expect("the chain adopts it");
    }

    // ---- delivery ----

    pub fn deliver_one(&mut self) -> Delivery {
        let msg = self.queue.pop_front().expect("a message to deliver");
        self.execute(msg)
    }

    /// Executes `msg` now, ahead of the queue, and queues what it sends.
    pub fn execute(&mut self, msg: Message) -> Delivery {
        let dst = msg.dst().expect("a destination");
        let account = self.bc.get_account(&dst).cloned().unwrap_or_default();
        let before = self.model.snapshot(self, &dst);
        let exposure = self.model.exposure(self, &dst);
        let (addr, tx, outs) = self.bc.execute_one(msg.clone()).expect("the executor runs");
        if let Some(dir) = trace_dir() {
            self.record(&dir, &msg, &account, &addr, &tx);
        }
        for out in &outs {
            if out.is_internal() {
                self.queue.push_back(out.clone());
            } else {
                let header = out.ext_out_header().expect("an external header");
                let topic = match &header.dst {
                    MsgAddressExt::AddrExtern(ext) => {
                        let bytes = ext.external_address.get_bytestring(0);
                        u32::from_be_bytes(bytes[bytes.len() - 4..].try_into().expect("a topic"))
                    }
                    MsgAddressExt::AddrNone => 0,
                };
                self.logs.push((addr.clone(), topic, out.clone()));
            }
        }
        self.check_gas(&addr, &msg, &tx);
        let after = self.model.snapshot(self, &addr);
        let balance_before = account.balance().map(|b| b.coins.as_u128()).unwrap_or(0);
        let delivery = Delivery { balance_before, addr, msg, tx, outs };
        let mut model = std::mem::take(&mut self.model);
        model.lifecycle(self, &delivery.addr, exposure);
        model.observe(self, &delivery, before, after);
        self.model = model;
        self.delivered.push(Delivery {
            balance_before: delivery.balance_before,
            addr: delivery.addr.clone(),
            msg: delivery.msg.clone(),
            tx: delivery.tx.clone(),
            outs: delivery.outs.clone(),
        });
        delivery
    }

    /// Every settlement step stays within the gas its contract declares and
    /// prices into every budget; a step over it would leave its successor
    /// underfunded at worst-case occupancy.
    fn check_gas(&mut self, addr: &MsgAddressInt, msg: &Message, tx: &Transaction) {
        if msg.int_header().is_some_and(|h| h.bounced) {
            return;
        }
        let Some(op) = body_op(msg) else { return };
        let code = self.bc.get_account(addr).and_then(|a| a.get_code());
        let Some(code) = code else { return };
        let codes = codes();
        let kind = if code.repr_hash() == codes.bridge.repr_hash() {
            "bridge"
        } else if code.repr_hash() == codes.minter.repr_hash() {
            "minter"
        } else if code.repr_hash() == codes.wallet.repr_hash() {
            "wallet"
        } else {
            return;
        };
        let settlement = (40..=63).contains(&op) || op == OP_BURN || op == OP_EXECUTE_VOTING;
        if !settlement {
            return;
        }
        let mut body = msg.body().expect("a body").clone();
        let sub = match op {
            op::ADVANCE | OP_EXECUTE_VOTING => {
                let _ = body.get_next_u32();
                let _ = body.get_next_u64();
                body.get_next_byte().unwrap_or(0)
            }
            _ => 0,
        };
        let gas = outcome(tx).gas_used;
        let entry = self.gas_seen.entry((kind, op, sub)).or_insert(0);
        *entry = (*entry).max(gas);
        let budget = match kind {
            "bridge" if op == OP_EXECUTE_VOTING => declared("BRIDGE_VOTE_GAS"),
            "bridge" => declared("BRIDGE_STEP_GAS"),
            "wallet" => declared("WALLET_STEP_GAS"),
            _ if op == op::OPENED || (op == op::ADVANCE && sub == advance::STRAND) => declared("MINTER_BATCH_GAS"),
            _ => declared("MINTER_STEP_GAS"),
        } as u64;
        assert!(gas <= budget, "{kind} op {op}/{sub} used {gas} gas, over its declared {budget}");
    }

    pub fn send(&mut self, msg: Message) -> Transaction {
        let d = self.execute(msg);
        self.settle();
        d.tx
    }

    /// Delivers `msg` alone; what it sends stays queued.
    pub fn send_one(&mut self, msg: Message) -> Transaction {
        self.execute(msg).tx
    }

    pub fn settle(&mut self) {
        let mut steps = 0;
        while !self.queue.is_empty() {
            steps += 1;
            assert!(steps < 4096, "the cascade does not end");
            self.deliver_one();
        }
    }

    /// Delivers until the next message is one `stop` names, and leaves it queued.
    pub fn deliver_until(&mut self, stop: impl Fn(&Message) -> bool) {
        let mut steps = 0;
        while let Some(next) = self.queue.front() {
            if stop(next) {
                return;
            }
            steps += 1;
            assert!(steps < 4096, "the cascade does not end");
            self.deliver_one();
        }
        panic!("the cascade ended before the awaited message");
    }

    /// Takes the first queued message `pick` names out of the queue.
    pub fn take(&mut self, pick: impl Fn(&Message) -> bool) -> Message {
        let index = self.queue.iter().position(|m| pick(m)).expect("a queued message to take");
        self.queue.remove(index).expect("the message")
    }

    /// Delivers until a message `pick` names is queued, and takes it out.
    pub fn intercept(&mut self, pick: impl Fn(&Message) -> bool) -> Message {
        let mut steps = 0;
        loop {
            if let Some(index) = self.queue.iter().position(|m| pick(m)) {
                return self.queue.remove(index).expect("the message");
            }
            steps += 1;
            assert!(steps < 4096, "the cascade does not end");
            assert!(!self.queue.is_empty(), "the cascade ended before the awaited message");
            self.deliver_one();
        }
    }

    pub fn drop_op(&mut self, op: u32) -> Message {
        self.intercept(|m| body_op(m) == Some(op))
    }

    /// The data hash of every bridge, minter and wallet account.
    pub fn state_hashes(&self) -> Vec<(String, Option<UInt256>)> {
        let mut all: Vec<MsgAddressInt> = vec![self.bridge.clone(), self.minter()];
        all.extend(self.minters.values().cloned());
        for u in &self.users {
            all.push(self.wallet_of(u.address()));
        }
        all.push(self.wallet_of(self.stranger.address()));
        all.iter()
            .map(|a| (a.to_string(), self.bc.get_account(a).and_then(|x| x.get_data_hash())))
            .collect()
    }

    /// Every transaction since `from` that exited with `code`.
    pub fn exits_since(&self, from: usize, code: i32) -> usize {
        self.delivered[from..].iter().filter(|d| outcome(&d.tx).exit_code == Some(code)).count()
    }

    /// No settlement message was ever bounced: none is bounceable.
    pub fn assert_no_settlement_bounce(&self) {
        for d in &self.delivered {
            for m in &d.outs {
                if let Some(h) = m.int_header() {
                    if h.bounced {
                        let mut s = m.body().unwrap().clone();
                        s.get_next_u32().ok();
                        let op = s.get_next_u32().ok().unwrap_or(0);
                        // advance and cancel_burn are a caller's own messages and may bounce
                        let callers = op == op::ADVANCE || op == op::CANCEL_BURN;
                        assert!(callers || !(40..=63).contains(&op), "a settlement message bounced: op {op}");
                    }
                }
            }
        }
    }

    /// Prints every delivered transaction: where, which opcode, and how it ended.
    pub fn dump(&self) {
        for d in &self.delivered_log() {
            eprintln!("{d}");
        }
    }

    pub fn delivered_log(&self) -> Vec<String> {
        self.delivered
            .iter()
            .map(|d| {
                let o = outcome(&d.tx);
                let who = if d.addr == self.bridge {
                    "bridge".to_string()
                } else if self.minters.values().any(|m| *m == d.addr) || d.addr == self.minter() {
                    "minter".to_string()
                } else {
                    d.addr.to_string()[..12].to_string()
                };
                let outs: Vec<String> = d
                    .outs
                    .iter()
                    .map(|m| match body_op(m) {
                        Some(op) => format!("{op}"),
                        None => "ext".into(),
                    })
                    .collect();
                format!(
                    "{who:>14} op {:>10?} exit {:?} aborted {} gas {} action {} -> {:?}",
                    body_op(&d.msg),
                    o.exit_code,
                    o.aborted,
                    o.gas_used,
                    o.action_ok,
                    outs
                )
            })
            .collect()
    }

    // ---- getters ----

    pub fn get(
        &self,
        addr: &MsgAddressInt,
        method: &str,
        args: Vec<StackItem>,
    ) -> tos_sandbox::GetMethodResult {
        let result = self
            .bc
            .run_get_method_with_gas(addr, method, args, 10_000_000)
            .expect("the get-method runs");
        result.expect_success();
        result
    }

    pub fn try_get(
        &self,
        addr: &MsgAddressInt,
        method: &str,
        args: Vec<StackItem>,
    ) -> Option<tos_sandbox::GetMethodResult> {
        let account = self.bc.get_account(addr)?;
        account.get_code()?;
        let result = self.bc.run_get_method_with_gas(addr, method, args, 10_000_000).ok()?;
        (result.exit_code == 0).then_some(result)
    }

    pub fn minter(&self) -> MsgAddressInt {
        self.minter_of(0x5a)
    }

    pub fn minter_of(&self, token: u8) -> MsgAddressInt {
        if let Some(m) = self.minters.get(&token) {
            return m.clone();
        }
        let r = self.get(&self.bridge, "get_minter_address", vec![StackItem::cell(wrapped_token_data(token))]);
        MsgAddressInt::construct_from(&mut r.slice_at(0)).expect("a minter")
    }

    pub fn user(&self, i: usize) -> MsgAddressInt {
        self.users[i].address().clone()
    }

    pub fn wallet_of(&self, owner: &MsgAddressInt) -> MsgAddressInt {
        self.wallet_in(&self.minter(), owner)
    }

    pub fn wallet_in(&self, minter: &MsgAddressInt, owner: &MsgAddressInt) -> MsgAddressInt {
        let init = wallet_state_init(minter, owner);
        MsgAddressInt::with_params(0, init.serialize().expect("a state init").repr_hash())
            .expect("a wallet address")
    }

    pub fn tokens(&self, owner: &MsgAddressInt) -> u128 {
        let wallet = self.wallet_of(owner);
        self.try_get(&wallet, "get_wallet_data", vec![])
            .map(|r| r.int_at(0) as u128)
            .unwrap_or(0)
    }

    pub fn wallet_state(&self, owner: &MsgAddressInt) -> Vec<i128> {
        let wallet = self.wallet_of(owner);
        let r = self.get(&wallet, "get_settlement_state", vec![]);
        (0..10).map(|i| r.int_at(i)).collect()
    }

    pub fn held(&self, owner: &MsgAddressInt, b: u64) -> i128 {
        let wallet = self.wallet_of(owner);
        self.try_get(&wallet, "get_burn", vec![int_arg(b)]).map(|r| r.int_at(0)).unwrap_or(-1)
    }

    /// (signed supply, in flight, mint reserve, burn reserve, stranded)
    pub fn supply_state(&self) -> (i128, i128, i128, i128, i128) {
        self.supply_state_of(&self.minter())
    }

    pub fn supply_state_of(&self, minter: &MsgAddressInt) -> (i128, i128, i128, i128, i128) {
        match self.try_get(minter, "get_supply_state", vec![]) {
            Some(r) => (r.int_at(0), r.int_at(1), r.int_at(2), r.int_at(3), r.int_at(4)),
            None => (0, 0, 0, 0, 0),
        }
    }

    pub fn supply(&self) -> i128 {
        self.supply_state().0
    }

    /// The minter's channel state (see get_channels).
    pub fn minter_channels(&self) -> Vec<i128> {
        let r = self.get(&self.minter(), "get_channels", vec![]);
        (0..11).map(|i| r.int_at(i)).collect()
    }

    /// (status or -1, bound life, k, escrow, owner, amount)
    pub fn mint(&self, s: u64) -> (i128, i128, i128, i128) {
        let r = self.get(&self.minter(), "get_mint", vec![int_arg(s)]);
        (r.int_at(0), r.int_at(1), r.int_at(2), r.int_at(5))
    }

    pub fn mint_status(&self, s: u64) -> i128 {
        match self.try_get(&self.minter(), "get_mint", vec![int_arg(s)]) {
            Some(r) => r.int_at(0),
            None => -1,
        }
    }

    pub fn holder(&self, owner: &MsgAddressInt) -> Vec<i128> {
        let r = self.get(&self.minter(), "get_holder", vec![addr_arg(owner)]);
        (0..15).map(|i| r.int_at(i)).collect()
    }

    /// (where, status, cancel, m, amount)
    pub fn minter_burn(&self, owner: &MsgAddressInt, b: u64) -> (i128, i128, i128, i128, i128) {
        let r = self.get(&self.minter(), "get_burn", vec![addr_arg(owner), int_arg(b)]);
        (r.int_at(0), r.int_at(1), r.int_at(2), r.int_at(3), r.int_at(4))
    }

    pub fn bridge_state(&self) -> Vec<i128> {
        let r = self.get(&self.bridge, "get_bridge_state", vec![]);
        // index 2 is the 160-bit counterparty address, wider than i128
        (0..8).map(|i| if i == 2 { 0 } else { r.int_at(i) }).collect()
    }

    pub fn bridge_life(&self) -> u64 {
        self.bridge_state()[0] as u64
    }

    /// (state or -1, fee, s)
    pub fn swap_record(&self, n: u64) -> (i128, i128, i128) {
        let r = self.get(&self.bridge, "get_swap", vec![int_arg(n)]);
        (r.int_at(0), r.int_at(1), r.int_at(2))
    }

    pub fn channel(&self) -> Vec<i128> {
        self.channel_of(&self.minter())
    }

    pub fn channel_of(&self, minter: &MsgAddressInt) -> Vec<i128> {
        let r = self.get(&self.bridge, "get_channel", vec![addr_arg(minter)]);
        (0..11).map(|i| r.int_at(i)).collect()
    }

    pub fn pending(&self, s: u64) -> i128 {
        let r = self.get(&self.bridge, "get_pending_mint", vec![addr_arg(&self.minter()), int_arg(s)]);
        r.int_at(0)
    }

    pub fn burn_outcome(&self, m: u64) -> i128 {
        let r = self.get(&self.bridge, "get_burn_outcome", vec![addr_arg(&self.minter()), int_arg(m)]);
        r.int_at(0)
    }

    pub fn balance(&self, addr: &MsgAddressInt) -> u128 {
        self.bc
            .get_account(addr)
            .and_then(|a| a.balance().cloned())
            .map(|b| b.coins.as_u128())
            .unwrap_or(0)
    }

    pub fn set_balance(&mut self, addr: &MsgAddressInt, balance: u128) {
        let mut account = self.bc.get_account(addr).expect("deployed").clone();
        account.set_balance(chain_block::CurrencyCollection::with_coins(balance as u64));
        self.bc.set_account(addr.clone(), account);
    }

    pub fn logs_from(&self, addr: &MsgAddressInt, topic: u32) -> usize {
        self.logs.iter().filter(|(a, t, _)| a == addr && *t == topic).count()
    }

    pub fn burn_logs(&self) -> usize {
        self.logs_from(&self.bridge, LOG_BURN)
    }

    // ---- the operations ----

    pub fn vote(&mut self, query: u64, voting: Cell) -> Message {
        // what the oracles attach to a vote: enough for its gas and records
        MessageBuilder::internal(self.oracles.address(), &self.bridge, 2 * TOS)
            .body(cell(|b| {
                b.append_u32(OP_EXECUTE_VOTING).unwrap().append_u64(query).unwrap();
                b.checked_append_references_and_data(&SliceData::load_cell(voting).unwrap()).unwrap();
            }))
            .build()
    }

    pub fn activation(&self, bridge_hash: &[u8], life: u64, generation: u32, start: u64) -> Cell {
        cell(|b| {
            b.append_u8(8).unwrap();
            b.append_raw(bridge_hash, 256).unwrap();
            b.append_u64(life).unwrap();
            b.append_u32(generation).unwrap();
            b.append_u64(start).unwrap();
        })
    }

    pub fn activate(&mut self, generation: u32, start: u64) {
        let life = self.bridge_life();
        let voting = self.activation(&account_hash(&self.bridge), life, generation, start);
        let vote = self.vote(1, voting);
        succeeded(&self.send(vote));
        self.next_nonce = start;
    }

    pub fn pay(&mut self, n: u64) -> Transaction {
        let payer = self.stranger.address().clone();
        self.pay_from(&payer, GENERATION, n, self.mint_fee)
    }

    pub fn pay_from(&mut self, payer: &MsgAddressInt, generation: u32, n: u64, value: u64) -> Transaction {
        let pay = MessageBuilder::internal(payer, &self.bridge, value)
            .bounce(true)
            .body(cell(|b| {
                b.append_u32(OP_PAY_SWAP).unwrap().append_u64(0).unwrap();
                b.append_u32(generation).unwrap();
                b.append_u64(n).unwrap();
            }))
            .build();
        // Only the payment: whatever else is queued keeps waiting.
        let d = self.execute(pay);
        let bounced: Vec<Message> = d.outs.iter().filter(|m| m.is_internal()).cloned().collect();
        for m in bounced {
            let index = self.queue.iter().rposition(|q| *q == m).expect("the queued answer");
            let m = self.queue.remove(index).expect("the answer");
            self.execute(m);
        }
        d.tx
    }

    pub fn swap_voting(&self, generation: u32, n: u64, recipient: &MsgAddressInt, amount: u128, token: u8) -> Cell {
        cell(|b| {
            b.append_u8(0).unwrap();
            b.append_u32(generation).unwrap();
            b.append_u64(n).unwrap();
            b.append_u32(CHAIN_ID).unwrap();
            b.append_raw(&EVM_BRIDGE, 160).unwrap();
            b.append_raw(&account_hash(recipient), 256).unwrap();
            coins(b, amount);
            b.checked_append_reference(wrapped_token_data(token)).unwrap();
        })
    }

    /// Pays for lock n and queues its vote.
    pub fn start_swap_to(&mut self, recipient: &MsgAddressInt, amount: u128) -> u64 {
        self.start_swap_token(recipient, amount, 0x5a)
    }

    pub fn start_swap_token(&mut self, recipient: &MsgAddressInt, amount: u128, token: u8) -> u64 {
        let n = self.next_nonce;
        self.next_nonce = self.next_nonce.saturating_add(1);
        succeeded(&self.pay(n));
        let voting = self.swap_voting(GENERATION, n, recipient, amount, token);
        let vote = self.vote(n.wrapping_add(100), voting);
        self.queue.push_back(vote);
        n
    }

    pub fn start_swap(&mut self, amount: u128) -> u64 {
        let user = self.user(0);
        self.start_swap_to(&user, amount)
    }

    pub fn swap(&mut self, amount: u128) -> u64 {
        let n = self.start_swap(amount);
        self.settle();
        n
    }

    pub fn swap_to(&mut self, recipient: &MsgAddressInt, amount: u128) -> u64 {
        let n = self.start_swap_to(recipient, amount);
        self.settle();
        n
    }

    pub fn cancel_lock_vote(&self, generation: u32, n: u64) -> Cell {
        cell(|b| {
            b.append_u8(9).unwrap();
            b.append_u32(generation).unwrap();
            b.append_u64(n).unwrap();
        })
    }

    pub fn burn_message(&self, owner: &MsgAddressInt, amount: u128, value: u64) -> Message {
        let wallet = self.wallet_of(owner);
        let user = owner.clone();
        MessageBuilder::internal(&user, &wallet, value)
            .bounce(true)
            .body(cell(|b| {
                b.append_u32(OP_BURN).unwrap().append_u64(7).unwrap();
                coins(b, amount);
                user.write_to(b).unwrap();
                b.append_bit_one().unwrap();
                b.checked_append_reference(cell(|d| {
                    d.append_raw(&DESTINATION, 160).unwrap();
                }))
                .unwrap();
            }))
            .build()
    }

    /// Queues `owner`'s burn of `amount`.
    pub fn start_burn_from(&mut self, owner: &MsgAddressInt, amount: u128) {
        let burn = self.burn_message(owner, amount, self.burn_fee);
        self.queue.push_back(burn);
    }

    pub fn start_burn(&mut self, amount: u128) {
        let user = self.user(0);
        self.start_burn_from(&user, amount);
    }

    pub fn cancel_message(&self, owner: &MsgAddressInt, b: u64, value: u64) -> Message {
        let wallet = self.wallet_of(owner);
        MessageBuilder::internal(owner, &wallet, value)
            .bounce(true)
            .body(cell(|x| {
                x.append_u32(op::CANCEL_BURN).unwrap().append_u64(0).unwrap();
                x.append_u64(b).unwrap();
            }))
            .build()
    }

    /// An advance from the stranger to `to`, of `value`, with `args` after the kind.
    pub fn advance_message(&self, to: &MsgAddressInt, kind: u8, value: u64, args: impl FnOnce(&mut BuilderData)) -> Message {
        MessageBuilder::internal(self.stranger.address(), to, value)
            .bounce(true)
            .body(cell(|b| {
                b.append_u32(op::ADVANCE).unwrap().append_u64(0).unwrap();
                b.append_u8(kind).unwrap();
                args(b);
            }))
            .build()
    }

    /// (need, quote) of an advance, from the contract's own get-method.
    pub fn bridge_advance_cost(&self, kind: u8, s: u64) -> (u64, u64) {
        let r = self.get(
            &self.bridge,
            "get_advance_cost",
            vec![int_arg(kind as u64), addr_arg(&self.minter()), int_arg(s)],
        );
        (r.int_at(0) as u64, r.int_at(1) as u64)
    }

    pub fn minter_advance_cost(&self, kind: u8, owner: &MsgAddressInt) -> (u64, u64) {
        let r = self.get(&self.minter(), "get_advance_cost", vec![int_arg(kind as u64), addr_arg(owner)]);
        (r.int_at(0) as u64, r.int_at(1) as u64)
    }

    pub fn wallet_advance_cost(&self, owner: &MsgAddressInt, kind: u8) -> (u64, u64) {
        let r = self.get(&self.wallet_of(owner), "get_advance_cost", vec![int_arg(kind as u64)]);
        (r.int_at(0) as u64, r.int_at(1) as u64)
    }

    pub fn advance_bridge_mint(&mut self, s: u64) -> Transaction {
        let (_, quote) = self.bridge_advance_cost(advance::MINT, s);
        let minter = self.minter();
        let msg = self.advance_message(&self.bridge.clone(), advance::MINT, quote, |b| {
            b.append_raw(&account_hash(&minter), 256).unwrap();
            b.append_u64(s).unwrap();
        });
        self.send(msg)
    }

    pub fn advance_bridge_burn_result(&mut self, m: u64) -> Transaction {
        let (_, quote) = self.bridge_advance_cost(advance::BURN_RESULT, 0);
        let minter = self.minter();
        let msg = self.advance_message(&self.bridge.clone(), advance::BURN_RESULT, quote, |b| {
            b.append_raw(&account_hash(&minter), 256).unwrap();
            b.append_u64(m).unwrap();
        });
        self.send(msg)
    }

    pub fn advance_bridge_sync(&mut self) -> Transaction {
        let (_, quote) = self.bridge_advance_cost(advance::SYNC, 0);
        let minter = self.minter();
        let msg = self.advance_message(&self.bridge.clone(), advance::SYNC, quote, |b| {
            b.append_raw(&account_hash(&minter), 256).unwrap();
        });
        self.send(msg)
    }

    pub fn advance_minter_mint(&mut self, s: u64) -> Transaction {
        let owner = MsgAddressInt::with_params(0, UInt256::default()).unwrap();
        let (_, quote) = self.minter_advance_cost(advance::MINT, &owner);
        // The need depends on the mint's own recipient; quote for the largest.
        let quote = quote + TOS;
        let minter = self.minter();
        let msg = self.advance_message(&minter, advance::MINT, quote, |b| {
            b.append_u64(s).unwrap();
        });
        self.send(msg)
    }

    pub fn advance_minter(&mut self, kind: u8, owner: &MsgAddressInt, extra: Option<u64>) -> Transaction {
        let (_, quote) = self.minter_advance_cost(kind, owner);
        let minter = self.minter();
        let owner = owner.clone();
        let msg = self.advance_message(&minter, kind, quote, |b| {
            b.append_raw(&account_hash(&owner), 256).unwrap();
            if let Some(x) = extra {
                b.append_u64(x).unwrap();
            }
        });
        self.send(msg)
    }

    pub fn advance_minter_sync(&mut self, channel: u8, owner: Option<&MsgAddressInt>) -> Transaction {
        let probe = owner.cloned().unwrap_or_else(|| self.user(0));
        let (_, quote) = self.minter_advance_cost(advance::SYNC, &probe);
        let minter = self.minter();
        let owner = owner.cloned();
        let msg = self.advance_message(&minter, advance::SYNC, quote, |b| {
            b.append_u8(channel).unwrap();
            if let Some(o) = owner {
                b.append_raw(&account_hash(&o), 256).unwrap();
            }
        });
        self.send(msg)
    }

    pub fn advance_wallet(&mut self, owner: &MsgAddressInt, kind: u8, arg: Option<u64>) -> Transaction {
        let (_, quote) = self.wallet_advance_cost(owner, kind);
        let wallet = self.wallet_of(owner);
        let msg = self.advance_message(&wallet, kind, quote, |b| {
            if let Some(x) = arg {
                b.append_u64(x).unwrap();
            }
        });
        self.send(msg)
    }

    /// Opens `owner`'s wallet through its own funded request.
    pub fn open_wallet(&mut self, owner: &MsgAddressInt) -> Transaction {
        self.advance_wallet(owner, advance::OPEN, None)
    }

    /// The user's wallet sends `amount` to `to`'s wallet.
    pub fn transfer(&mut self, from: &MsgAddressInt, to: &MsgAddressInt, amount: u128) -> Message {
        let wallet = self.wallet_of(from);
        let from = from.clone();
        MessageBuilder::internal(&from, &wallet, TOS)
            .body(cell(|b| {
                b.append_u32(OP_TRANSFER).unwrap().append_u64(3).unwrap();
                coins(b, amount);
                to.write_to(b).unwrap();
                from.write_to(b).unwrap();
                b.append_bit_zero().unwrap(); // no custom payload
                coins(b, 0);
                b.append_bit_zero().unwrap(); // no forward payload
            }))
            .build()
    }

    /// Removes an account, as the chain does when it deletes one for storage debt.
    pub fn delete_account(&mut self, addr: &MsgAddressInt) {
        let mut model = std::mem::take(&mut self.model);
        model.account_deleted(self, addr);
        self.model = model;
        self.bc.set_account(addr.clone(), chain_block::Account::default());
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
        let (exit_code, skipped, gas_used) = match &d.compute_ph {
            TrComputePhase::Vm(vm) => (Some(vm.exit_code), false, Some(vm.gas_used.as_u64())),
            TrComputePhase::Skipped(_) => (None, true, None),
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
                // an empty inline body is the empty cell, as the native engine reports it
                .unwrap_or_else(|| Cell::default().repr_hash().as_hex_string());
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
            "lt": tx.logical_time().to_string(),
            "config": boc(config),
            "shard_account": boc(shard_account.serialize().expect("a shard account cell")),
            "message": boc(msg.serialize().expect("a message cell")),
            "expect": {
                "gas_used": gas_used,
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
}

/// Where to record every transaction for replay in the native engine, if set.
pub fn trace_dir() -> Option<PathBuf> {
    std::env::var_os("TOKEN_BRIDGE_TRACE_DIR").map(PathBuf::from)
}

/// The initial state of `owner`'s wallet under `minter`: jetton-wallet.fc's
/// layout with an empty settlement half (utils.fc, pack_jetton_wallet_data).
pub fn wallet_state_init(minter: &MsgAddressInt, owner: &MsgAddressInt) -> StateInit {
    let data = cell(|b| {
        coins(b, 0);
        owner.write_to(b).unwrap();
        minter.write_to(b).unwrap();
        b.checked_append_reference(codes().wallet.clone()).unwrap();
        b.checked_append_reference(cell(|s| {
            s.append_raw(&[0u8; 45], 64 + 64 + 1 + 32 + 64 + 64 + 64).unwrap();
            s.append_bit_zero().unwrap();
            s.append_raw(&[0u8; 16], 64 + 64).unwrap();
            s.append_bit_zero().unwrap();
        }))
        .unwrap();
    });
    StateInit::with_code_and_data(codes().wallet.clone(), data)
}

/// A message from `from` to `to` carrying `body`, as a contract would send it.
pub fn forged(from: &MsgAddressInt, to: &MsgAddressInt, value: u64, body: Cell) -> Message {
    MessageBuilder::internal(from, to, value).bounce(false).body(body).build()
}

/// A bounced copy of `msg`, as the network would return it to its sender.
pub fn bounced_copy(msg: &Message) -> Message {
    let header = msg.int_header().expect("an internal message");
    let original = settlement_body(msg);
    let body = cell(|b| {
        b.append_u32(0xffff_ffff).unwrap();
        let mut s = original.clone();
        let bits = s.remaining_bits().min(256);
        b.append_bytestring(&s.get_next_slice(bits).unwrap()).unwrap();
    });
    let mut bounce = MessageBuilder::internal(&header.dst, &header.src_ref().expect("a source").clone(), 1)
        .bounce(false)
        .body(body)
        .build();
    if let Some(h) = bounce.int_header_mut() {
        h.bounced = true;
    }
    bounce
}

/// Every account that held state before still holds the same state. A failed
/// deployment is exempt: one engine leaves an empty account behind, the other
/// creates none, and neither holds anything a later message could use.
pub fn assert_unchanged(net: &Net, before: &[(String, Option<UInt256>)], what: &str) {
    let after = net.state_hashes();
    for ((addr, b), (_, a)) in before.iter().zip(after.iter()) {
        if b.is_some() {
            assert_eq!(b, a, "{what} changed the state of {addr}");
        }
    }
}

/// A leg stopped for funds: its funding check refused it, or it ran out of gas
/// before it got there. Either way it applied nothing.
pub fn stopped_for_funds(tx: &Transaction) {
    let o = outcome(tx);
    assert!(o.aborted, "the leg went through");
    assert!(
        o.exit_code == Some(err("underfunded")) || o.exit_code == Some(-14),
        "stopped for another reason: {:?}",
        o.exit_code
    );
}

/// What forwarding `msg` costs as the network charges it: every cell but the
/// root, at the masterchain's prices when `masterchain`.
pub fn forward_fee_of(net: &Net, msg: &Message, masterchain: bool) -> u128 {
    fn visit(c: &Cell, seen: &mut std::collections::HashSet<UInt256>, cells: &mut u128, bits: &mut u128) {
        for i in 0..c.references_count() {
            let child = c.reference(i).expect("a reference");
            if seen.insert(child.repr_hash()) {
                *cells += 1;
                *bits += child.bit_length() as u128;
                visit(&child, seen, cells, bits);
            }
        }
    }
    let root = msg.serialize().expect("a message cell");
    let (mut cells, mut bits) = (0u128, 0u128);
    visit(&root, &mut std::collections::HashSet::new(), &mut cells, &mut bits);
    let prices = net.bc.config_params().fwd_prices(masterchain).expect("forward prices");
    u128::from(prices.lump_price)
        + ((u128::from(prices.bit_price) * bits + u128::from(prices.cell_price) * cells + 0xffff) >> 16)
}

/// A minter's initial state: utils.fc, pack_minter_initial_data, with the
/// bridge pinned in.
pub fn minter_state_init(bridge: &MsgAddressInt, token: u8) -> StateInit {
    let data = cell(|b| {
        b.append_raw(&[0u8; 16], 128).unwrap();
        for _ in 0..4 {
            coins(b, 0);
        }
        b.checked_append_reference(wrapped_token_data(token)).unwrap();
        b.checked_append_reference(codes().wallet.clone()).unwrap();
        b.checked_append_reference(cell(|a| {
            bridge.write_to(a).unwrap();
            a.append_raw(&[0u8; 17], 129).unwrap();
            a.append_raw(&[0u8; 16], 128).unwrap();
            a.append_raw(&[0u8; 16], 128).unwrap();
            a.append_u32(0).unwrap();
            a.append_bit_zero().unwrap();
            a.append_bit_zero().unwrap();
            a.append_bit_zero().unwrap();
        }))
        .unwrap();
    });
    StateInit::with_code_and_data(codes().minter.clone(), data)
}

impl Net {
    /// Deploys `init` at its address with a plain top-up: what any sender of a
    /// StateInit-carrying message does to an account that does not exist.
    pub fn deploy_initial(&mut self, init: StateInit, workchain: i32) -> MsgAddressInt {
        let addr = MsgAddressInt::with_params(workchain, init.serialize().unwrap().repr_hash()).unwrap();
        let from = self.deployer.address().clone();
        let msg = MessageBuilder::internal(&from, &addr, 5 * TOS).bounce(false).state_init(init).build();
        self.send(msg);
        addr
    }

    pub fn recreate_wallet(&mut self, owner: &MsgAddressInt) -> MsgAddressInt {
        let init = wallet_state_init(&self.minter(), owner);
        self.deploy_initial(init, 0)
    }

    pub fn recreate_minter(&mut self) -> MsgAddressInt {
        let init = minter_state_init(&self.bridge, 0x5a);
        let addr = self.deploy_initial(init, 0);
        assert_eq!(addr, self.minter(), "the minter's initial state reproduces its address");
        addr
    }

    pub fn recreate_bridge(&mut self) {
        let init = StateInit::with_code_and_data(codes().bridge.clone(), initial_bridge_data());
        let addr = self.deploy_initial(init, -1);
        assert_eq!(addr, self.bridge, "the bridge's initial state reproduces its address");
    }

    /// ConfigParam 18: one storage price table, in force from the start.
    pub fn set_storage_prices(&mut self, bit: u64, cell_price: u64, mc_bit: u64, mc_cell: u64) {
        let mut config = self.bc.config_params().clone();
        let mut param = chain_block::ConfigParam18::default();
        param
            .insert(&chain_block::StoragePrices {
                utime_since: 0,
                bit_price_ps: bit,
                cell_price_ps: cell_price,
                mc_bit_price_ps: mc_bit,
                mc_cell_price_ps: mc_cell,
            })
            .unwrap();
        config.set_config(ConfigParamEnum::ConfigParam18(param)).expect("param 18");
        self.bc.set_config(config).expect("the chain adopts it");
    }

    pub fn advance_time(&mut self, seconds: u32) {
        let now = self.bc.now();
        self.bc.set_now(now + seconds);
    }

    /// The account's whole state as a StateInit: what restores it once frozen.
    pub fn state_of(&self, addr: &MsgAddressInt) -> StateInit {
        let a = self.bc.get_account(addr).expect("deployed");
        StateInit::with_code_and_data(a.get_code().unwrap(), a.get_data().unwrap())
    }

    pub fn is_frozen(&self, addr: &MsgAddressInt) -> bool {
        self.bc.get_account(addr).is_some_and(|a| a.frozen_hash().is_some())
    }

    pub fn exists(&self, addr: &MsgAddressInt) -> bool {
        self.bc.get_account(addr).is_some_and(|a| !a.is_none())
    }
}
