/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The real pool contract in the VM, driven by real messages.
//!
//! This is not a probe. It is the contract that would ship, deployed from the
//! same source list, given the development verifying key, and sent the
//! messages a wallet would send. What it exists for is the one thing no test
//! on the chain side can do on its own: put a proof in front of it that
//! actually verifies.

use ark_ff::{BigInteger, PrimeField};
use chain_block::{BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, StateInit};
use shielded_pool_circuit::field::Fr;
use tos_sandbox::{compile_func, Blockchain, MessageBuilder, SendResult};

use crate::{library_dir, stdlib_path, CrossCheckError, Result, ACTIVE_VERSION, TOS};

pub const OP_DEPOSIT: u32 = 0x5348_5001;
pub const OP_TRANSACT: u32 = 0x5348_5002;
pub const OP_RESERVE_TOPUP: u32 = 0x5348_5003;

/// Section 13.2.
const MAGIC: u32 = 0x5350_5631;
const VERSION: u16 = 1;
const EPOCH_NONE: u32 = 0xffff_ffff;
/// The one configured denomination, and the fee section 14.2 fixes.
pub const DENOMINATION: u64 = TOS;
/// Section 14.2's fee, from the crate that puts it in the genesis store
/// rather than copied. A test constant that restates a chain constant rots
/// the moment the chain's moves, and this one has moved.
pub const WITHDRAWAL_FEE: u64 = shielded_pool_genesis::WITHDRAWAL_FEE as u64;

/// A field element as its 32 big-endian wire bytes.
pub fn be(value: Fr) -> [u8; 32] {
    let digits = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - digits.len()..].copy_from_slice(&digits);
    out
}

/// A field element as the decimal string a get-method prints.
pub fn dec(value: Fr) -> String {
    let mut digits = vec![0u8];
    for byte in be(value) {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            let next = u32::from(*digit) * 256 + carry;
            *digit = (next % 10) as u8;
            carry = next / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

/// Coins are a VarUInteger 16: four bits of byte length, then the bytes.
pub fn store_coins(builder: &mut BuilderData, amount: u128) -> Result<()> {
    let bytes = amount.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let length = bytes.len() - first;
    builder
        .append_bits(length, 4)
        .map_err(|error| CrossCheckError::Sandbox(format!("coin length: {error}")))?;
    if length > 0 {
        builder
            .append_raw(&bytes[first..], length * 8)
            .map_err(|error| CrossCheckError::Sandbox(format!("coin bytes: {error}")))?;
    }
    Ok(())
}

fn cell_of(builder: BuilderData) -> Result<Cell> {
    builder.into_cell().map_err(|error| CrossCheckError::Sandbox(format!("cell: {error}")))
}

fn empty_ring_holder() -> Result<Cell> {
    let mut builder = BuilderData::new();
    builder
        .append_bit_zero()
        .map_err(|error| CrossCheckError::Sandbox(format!("ring holder: {error}")))?;
    cell_of(builder)
}

/// The development verifying key, as the fixture records it.
pub fn development_vk_bytes() -> Result<Vec<u8>> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/groth16-development.json");
    let text = std::fs::read_to_string(&path)
        .map_err(|error| CrossCheckError::Fixture(format!("{}: {error}", path.display())))?;
    let fixture: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| CrossCheckError::Fixture(format!("fixture json: {error}")))?;
    let hex = fixture["verifying_key"]["hex"]
        .as_str()
        .ok_or_else(|| CrossCheckError::Fixture("no verifying key in the fixture".to_string()))?;
    (0..hex.len() / 2)
        .map(|i| {
            u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|error| CrossCheckError::Fixture(format!("vk hex: {error}")))
        })
        .collect()
}

/// A gas ceiling as the contract declares it, read out of the source.
///
/// Not copied into a constant here. A test that keeps its own copy of a
/// ceiling checks the copy: the rule `M * 5 <= C * 4` then holds between two
/// numbers in the same file and says nothing about the contract, and a
/// mutation that lowers the contract's ceiling below the measured maximum
/// survives. Reading it is what makes the measurement load-bearing.
pub fn contract_gas_ceiling(name: &str) -> Result<i64> {
    let path = library_dir().join("../tos-shielded-pool-v1.fc");
    let source = std::fs::read_to_string(&path)
        .map_err(|error| CrossCheckError::Fixture(format!("{}: {error}", path.display())))?;
    let needle = format!("int {name}() asm \"");
    let at = source
        .find(&needle)
        .ok_or_else(|| CrossCheckError::Fixture(format!("{name} is not declared in the pool")))?;
    let rest = &source[at + needle.len()..];
    let end = rest
        .find(" PUSHINT")
        .ok_or_else(|| CrossCheckError::Fixture(format!("{name} is not a PUSHINT constant")))?;
    rest[..end].trim().parse().map_err(|error| CrossCheckError::Fixture(format!("{name}: {error}")))
}

/// The denomination list a pool is really deployed with, from section 12.1.
///
/// Most tests want one denomination, because two deposits of the same amount
/// are the smallest thing that can fund a withdrawal. Anything that measures
/// what a path *costs* wants this one instead: the contract walks the list to
/// validate an amount, so a measurement taken against a shorter list is a
/// measurement of a pool nobody deploys.
pub const DEPLOYED_DENOMINATIONS: [u64; 4] =
    [1_000_000_000, 10_000_000_000, 100_000_000_000, 1_000_000_000_000];

/// The parameters a test pool is deployed with: the deployment's, with the
/// denomination list replaced.
///
/// This goes through `shielded-pool-genesis` rather than assembling a state
/// cell here. A hand-built fixture agrees with itself; what has to be true is
/// that the state these tests deploy and the state a deployment ships are the
/// same object, built by the same code. `genesis_vs_vm.rs` holds that
/// generator against the contract's own `state_genesis`.
///
/// Everything except the list comes from
/// `shielded_pool_genesis::development_parameters`, so a pool deployed here
/// with `DEPLOYED_DENOMINATIONS` is byte for byte the state the frozen
/// manifest names -- and a change to the profile, the Poseidon2 manifest or
/// the verifying key moves both together.
fn parameters(denominations: &[u64]) -> Result<shielded_pool_genesis::Parameters> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut parameters = shielded_pool_genesis::development_parameters(&root)
        .map_err(|error| CrossCheckError::Fixture(format!("the deployment parameters: {error}")))?;
    parameters.denominations = denominations.iter().map(|amount| u128::from(*amount)).collect();
    Ok(parameters)
}

fn genesis_state(denominations: &[u64]) -> Result<Cell> {
    let genesis = shielded_pool_genesis::build(parameters(denominations)?)
        .map_err(|error| CrossCheckError::Fixture(format!("the genesis state: {error}")))?;
    Ok(genesis.state)
}

/// The shielded pool, deployed.
pub struct Pool {
    pub bc: Blockchain,
    pub addr: MsgAddressInt,
    payer: tos_sandbox::Treasury,
}

/// Every FunC source the pool is built from, in dependency order.
pub fn pool_sources() -> Vec<std::path::PathBuf> {
    let library = library_dir();
    let contract = library.join("../tos-shielded-pool-v1.fc");
    let mut sources = vec![stdlib_path()];
    for name in [
        "domains.fc",
        "empty-roots.fc",
        "notes.fc",
        "tree.fc",
        "imt.fc",
        "auth.fc",
        "payload.fc",
        "domain.fc",
        "anchors.fc",
        "state.fc",
        "transact.fc",
        "groth16.fc",
        "payout.fc",
        "recovery.fc",
    ] {
        sources.push(library.join(name));
    }
    sources.push(contract);
    sources
}

impl Pool {
    /// The pool as every test but the dust measurement wants it: one
    /// denomination.
    ///
    /// The roots are not arguments. Section 13.2 derives both of them -- an
    /// empty commitment tree and a nullifier tree holding only the head
    /// sentinel -- so a caller that could choose them could deploy a pool that
    /// no prover agrees with.
    pub fn deploy() -> Result<Self> {
        Self::deploy_with_denominations(&[DENOMINATION])
    }

    pub fn deploy_with_denominations(denominations: &[u64]) -> Result<Self> {
        Self::deploy_with(denominations, None)
    }

    /// A pool carrying a verifying key the caller chose.
    ///
    /// The one thing a ceremony produces that this chain has to live with is
    /// 1,248 bytes, and until they exist nothing can be said about them except
    /// by deploying a pool that carries them and putting a proof through it.
    /// `None` keeps the development key, which is what every other test wants.
    ///
    /// A different key is a different genesis state and therefore a different
    /// address, which is not a side effect to work around -- it is the reason
    /// the ceremony has to finish before an address can be published.
    /// Deploy with a chosen balance instead of a comfortable one.
    ///
    /// Every other deployment here starts with 100 TOS against a 5 TOS floor,
    /// which is ninety-five TOS of headroom -- enough that no check near the
    /// floor is ever reached. The one case that distinguishes a backing check
    /// made before this transaction's fee from one made after it only exists
    /// close to the floor, so it needs a pool that starts there.
    pub fn deploy_with_balance(denominations: &[u64], balance: u64) -> Result<Self> {
        Self::deploy_inner(denominations, None, balance)
    }

    pub fn deploy_with(denominations: &[u64], verifying_key: Option<&[u8]>) -> Result<Self> {
        Self::deploy_inner(denominations, verifying_key, 100 * TOS)
    }

    fn deploy_inner(
        denominations: &[u64],
        verifying_key: Option<&[u8]>,
        deploy_value: u64,
    ) -> Result<Self> {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)?;
        bc.set_workchain(0);
        let payer = bc.treasury("relay", 1_000_000 * TOS)?;
        let code = compile_func(&pool_sources())?;
        let state = match verifying_key {
            None => genesis_state(denominations)?,
            Some(bytes) => {
                let mut parameters = parameters(denominations)?;
                parameters.verifying_key = bytes.to_vec();
                shielded_pool_genesis::build(parameters)
                    .map_err(|error| {
                        CrossCheckError::Fixture(format!(
                            "a genesis state carrying that verifying key: {error}"
                        ))
                    })?
                    .state
            }
        };
        let si = StateInit::with_code_and_data(code, state);
        let addr_hash = si
            .write_to_new_cell()
            .and_then(|builder| builder.into_cell())
            .map_err(|error| CrossCheckError::Sandbox(format!("state init: {error}")))?
            .hash(0);
        let addr = MsgAddressInt::with_params(0, addr_hash)
            .map_err(|error| CrossCheckError::Sandbox(format!("address: {error}")))?;
        bc.send_message(
            MessageBuilder::internal(payer.address(), &addr, deploy_value)
                .bounce(false)
                .state_init(si)
                .body(Cell::default())
                .build(),
        )?
        .expect_success();
        Ok(Self { bc, addr, payer })
    }

    /// The pool's own account id, which the execution domain is built from.
    pub fn account(&self) -> Result<[u8; 32]> {
        let bytes = self.addr.address().get_bytestring(0);
        let mut out = [0u8; 32];
        if bytes.len() != 32 {
            return Err(CrossCheckError::Sandbox("an account id that is not 32 bytes".to_string()));
        }
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    pub fn get(&self, method: &str) -> Result<String> {
        let result = self
            .bc
            .run_get_method(&self.addr, method, vec![])
            .map_err(|error| CrossCheckError::Vm(format!("{method}: {error}")))?;
        if result.exit_code != 0 {
            return Err(CrossCheckError::Vm(format!("{method} exited {}", result.exit_code)));
        }
        let top = result
            .stack
            .last()
            .ok_or_else(|| CrossCheckError::Vm(format!("{method} returned nothing")))?;
        Ok(top
            .as_integer()
            .map_err(|error| CrossCheckError::Vm(format!("{method}: {error}")))?
            .to_string())
    }

    pub fn send(&mut self, value: u64, body: Cell) -> Result<SendResult> {
        let msg = MessageBuilder::internal(self.payer.address(), &self.addr, value)
            .bounce(true)
            .body(body)
            .build();
        Ok(self.bc.send_message(msg)?)
    }

    /// The exit code, the gas, and how many messages the pool sent.
    ///
    /// The count is the half that distinguishes a transfer from a withdrawal.
    /// Both move every root the same way -- the same two nullifier insertions
    /// and the same three commitment appends run before the withdrawal branch
    /// is even reached -- so no root can tell them apart. What a transfer must
    /// do is send nothing, and a message the pool sends is public: it says a
    /// transfer happened and who it went to, which is the whole of what this
    /// pool exists to hide.
    pub fn run_counting_sends(&mut self, value: u64, body: Cell) -> Result<(i32, i64, usize)> {
        let result = self.send(value, body)?;
        let sent = result
            .first_transaction()
            .ok_or_else(|| CrossCheckError::Vm("the pool did not run at all".into()))?
            .out_msgs
            .len()
            .map_err(|error| CrossCheckError::Vm(format!("counting outbound messages: {error}")))?;
        match result.read_primary_description().compute_ph {
            chain_block::TrComputePhase::Vm(vm) => Ok((
                vm.exit_code,
                vm.gas_used
                    .to_string()
                    .parse()
                    .map_err(|error| CrossCheckError::Vm(format!("gas used: {error}")))?,
                sent,
            )),
            chain_block::TrComputePhase::Skipped(s) => {
                Err(CrossCheckError::Vm(format!("compute skipped: {:?}", s.reason)))
            }
        }
    }

    /// The exit code and the gas it took to get there.
    pub fn run(&mut self, value: u64, body: Cell) -> Result<(i32, i64)> {
        let result = self.send(value, body)?;
        match result.read_primary_description().compute_ph {
            chain_block::TrComputePhase::Vm(vm) => Ok((
                vm.exit_code,
                vm.gas_used
                    .to_string()
                    .parse()
                    .map_err(|error| CrossCheckError::Vm(format!("gas used: {error}")))?,
            )),
            chain_block::TrComputePhase::Skipped(s) => {
                Err(CrossCheckError::Vm(format!("compute skipped: {:?}", s.reason)))
            }
        }
    }

    /// The configuration cell section 13 keeps at reference two.
    ///
    /// The denomination walk's cost is a property of the list a pool was
    /// deployed with, so pricing it against a list assembled in a test would
    /// price a pool nobody deploys. This hands the real one to the probe.
    pub fn config_cell(&self) -> Result<Cell> {
        self.bc
            .get_account(&self.addr)
            .ok_or_else(|| CrossCheckError::Sandbox("the pool has no account".to_string()))?
            .get_data()
            .ok_or_else(|| CrossCheckError::Sandbox("the pool has no data".to_string()))?
            .reference(2)
            .map_err(|error| CrossCheckError::Sandbox(format!("config ref: {error}")))
    }

    /// The verifying key cell section 13 keeps at reference three.
    pub fn vk_cell(&self) -> Result<Cell> {
        self.bc
            .get_account(&self.addr)
            .ok_or_else(|| CrossCheckError::Sandbox("the pool has no account".to_string()))?
            .get_data()
            .ok_or_else(|| CrossCheckError::Sandbox("the pool has no data".to_string()))?
            .reference(3)
            .map_err(|error| CrossCheckError::Sandbox(format!("vk ref: {error}")))
    }

    /// The two anchor rings as the pool actually holds them, each entry the
    /// slot it sits in, the version recorded there and the root.
    ///
    /// Section 6's acceptance rule is an exact match on the pair, so what a
    /// slot holds is the whole of a recent root's validity. Reading the rings
    /// is how traffic-level tests say which roots are still acceptable
    /// without submitting a proof for each one.
    pub fn anchor_rings(&self) -> Result<(Vec<AnchorEntry>, Vec<AnchorEntry>)> {
        let data = self
            .bc
            .get_account(&self.addr)
            .ok_or_else(|| CrossCheckError::Sandbox("the pool has no account".to_string()))?
            .get_data()
            .ok_or_else(|| CrossCheckError::Sandbox("the pool has no data".to_string()))?;
        let anchors = data
            .reference(1)
            .map_err(|error| CrossCheckError::Sandbox(format!("anchors ref: {error}")))?;
        let mut slice = chain_block::SliceData::load_cell(anchors)
            .map_err(|error| CrossCheckError::Sandbox(format!("anchor root: {error}")))?;
        if slice.remaining_bits() != 0 || slice.remaining_references() != 2 {
            return Err(CrossCheckError::Sandbox(
                "the anchor root is not section 13.1's two references".to_string(),
            ));
        }
        let mut rings = Vec::new();
        for _ in 0..2 {
            let holder = slice
                .checked_drain_reference()
                .map_err(|error| CrossCheckError::Sandbox(format!("a ring: {error}")))?;
            let mut holder = chain_block::SliceData::load_cell(holder)
                .map_err(|error| CrossCheckError::Sandbox(format!("a ring holder: {error}")))?;
            // A HashmapE is one maybe bit and, when it holds anything, the root.
            let present = holder
                .get_next_bit()
                .map_err(|error| CrossCheckError::Sandbox(format!("the maybe bit: {error}")))?;
            let dict = if present {
                Some(holder.checked_drain_reference().map_err(|error| {
                    CrossCheckError::Sandbox(format!("the hashmap root: {error}"))
                })?)
            } else {
                None
            };
            let mut entries = Vec::new();
            let mut failure = None;
            chain_block::HashmapType::iterate_slices(
                &chain_block::HashmapE::with_hashmap(12, dict),
                |key, mut value| {
                    let slot = key.clone().get_next_int(12)?;
                    if value.remaining_bits() != 288 || value.remaining_references() != 0 {
                        failure = Some("an entry is not exactly 32 + 256 bits".to_string());
                        return Ok(false);
                    }
                    let version = value.get_next_int(32)?;
                    let mut root = [0u8; 32];
                    for byte in root.iter_mut() {
                        *byte = value.get_next_byte()?;
                    }
                    entries.push(AnchorEntry { slot, version, root });
                    Ok(true)
                },
            )
            .map_err(|error| CrossCheckError::Sandbox(format!("iterate a ring: {error}")))?;
            if let Some(why) = failure {
                return Err(CrossCheckError::Sandbox(why));
            }
            entries.sort_by_key(|entry| entry.slot);
            rings.push(entries);
        }
        let epoch = rings.pop().unwrap_or_default();
        let recent = rings.pop().unwrap_or_default();
        Ok((recent, epoch))
    }

    /// Move the pool to the state a mature one would hold: `index` leaves
    /// appended, and both anchor rings at the given occupancy.
    ///
    /// Nothing else changes -- the same code, the same verifying key, the
    /// same configuration and the same balance. What changes is the three
    /// places whose cost depends on how long the pool has been running, and
    /// the point is to send the contract a real message once they do.
    ///
    /// The commitment root is left as it was. A deposit does not read it, and
    /// inventing one that matched the substituted frontier would mean
    /// reimplementing the tree here to no purpose.
    pub fn age_to(&mut self, index: u64, frontier: Cell, anchors: Cell) -> Result<()> {
        let mut account = self
            .bc
            .get_account(&self.addr)
            .ok_or_else(|| CrossCheckError::Sandbox("the pool has no account".to_string()))?
            .clone();
        let data = account
            .get_data()
            .ok_or_else(|| CrossCheckError::Sandbox("the pool has no data".to_string()))?;

        let mut slice = chain_block::SliceData::load_cell(data.clone())
            .map_err(|error| CrossCheckError::Sandbox(format!("state slice: {error}")))?;
        if slice.remaining_references() != 4 {
            return Err(CrossCheckError::Sandbox(
                "the state cell does not have the four references section 13 fixes".to_string(),
            ));
        }
        // magic, version, commitment root: copied. Then the index, replaced.
        let head = slice
            .get_next_bits(32 + 16 + 256)
            .map_err(|error| CrossCheckError::Sandbox(format!("state head: {error}")))?;
        let old_index = slice
            .get_next_int(64)
            .map_err(|error| CrossCheckError::Sandbox(format!("state index: {error}")))?;
        if old_index >= index {
            return Err(CrossCheckError::Fixture(format!(
                "aging to {index} would move the pool backwards from {old_index}"
            )));
        }
        let tail_bits = slice.remaining_bits();
        let tail = slice
            .get_next_bits(tail_bits)
            .map_err(|error| CrossCheckError::Sandbox(format!("state tail: {error}")))?;

        let mut builder = BuilderData::new();
        builder
            .append_raw(&head, 32 + 16 + 256)
            .and_then(|b| b.append_u64(index))
            .and_then(|b| b.append_raw(&tail, tail_bits))
            .map_err(|error| CrossCheckError::Sandbox(format!("aged state bits: {error}")))?;

        // The frontier store is section 13's maybe-ref holder, not the level
        // chain itself.
        let mut holder = BuilderData::new();
        holder
            .append_bit_one()
            .and_then(|b| b.checked_append_reference(frontier))
            .map_err(|error| CrossCheckError::Sandbox(format!("frontier holder: {error}")))?;
        let holder = cell_of(holder)?;

        let config = data
            .reference(2)
            .map_err(|error| CrossCheckError::Sandbox(format!("config ref: {error}")))?;
        let vk = data
            .reference(3)
            .map_err(|error| CrossCheckError::Sandbox(format!("vk ref: {error}")))?;
        for reference in [holder, anchors, config, vk] {
            builder
                .checked_append_reference(reference)
                .map_err(|error| CrossCheckError::Sandbox(format!("aged state ref: {error}")))?;
        }

        if !account.set_data(cell_of(builder)?) {
            return Err(CrossCheckError::Sandbox("the pool refused new data".to_string()));
        }
        self.bc.set_account(self.addr.clone(), account);
        Ok(())
    }

    /// Move only the leaf counter, keeping the frontier and both anchor
    /// rings exactly as the pool built them.
    ///
    /// This is how a test reaches a ring's overwrite boundary without sending
    /// four thousand messages: the versions in between were never externally
    /// visible roots, so skipping them changes nothing a later transaction
    /// can observe.
    pub fn age_index_to(&mut self, index: u64) -> Result<()> {
        let data = self
            .bc
            .get_account(&self.addr)
            .ok_or_else(|| CrossCheckError::Sandbox("the pool has no account".to_string()))?
            .get_data()
            .ok_or_else(|| CrossCheckError::Sandbox("the pool has no data".to_string()))?;
        let frontier_holder = data
            .reference(0)
            .map_err(|error| CrossCheckError::Sandbox(format!("frontier ref: {error}")))?;
        let mut holder = chain_block::SliceData::load_cell(frontier_holder)
            .map_err(|error| CrossCheckError::Sandbox(format!("frontier holder: {error}")))?;
        let present = holder
            .get_next_bit()
            .map_err(|error| CrossCheckError::Sandbox(format!("the maybe bit: {error}")))?;
        let frontier = if present {
            holder
                .checked_drain_reference()
                .map_err(|error| CrossCheckError::Sandbox(format!("frontier: {error}")))?
        } else {
            Cell::default()
        };
        let anchors = data
            .reference(1)
            .map_err(|error| CrossCheckError::Sandbox(format!("anchors ref: {error}")))?;
        if !present {
            return Err(CrossCheckError::Fixture(
                "the pool's frontier is still empty, so there is no age to keep".to_string(),
            ));
        }
        self.age_to(index, frontier, anchors)
    }

    /// Deliver a message to the pool with the bounced bit set, without it
    /// having been a bounce.
    ///
    /// Section 19 gate 16 says in as many words that this is not end-to-end
    /// evidence, and it is not used as any. It is here so that a test can
    /// show what an attacker *would* get if the bit were theirs to set, which
    /// is the only way to show that the platform clearing it is what stops
    /// them.
    pub fn deliver_synthetic_bounce(
        &mut self,
        src: &MsgAddressInt,
        body: Cell,
        value: u64,
    ) -> Result<(i32, i64)> {
        let mut header = chain_block::InternalMessageHeader::with_addresses(
            src.clone(),
            self.addr.clone(),
            chain_block::CurrencyCollection::with_coins(value),
        );
        header.bounce = false;
        header.bounced = true;
        header.ihr_disabled = true;
        let mut message = chain_block::Message::with_int_header(header);
        message.set_body(
            chain_block::SliceData::load_cell(body)
                .map_err(|error| CrossCheckError::Sandbox(format!("bounce body: {error}")))?,
        );
        let result = self.bc.send_message(message)?;
        match result.read_primary_description().compute_ph {
            chain_block::TrComputePhase::Vm(vm) => Ok((
                vm.exit_code,
                vm.gas_used
                    .to_string()
                    .parse()
                    .map_err(|error| CrossCheckError::Vm(format!("gas used: {error}")))?,
            )),
            chain_block::TrComputePhase::Skipped(s) => {
                Err(CrossCheckError::Vm(format!("compute skipped: {:?}", s.reason)))
            }
        }
    }

    /// Everything the contract keeps between messages.
    ///
    /// Gate 11 is about what a failure leaves behind, and "nothing" has to
    /// mean every field, not the two a test happened to look at. The anchor
    /// rings are included because a mutation preserves a root before it does
    /// anything else, so they are the first thing a half-finished
    /// transaction would show.
    pub fn state_snapshot(&self) -> Result<PoolState> {
        let mut fields = Vec::new();
        for method in [
            "commitment_root",
            "commitment_next_index",
            "nullifier_root",
            "nullifier_next_index",
            "native_liability",
        ] {
            fields.push(self.get(method)?);
        }
        let (recent, epoch) = self.anchor_rings()?;
        Ok(PoolState { fields, recent, epoch })
    }

    /// Set the pool's balance, breaking the backing invariant on purpose.
    ///
    /// The compute phase checks the balance against the liability it is about
    /// to leave behind; the action phase then has to reserve that and send
    /// the payout on top. A pool drained to between the two passes compute
    /// and fails in the action phase, which is the only way to reach that
    /// failure without changing the contract.
    pub fn set_balance(&mut self, balance: u64) -> Result<()> {
        let mut account = self
            .bc
            .get_account(&self.addr)
            .ok_or_else(|| CrossCheckError::Sandbox("the pool has no account".to_string()))?
            .clone();
        account.set_balance(chain_block::CurrencyCollection::with_coins(balance));
        self.bc.set_account(self.addr.clone(), account);
        Ok(())
    }

    /// What the pool holds right now.
    pub fn balance(&self) -> Result<u64> {
        let account = self
            .bc
            .get_account(&self.addr)
            .ok_or_else(|| CrossCheckError::Sandbox("the pool has no account".to_string()))?;
        u64::try_from(account.balance().map(|value| value.coins.as_u128()).unwrap_or_default())
            .map_err(|_| CrossCheckError::Sandbox("a balance above u64".to_string()))
    }

    /// The compute exit, the action-phase result code, and whether the
    /// transaction was aborted.
    ///
    /// A compute exit of zero is not success: the action phase can still
    /// refuse to send the messages the compute phase asked for, or refuse the
    /// account state it produced, and either aborts the transaction. A test
    /// about what a failure leaves behind has to be able to say which failure
    /// it got.
    pub fn run_phases(&mut self, value: u64, body: Cell) -> Result<Phases> {
        let result = self.send(value, body)?;
        let description = result.read_primary_description();
        let compute = match description.compute_ph {
            chain_block::TrComputePhase::Vm(vm) => vm.exit_code,
            chain_block::TrComputePhase::Skipped(s) => {
                return Err(CrossCheckError::Vm(format!("compute skipped: {:?}", s.reason)))
            }
        };
        Ok(Phases {
            compute,
            action: description.action.as_ref().map(|phase| phase.result_code),
            failed_action: description.action.as_ref().and_then(|phase| phase.result_arg),
            aborted: description.aborted,
        })
    }

    /// Section 12.3's top-up body: the operation and a query id, and nothing
    /// else at all.
    pub fn topup_body(query_id: u64) -> Result<Cell> {
        let mut builder = BuilderData::new();
        builder
            .append_u32(OP_RESERVE_TOPUP)
            .and_then(|b| b.append_u64(query_id))
            .map_err(|error| CrossCheckError::Sandbox(format!("top-up body: {error}")))?;
        cell_of(builder)
    }

    /// Section 12.1's deposit body.
    pub fn deposit_body(amount: u64, owner_commitment: Fr, payload: Cell) -> Result<Cell> {
        let mut builder = BuilderData::new();
        builder
            .append_u32(OP_DEPOSIT)
            .and_then(|b| b.append_u64(1))
            .map_err(|error| CrossCheckError::Sandbox(format!("deposit header: {error}")))?;
        store_coins(&mut builder, u128::from(amount))?;
        builder
            .append_raw(&be(owner_commitment), 256)
            .and_then(|b| b.checked_append_reference(payload))
            .map_err(|error| CrossCheckError::Sandbox(format!("deposit body: {error}")))?;
        cell_of(builder)
    }
}

/// How far a transaction got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phases {
    /// The compute phase's exit code.
    pub compute: i32,
    /// The action phase's result code, if it ran at all.
    pub action: Option<i32>,
    /// Which action in the list failed, counting from zero.
    pub failed_action: Option<i32>,
    /// Whether the transaction was rolled back.
    pub aborted: bool,
}

/// Every persistent field of the pool, for comparing before with after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolState {
    fields: Vec<String>,
    recent: Vec<AnchorEntry>,
    epoch: Vec<AnchorEntry>,
}

/// One slot of an anchor ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorEntry {
    pub slot: u64,
    pub version: u64,
    pub root: [u8; 32],
}

/// `addr_none$00`, the only recipient a transfer may name.
pub fn addr_none(builder: &mut BuilderData) -> Result<()> {
    builder
        .append_bits(0, 2)
        .map_err(|error| CrossCheckError::Sandbox(format!("addr_none: {error}")))?;
    Ok(())
}

/// A cell holding only references, which is what the frozen bundles are.
pub fn refs_only(cells: &[Cell]) -> Result<Cell> {
    let mut builder = BuilderData::new();
    for cell in cells {
        builder
            .checked_append_reference(cell.clone())
            .map_err(|error| CrossCheckError::Sandbox(format!("bundle: {error}")))?;
    }
    cell_of(builder)
}
