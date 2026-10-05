/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! The two-party payment channel (crypto/smartcont/payment-channel-code.fc) as real
//! transactions, with a party key anyone can sign for. Each party's key is checked
//! twice: once for the signature over a command, and once for a promise the other
//! party carries. Both checks refuse a weak key before the contract accepts an
//! external message, so a forged signature costs the channel nothing and moves
//! nothing; the honest party, the timeout path and strong keys keep working.

use chain_block::{
    BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, SliceData, StateInit,
};
use ed25519_dalek::{Signer, SigningKey};
use tos_sandbox::{Blockchain, MessageBuilder, SendResult, compile_func_with_stdlib};

mod weak_ed25519;

const TOS: u64 = 1_000_000_000;
const CHANNEL_ID: u64 = 0x5043_4841_4e00_0001;
const ERR_WEAK_KEY: i32 = 42;
const EXTERNAL_GAS_CREDIT: i64 = 10_000;

const OP_PCHAN_CMD: u32 = 0x9128_38d1;
const MSG_CLOSE: u32 = 0xf28a_e183;

const CHANNEL_A: u64 = 4 * TOS;
const CHANNEL_B: u64 = 4 * TOS;

fn smartcont(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../crypto/smartcont").join(name)
}

fn source() -> String {
    std::fs::read_to_string(smartcont("payment-channel-code.fc")).expect("source")
}

/// Compiles `source` as payment-channel-code.fc next to the weak-key helper it includes.
fn compile(source: &str) -> Cell {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("payment-channel-code.fc"), source).expect("write source");
    std::fs::copy(smartcont("strong-ed25519-key.fc"), dir.path().join("strong-ed25519-key.fc"))
        .expect("copy helper");
    compile_func_with_stdlib(&[dir.path().join("payment-channel-code.fc")]).expect("compile")
}

/// The four places a stored party key is about to verify a signature.
const GUARDS: [&str; 4] = [
    "    require_strong_key(a_key);\n    throw_unless(err:wrong_a_signature(), check_signature(hash, a_sig, a_key));",
    "    require_strong_key(b_key);\n    throw_unless(err:wrong_b_signature(), check_signature(hash, b_sig, b_key));",
    "      require_strong_key(a_key);\n      throw_unless(err:wrong_a_signature(), check_signature(hash, sig, a_key));",
    "      require_strong_key(b_key);\n      throw_unless(err:wrong_b_signature(), check_signature(hash, sig, b_key));",
];

/// The source with every weak-key guard taken out: the contract as it was before them.
fn unguarded_source() -> String {
    let mut source = source();
    for guard in GUARDS {
        assert_eq!(source.matches(guard).count(), 1, "guard moved: {guard}");
        let (_, check) = guard.split_once('\n').expect("two lines");
        source = source.replace(guard, check);
    }
    assert!(!source.contains("  require_strong_key("), "a guard was left in");
    source
}

/// The source with the close command's acceptance replaced by a throw whose exit code
/// is the gas consumed so far: the whole pre-acceptance cost of an external close. The
/// probe lifts its own gas limit first, so a path over the external credit still
/// reports its cost (over-estimated by that one instruction) instead of failing.
fn probe_source(source: &str) -> String {
    let accept = "  accept_message();\n  update_promise_A += extra_A;";
    assert_eq!(source.matches(accept).count(), 1);
    let probe = source.replace(accept, "  throw(gas_consumed());\n  update_promise_A += extra_A;");
    let entry = "() recv_external(slice in_msg) impure {\n";
    assert_eq!(probe.matches(entry).count(), 1);
    let probe = probe.replace(entry, &format!("{entry}  set_gas_limit(1000000);\n"));
    format!("int gas_consumed() asm \"GASCONSUMED\";\n{probe}")
}

fn cell(build: impl FnOnce(&mut BuilderData)) -> Cell {
    let mut b = BuilderData::new();
    build(&mut b);
    b.into_cell().expect("cell")
}

/// Tomis (VarUInteger 16): a 4-bit byte length, then the value big-endian.
fn append_tomis(b: &mut BuilderData, value: u64) {
    let bytes = value.to_be_bytes();
    let skip = bytes.iter().take_while(|byte| **byte == 0).count();
    b.append_bits(bytes.len() - skip, 4).unwrap();
    b.append_raw(&bytes[skip..], (bytes.len() - skip) * 8).unwrap();
}

fn address_cell(address: &MsgAddressInt) -> Cell {
    cell(|b| address.write_to(b).unwrap())
}

/// config$_ initTimeout:uint32 exitTimeout:uint32 a_key:uint256 b_key:uint256 ^a_addr
/// ^b_addr channel_id:uint64 min_A_extra:Tomis
fn config(a_key: &[u8; 32], b_key: &[u8; 32], a: &MsgAddressInt, b: &MsgAddressInt) -> Cell {
    cell(|c| {
        c.append_u32(3_600).unwrap();
        c.append_u32(3_600).unwrap();
        c.append_u256(a_key).unwrap();
        c.append_u256(b_key).unwrap();
        c.checked_append_reference(address_cell(a)).unwrap();
        c.checked_append_reference(address_cell(b)).unwrap();
        c.append_u64(CHANNEL_ID).unwrap();
        append_tomis(c, 0);
    })
}

/// A channel both parties have funded and signed into, so it is closing: nobody has
/// signed a close yet and no promise is recorded.
fn closing_state() -> Cell {
    cell(|s| {
        s.append_bits(1, 3).unwrap();
        s.append_bit_zero().unwrap();
        s.append_bit_zero().unwrap();
        append_tomis(s, 0);
        append_tomis(s, 0);
        s.append_u32(0).unwrap();
        append_tomis(s, CHANNEL_A);
        append_tomis(s, CHANNEL_B);
    })
}

/// close$_ op extra_A extra_B has_sig:(Maybe ^sig) channel_id promise_A promise_B: the part
/// the command signatures cover.
fn close_command(promise: Option<(Cell, &Cell)>, promise_a: u64, promise_b: u64) -> Cell {
    cell(|m| {
        m.append_u32(MSG_CLOSE).unwrap();
        append_tomis(m, 0);
        append_tomis(m, 0);
        match promise {
            Some((signature, body)) => {
                m.append_bit_one().unwrap();
                m.checked_append_reference(signature).unwrap();
                let body = SliceData::load_cell(body.clone()).unwrap();
                m.append_builder(&body.as_builder().unwrap()).unwrap();
            }
            None => {
                m.append_bit_zero().unwrap();
                m.append_u64(CHANNEL_ID).unwrap();
                append_tomis(m, promise_a);
                append_tomis(m, promise_b);
            }
        }
    })
}

/// The promise a party signs on its own: channel_id promise_A promise_B.
fn promise_body(promise_a: u64, promise_b: u64) -> Cell {
    cell(|m| {
        m.append_u64(CHANNEL_ID).unwrap();
        append_tomis(m, promise_a);
        append_tomis(m, promise_b);
    })
}

fn signature_cell(signature: &[u8; 64]) -> Cell {
    cell(|b| {
        b.append_raw(signature, 512).unwrap();
    })
}

/// op:pchan_cmd a_sig:(Maybe ^sig) b_sig:(Maybe ^sig) command.
fn signed_command(a: Option<[u8; 64]>, b: Option<[u8; 64]>, command: &Cell) -> Cell {
    let command = SliceData::load_cell(command.clone()).unwrap();
    cell(|m| {
        m.append_u32(OP_PCHAN_CMD).unwrap();
        for signature in [a, b] {
            match signature {
                Some(signature) => {
                    m.append_bit_one().unwrap();
                    m.checked_append_reference(signature_cell(&signature)).unwrap();
                }
                None => {
                    m.append_bit_zero().unwrap();
                }
            }
        }
        m.append_builder(&command.as_builder().unwrap()).unwrap();
    })
}

fn sign(key: &SigningKey, message: &Cell) -> [u8; 64] {
    key.sign(message.hash(0).as_slice()).to_bytes()
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Party {
    A,
    B,
}

struct Channel {
    bc: Blockchain,
    address: MsgAddressInt,
    a: MsgAddressInt,
    b: MsgAddressInt,
}

impl Channel {
    fn deploy(code: Cell, a_key: &[u8; 32], b_key: &[u8; 32]) -> Self {
        Self::deploy_with_state(code, a_key, b_key, closing_state())
    }

    fn deploy_with_state(code: Cell, a_key: &[u8; 32], b_key: &[u8; 32], state: Cell) -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        let funder = bc.treasury("funder", 1_000 * TOS).expect("funder");
        // The parties live on the masterchain: the default sandbox config has no
        // basechain descriptor, so a payout to a basechain party would be dropped.
        bc.set_workchain(-1);
        let a = bc.treasury("party-a", 10 * TOS).expect("a").address().clone();
        let b = bc.treasury("party-b", 10 * TOS).expect("b").address().clone();
        let data = cell(|d| {
            d.checked_append_reference(config(a_key, b_key, &a, &b)).unwrap();
            d.checked_append_reference(state).unwrap();
        });
        let init = StateInit::with_code_and_data(code, data);
        let hash = init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let address = MsgAddressInt::with_params(0, hash).unwrap();
        let deploy = MessageBuilder::internal(funder.address(), &address, 10 * TOS)
            .bounce(false)
            .state_init(init)
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, address, a, b }
    }

    fn send(&mut self, body: Cell) -> Result<SendResult, String> {
        let message = MessageBuilder::external(&self.address)
            .body_slice(SliceData::load_cell(body).unwrap())
            .build();
        self.bc.send_message(message).map_err(|error| error.to_string())
    }

    fn balance_of(&self, address: &MsgAddressInt) -> u128 {
        self.bc.get_account(address).expect("account").balance().expect("balance").coins.as_u128()
    }

    fn data_hash(&self) -> chain_block::UInt256 {
        self.bc.get_account(&self.address).expect("account").get_data().expect("data").hash(0)
    }
}

/// Every weak key a signature over a channel message can actually be forged for: the
/// identity and order-2 aliases forge for any message, the rest for a fraction of them.
fn forgeable_weak_keys() -> Vec<[u8; 32]> {
    let probe = promise_body(0, 0).hash(0);
    let keys: Vec<[u8; 32]> = weak_ed25519::weak_keys()
        .into_iter()
        .filter(|key| {
            (0..64u8).any(|i| {
                let mut message = probe.as_slice().to_vec();
                message[0] = i;
                weak_ed25519::forge(key, &message).is_some()
            })
        })
        .collect();
    let aliases = weak_ed25519::sign_bit_aliases();
    assert!(keys.contains(&aliases[0]) && keys.contains(&aliases[1]), "aliases not forgeable");
    assert!(keys.len() >= 10, "only {} forgeable weak keys", keys.len());
    keys
}

fn honest_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// The keys of a channel in which `weak_party` holds `weak` and the other party holds
/// `honest`, as (a_key, b_key).
fn keys_with(weak_party: Party, weak: [u8; 32], honest: &SigningKey) -> ([u8; 32], [u8; 32]) {
    let honest = honest.verifying_key().to_bytes();
    match weak_party {
        Party::A => (weak, honest),
        Party::B => (honest, weak),
    }
}

/// The other party, holding a real key, closes the channel together with a forged
/// signature for the weak party and claims the weak party's whole deposit. The
/// forgery is found by varying the claimed promise by a few nanotomis.
fn forged_joint_close(weak_party: Party, weak: &[u8; 32], honest: &SigningKey) -> Cell {
    (0..4_096u64)
        .find_map(|dust| {
            let (promise_a, promise_b) = match weak_party {
                Party::A => (CHANNEL_A + dust, 0),
                Party::B => (0, CHANNEL_B + dust),
            };
            let command = close_command(None, promise_a, promise_b);
            let forged = weak_ed25519::forge(weak, command.hash(0).as_slice())?;
            let real = sign(honest, &command);
            Some(match weak_party {
                Party::A => signed_command(Some(forged), Some(real), &command),
                Party::B => signed_command(Some(real), Some(forged), &command),
            })
        })
        .expect("a forgeable close command")
}

/// The other party signs a close alone and carries a promise forged for the weak party
/// that hands it the weak party's whole deposit.
fn forged_promise_close(weak_party: Party, weak: &[u8; 32], honest: &SigningKey) -> Cell {
    (0..4_096u64)
        .find_map(|dust| {
            let (promise_a, promise_b) = match weak_party {
                Party::A => (CHANNEL_A + dust, 0),
                Party::B => (0, CHANNEL_B + dust),
            };
            let body = promise_body(promise_a, promise_b);
            let forged = weak_ed25519::forge(weak, body.hash(0).as_slice())?;
            let command = close_command(Some((signature_cell(&forged), &body)), 0, 0);
            let real = sign(honest, &command);
            Some(match weak_party {
                Party::A => signed_command(None, Some(real), &command),
                Party::B => signed_command(Some(real), None, &command),
            })
        })
        .expect("a forgeable promise")
}

fn exit_code(result: &SendResult) -> i32 {
    match result.read_primary_description().compute_ph {
        chain_block::TrComputePhase::Vm(vm) => vm.exit_code,
        chain_block::TrComputePhase::Skipped(skipped) => {
            panic!("compute skipped: {:?}", skipped.reason)
        }
    }
}

/// Without the guards, the other party drains a weak party's deposit with a forged
/// signature: the forgery is accepted and the whole channel pays out to the forger.
/// This is what the guards stop; if it ever stops reproducing, the refusal tests below
/// prove nothing.
#[test]
fn without_the_guards_a_forged_party_signature_drains_the_channel() {
    let code = compile(&unguarded_source());
    let honest = honest_key(0x51);
    for weak in weak_ed25519::sign_bit_aliases() {
        for weak_party in [Party::A, Party::B] {
            let (a_key, b_key) = keys_with(weak_party, weak, &honest);
            let mut channel = Channel::deploy(code.clone(), &a_key, &b_key);
            let forger = match weak_party {
                Party::A => channel.b.clone(),
                Party::B => channel.a.clone(),
            };
            let before = channel.balance_of(&forger);
            let result = channel
                .send(forged_joint_close(weak_party, &weak, &honest))
                .expect("the unguarded channel accepts the forgery");
            result.expect_success();
            let gained = channel.balance_of(&forger) - before;
            assert!(
                gained >= u128::from(CHANNEL_A + CHANNEL_B) - u128::from(TOS / 10),
                "{weak_party:?} weak: the forger gained only {gained}"
            );
        }
    }
}

/// Without the guards, a promise forged for the weak party is recorded as signed.
#[test]
fn without_the_guards_a_forged_promise_is_recorded() {
    let code = compile(&unguarded_source());
    let honest = honest_key(0x52);
    for weak in weak_ed25519::sign_bit_aliases() {
        for weak_party in [Party::A, Party::B] {
            let (a_key, b_key) = keys_with(weak_party, weak, &honest);
            let mut channel = Channel::deploy(code.clone(), &a_key, &b_key);
            let data = channel.data_hash();
            channel
                .send(forged_promise_close(weak_party, &weak, &honest))
                .expect("the unguarded channel accepts the forged promise")
                .expect_success();
            assert_ne!(channel.data_hash(), data, "{weak_party:?}: the promise was not recorded");
        }
    }
}

/// Every forgeable weak key, held by either party, signing a joint close or a promise:
/// refused with exit 42 before acceptance, so the external creates no transaction,
/// costs the channel nothing and changes nothing. Repeated three times per case.
#[test]
fn forged_signatures_under_a_weak_party_key_are_refused_before_acceptance() {
    let code = compile(&source());
    let honest = honest_key(0x53);
    let mut refusals = 0;
    for weak in forgeable_weak_keys() {
        for weak_party in [Party::A, Party::B] {
            let (a_key, b_key) = keys_with(weak_party, weak, &honest);
            let mut channel = Channel::deploy(code.clone(), &a_key, &b_key);
            let balance = channel.balance_of(&channel.address.clone());
            let data = channel.data_hash();
            for _ in 0..3 {
                for body in [
                    forged_joint_close(weak_party, &weak, &honest),
                    forged_promise_close(weak_party, &weak, &honest),
                ] {
                    let error = match channel.send(body) {
                        Ok(_) => panic!("{weak_party:?} weak {}: accepted", hex::encode(weak)),
                        Err(error) => error,
                    };
                    assert!(
                        error.contains(&format!("exit code: {ERR_WEAK_KEY}")),
                        "{weak_party:?} weak {}: {error}",
                        hex::encode(weak)
                    );
                    refusals += 1;
                }
            }
            assert_eq!(channel.balance_of(&channel.address.clone()), balance, "a refusal cost");
            assert_eq!(channel.data_hash(), data, "a refusal changed state");
        }
    }
    assert!(refusals >= 2 * 3 * 2 * 10);
}

/// A channel still being funded whose timer has run out: both deposits recorded,
/// nobody has signed.
fn expired_init_state(now: u32) -> Cell {
    cell(|s| {
        s.append_bits(0, 3).unwrap();
        s.append_bit_zero().unwrap();
        s.append_bit_zero().unwrap();
        append_tomis(s, 0);
        append_tomis(s, 0);
        s.append_u32(now - 1).unwrap();
        append_tomis(s, CHANNEL_A);
        append_tomis(s, CHANNEL_B);
    })
}

/// A weak key refuses only its own signatures. Over an internal message the refusal is
/// a failed transaction that changes nothing; the honest party's own signature still
/// verifies; and the timeout path, which needs no signature, still pays both parties
/// out of a channel holding a weak key.
#[test]
fn a_weak_key_blocks_only_its_own_signatures() {
    let code = compile(&source());
    let honest = honest_key(0x54);
    let weak = weak_ed25519::sign_bit_aliases()[0];
    let (a_key, b_key) = keys_with(Party::A, weak, &honest);
    let mut channel = Channel::deploy(code.clone(), &a_key, &b_key);

    let data = channel.data_hash();
    let funder = channel.bc.treasury("internal-sender", 100 * TOS).expect("sender");
    let internal = MessageBuilder::internal(funder.address(), &channel.address, TOS)
        .body(forged_joint_close(Party::A, &weak, &honest))
        .build();
    let result = channel.bc.send_message(internal).expect("internal");
    assert_eq!(exit_code(&result), ERR_WEAK_KEY, "the internal forgery is refused");
    assert_eq!(channel.data_hash(), data, "a refused internal message changed state");

    // B alone, with no promise: B's key verifies, and the contract refuses for its own
    // reason (38), not for the weak key of the party that did not sign.
    let command = close_command(None, 0, TOS);
    let alone = signed_command(None, Some(sign(&honest, &command)), &command);
    let error = channel.send(alone).err().unwrap_or_default();
    assert!(error.contains("exit code: 38"), "{error}");

    // B's real signature put forward as A's is checked against A's weak key: refused.
    let body = promise_body(0, 0);
    let command = close_command(Some((signature_cell(&sign(&honest, &body)), &body)), 0, 0);
    let error = channel.send(signed_command(Some(sign(&honest, &command)), None, &command));
    assert!(error.err().unwrap_or_default().contains(&format!("exit code: {ERR_WEAK_KEY}")));

    // The timeout needs no signature: both parties are paid their deposits.
    let now = channel.bc.now();
    let mut expired = Channel::deploy_with_state(code, &a_key, &b_key, expired_init_state(now));
    let before = (expired.balance_of(&expired.a.clone()), expired.balance_of(&expired.b.clone()));
    let timeout = cell(|m| {
        m.append_u32(OP_PCHAN_CMD).unwrap();
        m.append_bit_zero().unwrap();
        m.append_bit_zero().unwrap();
        m.append_u32(0x4327_8a28).unwrap();
    });
    expired.send(timeout).expect("timeout").expect_success();
    let gained_a = expired.balance_of(&expired.a.clone()) - before.0;
    let gained_b = expired.balance_of(&expired.b.clone()) - before.1;
    // Less the receiving party's own processing fee.
    let fee = u128::from(TOS / 10);
    assert!(
        gained_b <= u128::from(CHANNEL_B) && gained_b + fee >= u128::from(CHANNEL_B),
        "B is paid its deposit: {gained_b}"
    );
    assert!(gained_a + fee >= u128::from(CHANNEL_A), "A is paid at least its deposit: {gained_a}");
}

/// Strong keys on both sides, including keys whose first byte sends them through the
/// full check: a joint close pays out exactly as signed.
#[test]
fn strong_parties_close_the_channel() {
    let code = compile(&source());
    for first in [0x00u8, 0x01, 0x26, 0xc7, 0xec, 0xf7, 0x42] {
        let a = strong_key_starting_with(first, 0x11);
        let b = strong_key_starting_with(first, 0x22);
        let mut channel = Channel::deploy(
            code.clone(),
            &a.verifying_key().to_bytes(),
            &b.verifying_key().to_bytes(),
        );
        let before_b = channel.balance_of(&channel.b.clone());
        let command = close_command(None, TOS, 0);
        let body = signed_command(Some(sign(&a, &command)), Some(sign(&b, &command)), &command);
        channel.send(body).expect("strong close").expect_success();
        let gained = channel.balance_of(&channel.b.clone()) - before_b;
        assert!(
            gained >= u128::from(CHANNEL_B + TOS) - u128::from(TOS / 10)
                && gained <= u128::from(CHANNEL_B + TOS),
            "first byte {first:#04x}: B gained {gained}"
        );
    }
}

/// A signing key whose public key starts with `first`, so the prefilter cannot clear it
/// (unless `first` is one no weak encoding starts with).
fn strong_key_starting_with(first: u8, salt: u8) -> SigningKey {
    (0u32..)
        .map(|n| {
            let mut seed = [salt; 32];
            seed[..4].copy_from_slice(&n.to_le_bytes());
            SigningKey::from_bytes(&seed)
        })
        .find(|key| key.verifying_key().to_bytes()[0] == first)
        .expect("a key with that first byte")
}

/// Pre-acceptance gas of an external close under strong keys whose first byte enters
/// the full check, against the same build without the guards. The most expensive
/// shape checks two stored keys before acceptance: both parties signing, or one party
/// signing and carrying the other's promise.
fn pre_acceptance_gas(source: &str, a: &SigningKey, b: &SigningKey) -> Vec<i64> {
    let code = compile(&probe_source(source));
    let mut channel =
        Channel::deploy(code, &a.verifying_key().to_bytes(), &b.verifying_key().to_bytes());
    let joint = close_command(None, TOS, 0);
    let body = promise_body(TOS, 0);
    let carried = close_command(Some((signature_cell(&sign(b, &body)), &body)), 0, 0);
    [
        signed_command(Some(sign(a, &joint)), Some(sign(b, &joint)), &joint),
        signed_command(Some(sign(a, &carried)), None, &carried),
    ]
    .into_iter()
    .map(|message| {
        let result = channel.send(message).expect("the probe pays for itself");
        i64::from(exit_code(&result))
    })
    .collect()
}

#[test]
fn the_guards_fit_the_external_gas_credit() {
    let guarded = source();
    let unguarded = unguarded_source();
    let mut worst = 0i64;
    let mut worst_overhead = 0i64;
    for first in [0x00u8, 0x01, 0x26, 0xc7, 0xec, 0xff, 0x42] {
        let a = strong_key_starting_with(first, 0x31);
        let b = strong_key_starting_with(first, 0x32);
        let with = pre_acceptance_gas(&guarded, &a, &b);
        let without = pre_acceptance_gas(&unguarded, &a, &b);
        for (shape, (with, without)) in with.iter().zip(&without).enumerate() {
            eprintln!(
                "first byte {first:#04x} shape {shape}: {without} -> {with} gas before acceptance"
            );
            worst = worst.max(*with);
            worst_overhead = worst_overhead.max(with - without);
        }
    }
    eprintln!("worst {worst}, worst guard overhead {worst_overhead}");
    // About 300 gas for each key the prefilter clears and 1,050 for each it cannot;
    // the costliest shapes check two stored keys.
    assert!(worst_overhead <= 2_100, "the guards add {worst_overhead} gas");
    assert!(worst * 10 <= EXTERNAL_GAS_CREDIT * 9, "{worst} leaves under 10% of the credit");
}
