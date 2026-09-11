//! TEST ONLY: algebraic compatibility of existing D33 and R_COLLECT.
//! This is not Native admission, state authentication or pending removal.
use super::{hex, words};
use crate::{prove, Proof, ProverError, Statement, Witness};
use bulletproofs::PedersenGens;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint as Point, Scalar};
use std::collections::BTreeMap;
use tos_uno_crypto_prototype::{ffi::*, verify_relation};

fn fields(text: &str) -> BTreeMap<&str, &str> {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .collect()
}
fn word(text: &str) -> [u8; 32] {
    hex(text).try_into().expect("32-byte fixture field")
}
fn point(bytes: [u8; 32]) -> Point {
    CompressedRistretto(bytes).decompress().expect("canonical point")
}
fn ids() -> BTreeMap<&'static str, &'static str> {
    fields(include_str!("../../../../crypto/test/workchain-m4-collect-ids.txt"))
}
fn domain() -> [u8; 80] {
    let mut bytes = [0; 80];
    for (i, version) in [2u16, 1, 1, 2].into_iter().enumerate() {
        bytes[2 * i..2 * i + 2].copy_from_slice(&version.to_le_bytes());
    }
    bytes[8..12].copy_from_slice(&37i32.to_le_bytes());
    bytes[12..44].fill(0x11);
    bytes[44..48].copy_from_slice(&2i32.to_le_bytes());
    bytes[48..80].fill(0x22);
    bytes
}
fn owner() -> (Scalar, Point) {
    let secret = Scalar::from(223u64);
    (secret, secret.invert() * PedersenGens::default().B_blinding)
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Receipt {
    id: [u8; 32],
    amount: u64,
    c: [u8; 32],
    d: [u8; 32],
    system: bool,
}
fn request(id: [u8; 32], amount: u64) -> SystemEncryptionRequest {
    SystemEncryptionRequest {
        abi_version: UNO_CRYPTO_ABI_VERSION,
        domain: domain(),
        deposit_id: id,
        recipient: owner().1.compress().to_bytes(),
        amount,
    }
}
fn system(id: [u8; 32], amount: u64) -> Receipt {
    let req = request(id, amount);
    let mut out = SystemCiphertext { commitment: [0; 32], handle: [0; 32] };
    assert_eq!(unsafe { uno_crypto_system_encrypt_v1(&req, &mut out) }, 0);
    assert_eq!(unsafe { uno_crypto_system_verify_v1(&req, &out) }, 0);
    Receipt { id, amount, c: out.commitment, d: out.handle, system: true }
}
fn check_system(receipt: &Receipt) -> u32 {
    let supplied = SystemCiphertext { commitment: receipt.c, handle: receipt.d };
    unsafe { uno_crypto_system_verify_v1(&request(receipt.id, receipt.amount), &supplied) }
}
fn user_send() -> Receipt {
    // Verify a fresh proof of the actual M3 SEND statement; consume exactly its
    // transfer C and receiver D, not a separately invented ciphertext.
    let input =
        fields(include_str!("../../../../crypto/test/workchain-m3-vectors/send/request.txt"));
    let limits = KernelLimits {
        max_balance: 1_000_000,
        max_value: 10_000,
        max_collect: 8,
        max_context_bytes: 1024,
        max_proof_bytes: 4096,
    };
    let domain: [u8; 80] = hex(input["domain"]).try_into().expect("domain");
    let context = hex(input["context"]);
    let points = words(input["points"]);
    let fee: u64 = input["fee"].parse().expect("fee");
    let old = 50_000u64;
    let amount = 137u64;
    let new = old.checked_sub(amount).and_then(|n| n.checked_sub(fee)).expect("funded SEND");
    let rho = Scalar::from(149u64);
    let t = Scalar::from(163u64);
    let r = Scalar::from(179u64);
    let scalars = [Scalar::from(101u64), Scalar::from(new), Scalar::from(amount), r, rho, t];
    let values = [
        old,
        limits.max_balance.checked_sub(old).expect("old bound"),
        new,
        limits.max_balance.checked_sub(new).expect("new bound"),
        amount.checked_sub(1).expect("positive"),
        limits.max_value.checked_sub(amount).expect("value bound"),
        0,
        0,
    ];
    let blindings = [t, -t, rho, -rho, r, -r, Scalar::ZERO, Scalar::ZERO];
    let statement = Statement {
        kind: UNO_RELATION_SEND,
        limits: &limits,
        domain: &domain,
        fee,
        context: &context,
        points: &points,
        receipt_ids: &[],
    };
    let proof = prove(
        &statement,
        &Witness { scalars: &scalars, range_values: &values, range_blindings: &blindings },
    )
    .expect("fresh SEND");
    assert_eq!(
        verify_relation(
            UNO_RELATION_SEND,
            &limits,
            &domain,
            fee,
            &context,
            &points,
            &[],
            &proof.commitments,
            &proof.responses,
            &proof.range_proof
        ),
        Ok(())
    );
    assert_eq!(points[1], owner().1.compress().to_bytes());
    Receipt { id: word(ids()["send"]), amount, c: points[6], d: points[8], system: false }
}
struct Collect {
    limits: KernelLimits,
    domain: [u8; 80],
    points: Vec<[u8; 32]>,
    ids: Vec<[u8; 32]>,
    scalars: Vec<Scalar>,
    values: Vec<u64>,
    blindings: Vec<Scalar>,
    total: u64,
    rho: Scalar,
}
const CONTEXT: &[u8] =
    b"M4 D33/COLLECT algebra compatibility; explicit TEST context, not host authentication";
const OLD: u64 = 3107;
const FEE: u64 = 17;
impl Collect {
    fn new(receipts: &[Receipt], rho: Scalar) -> Self {
        assert!(!receipts.is_empty());
        let mut selected = receipts.to_vec();
        selected.sort_by_key(|r| r.id); // One order, regardless of origin.
        let limits = KernelLimits {
            max_balance: (1u64 << 62) - 1,
            max_value: (1u64 << 62) - 1,
            max_collect: 8,
            max_context_bytes: 1024,
            max_proof_bytes: 4096,
        };
        let total = selected
            .iter()
            .try_fold(OLD, |a, r| a.checked_add(r.amount))
            .and_then(|n| n.checked_sub(FEE))
            .expect("COLLECT total");
        let pc = PedersenGens::default();
        let g = pc.B;
        let h = pc.B_blinding;
        let (s, p) = owner();
        let old_r = Scalar::from(37u64);
        let t0 = Scalar::from(431u64);
        let mut points = vec![
            p,
            Scalar::from(OLD) * g + old_r * h,
            old_r * p,
            Scalar::from(total) * g + rho * h,
            rho * p,
            Scalar::from(OLD) * g + t0 * h,
        ];
        let mut scalars = vec![s, Scalar::from(OLD)];
        scalars.extend(selected.iter().map(|r| Scalar::from(r.amount)));
        scalars.extend([rho, t0]);
        let mut values = vec![
            OLD,
            limits.max_balance.checked_sub(OLD).expect("old bound"),
            total,
            limits.max_balance.checked_sub(total).expect("new bound"),
        ];
        let mut blindings = vec![t0, -t0, rho, -rho];
        for (i, receipt) in selected.iter().enumerate() {
            let ti = Scalar::from(
                503u64.checked_add(u64::try_from(i).expect("index")).expect("auxiliary"),
            );
            points.extend([
                point(receipt.c),
                point(receipt.d),
                Scalar::from(receipt.amount) * g + ti * h,
            ]);
            scalars.push(ti);
            values.extend([
                receipt.amount.checked_sub(1).expect("positive"),
                limits.max_value.checked_sub(receipt.amount).expect("receipt range"),
            ]);
            blindings.extend([ti, -ti]);
        }
        let m = values.len().checked_next_power_of_two().expect("padding");
        values.resize(m, 0);
        blindings.resize(m, Scalar::ZERO);
        Self {
            limits,
            domain: domain(),
            points: points.iter().map(|p| p.compress().to_bytes()).collect(),
            ids: selected.iter().map(|r| r.id).collect(),
            scalars,
            values,
            blindings,
            total,
            rho,
        }
    }
    fn prove(&self) -> Result<Proof, ProverError> {
        prove(
            &Statement {
                kind: UNO_RELATION_COLLECT,
                limits: &self.limits,
                domain: &self.domain,
                fee: FEE,
                context: CONTEXT,
                points: &self.points,
                receipt_ids: &self.ids,
            },
            &Witness {
                scalars: &self.scalars,
                range_values: &self.values,
                range_blindings: &self.blindings,
            },
        )
    }
    fn verify(&self, proof: &Proof) -> Result<(), AbiStatus> {
        verify_relation(
            UNO_RELATION_COLLECT,
            &self.limits,
            &self.domain,
            FEE,
            CONTEXT,
            &self.points,
            &self.ids,
            &proof.commitments,
            &proof.responses,
            &proof.range_proof,
        )
    }
    fn check_balance_and_remasking(&self, receipts: &[Receipt]) {
        let (s, p) = owner();
        let pc = PedersenGens::default();
        assert_eq!(
            point(self.points[3]) - s * point(self.points[4]),
            Scalar::from(self.total) * pc.B
        );
        assert_eq!(point(self.points[4]), self.rho * p);
        assert_eq!(
            point(self.points[3]),
            Scalar::from(self.total) * pc.B + self.rho * pc.B_blinding
        );
        for receipt in receipts {
            assert_ne!(self.points[4], receipt.d, "available must not reuse a receipt handle");
            if receipt.system {
                let public_new = system(receipt.id, self.total);
                assert_ne!(
                    self.points[4], public_new.d,
                    "available must not use D33's publicly derived blinding"
                );
            }
        }
    }
}
#[test]
fn system_collect_pure_and_mixed_real_proofs() {
    let sys = system(word(ids()["system1"]), 1_000_000_019);
    let send = user_send();
    for selected in [vec![sys.clone()], vec![sys.clone(), send]] {
        let a = Collect::new(&selected, Scalar::from(887u64));
        let proof = a.prove().expect("existing R_COLLECT must accept system ciphertexts");
        assert_eq!(a.verify(&proof), Ok(()));
        a.check_balance_and_remasking(&selected);
        let b = Collect::new(&selected, Scalar::from(991u64));
        assert_eq!(b.verify(&b.prove().expect("second private blinding")), Ok(()));
        assert_ne!(a.points[3..5], b.points[3..5]);
        assert_eq!(a.total, b.total);
        println!(
            "COLLECT k={} OK; balance={}; origins={:?}; two private rho values verified",
            selected.len(),
            a.total,
            a.ids
                .iter()
                .map(|id| selected.iter().find(|r| r.id == *id).expect("selected").system)
                .collect::<Vec<_>>()
        );
        if selected.len() == 2 {
            let mut unordered = Collect::new(&selected, Scalar::from(887u64));
            unordered.ids.reverse();
            assert_eq!(unordered.verify(&proof), Err(AbiStatus::UNO_CRYPTO_DECODE));
            unordered.ids[1] = unordered.ids[0];
            assert_eq!(unordered.verify(&proof), Err(AbiStatus::UNO_CRYPTO_DECODE));
        }
    }
}
#[test]
fn system_collect_invalid_origin_and_amount_are_distinguished() {
    let sys = system(word(ids()["system1"]), 1_000_000_019);
    let mut wrong_r = sys.clone();
    let pc = PedersenGens::default();
    let r = Scalar::from(17u64);
    wrong_r.c = (Scalar::from(sys.amount) * pc.B + r * pc.B_blinding).compress().to_bytes();
    wrong_r.d = (r * owner().1).compress().to_bytes();
    assert_eq!(check_system(&wrong_r), 3); // D33 reconstruction, not COLLECT provenance.
    let mut wrong_amount = sys.clone();
    wrong_amount.amount = wrong_amount.amount.checked_add(1).expect("amount");
    assert_eq!(check_system(&wrong_amount), 3);
    assert_eq!(
        Collect::new(&[wrong_amount], Scalar::from(887u64)).prove(),
        Err(ProverError::WitnessEquation)
    );
    let mut wrong_id = sys.clone();
    wrong_id.id = word(ids()["system2"]);
    assert_eq!(check_system(&wrong_id), 3);
    let original = Collect::new(&[sys], Scalar::from(887u64));
    let proof = original.prove().expect("baseline");
    let changed = Collect::new(&[wrong_id], Scalar::from(887u64));
    assert_eq!(changed.verify(&proof), Err(AbiStatus::UNO_CRYPTO_VERIFY));
    println!("wrong r: D33 VERIFY=3; wrong amount: D33 VERIFY=3 and prover WitnessEquation; wrong id: D33 VERIFY=3 and reused COLLECT proof VERIFY=3");
}
#[test]
fn system_collect_unselected_input_is_not_a_statement_dependency() {
    let first = system(word(ids()["system1"]), 1_000_000_019);
    let second = system(word(ids()["system2"]), 2_000_000_031);
    let pending = BTreeMap::from([(first.id, first.clone()), (second.id, second.clone())]);
    let before = pending.clone();
    let statement = Collect::new(&[pending[&first.id].clone()], Scalar::from(887u64));
    assert_eq!(statement.verify(&statement.prove().expect("selected only")), Ok(()));
    assert_eq!(pending, before);
    assert_eq!(pending[&second.id], second);
    // This confirms read-only crypto and selected-only construction. It does
    // NOT exercise host pending removal or claim a persisted post-state.
    println!("two system inputs; selected k=1 OK; borrowed unselected input unchanged; host removal NOT tested");
}
