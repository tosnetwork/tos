use super::*;
use tos_uno_crypto_prototype::{ffi::UNO_RELATION_SEND,
    withdrawal_statement::{WithdrawalAmounts, WithdrawalStatement, public_opening}};

fn run_case(mutation: Option<usize>) {
    run_case_context(mutation, b"authenticated Native destination, account and fee-policy test context", false);
}

fn run_case_context(mutation: Option<usize>, context: &[u8], check_abi: bool) {
    let limits = KernelLimits { max_balance: 10000, max_value: 1000, max_collect: 8,
        max_context_bytes: 1024, max_proof_bytes: 4096 };
    let domain = [42; 80];
    let withdrawal = [7; 32];
    let attempt = [8; 32];
    let amounts = WithdrawalAmounts { principal: 137, outward_fee: 17, return_reserve: 23, operation_fee: 11 };
    let total = amounts.total().expect("checked total");
    assert_eq!(total, 177);
    let gens = PedersenGens::default();
    let secret = Scalar::from(101u64);
    let p = secret.invert() * gens.B_blinding;
    let owner = p.compress().to_bytes();
    let r = public_opening(&domain, &withdrawal, &attempt, &owner, total).expect("opening");
    let rho = Scalar::from(31u64);
    let old_r = Scalar::from(23u64);
    let t = Scalar::from(37u64);
    let old = 10000u64;
    // The adversarial commitment case proves a debit smaller than the payout
    // total while all context bytes still describe the authenticated total.
    let v = if mutation == Some(6) { total.checked_sub(1).expect("positive total") } else { total };
    let new = old.checked_sub(v).and_then(|n| n.checked_sub(amounts.operation_fee)).expect("covered debit");
    let balance_points = [owner, gens.commit(Scalar::from(old), old_r).compress().to_bytes(),
        (old_r * p).compress().to_bytes(), gens.commit(Scalar::from(new), rho).compress().to_bytes(),
        (rho * p).compress().to_bytes(), gens.commit(Scalar::from(old), t).compress().to_bytes()];
    let rebuilt = WithdrawalStatement::new(&limits, domain, withdrawal, attempt, amounts,
        context, balance_points).expect("statement");
    let mut points = *rebuilt.points();
    if mutation == Some(6) { points[6] = gens.commit(Scalar::from(v), r).compress().to_bytes(); }
    let statement = Statement { kind: UNO_RELATION_SEND, limits: &limits, domain: rebuilt.domain(),
        fee: rebuilt.fee(), context: rebuilt.context(), points: &points, receipt_ids: &[] };
    let scalars = [secret, Scalar::from(new), Scalar::from(v), r, rho, t];
    let values = [old, limits.max_balance.checked_sub(old).expect("old bound"), new,
        limits.max_balance.checked_sub(new).expect("new bound"), v.checked_sub(1).expect("positive v"),
        limits.max_value.checked_sub(v).expect("v bound"), 0, 0];
    let blinds = [t, -t, rho, -rho, r, -r, Scalar::ZERO, Scalar::ZERO];
    let proof = prove(&statement, &Witness { scalars: &scalars, range_values: &values,
        range_blindings: &blinds }).expect("real SEND proof");
    assert!(tos_uno_crypto_prototype::verify_relation(UNO_RELATION_SEND, &limits, rebuilt.domain(),
        rebuilt.fee(), rebuilt.context(), &points, &[], &proof.commitments, &proof.responses,
        &proof.range_proof).is_ok(), "the raw relation must accept before testing specialization");
    let checked = rebuilt.verify(&limits, &proof.commitments, &proof.responses, &proof.range_proof);
    if mutation == Some(6) {
        assert_eq!(checked, Err(AbiStatus::UNO_CRYPTO_VERIFY),
            "reconstructed C_t must reject at real cryptographic verification");
        return;
    }
    assert!(checked.is_ok());
    if check_abi {
        use tos_uno_crypto_prototype::ffi::{WithdrawalVerifyRequestV1, uno_crypto_verify_withdrawal_v1};
        let mut request = WithdrawalVerifyRequestV1 {
            abi_version: 1, limits, domain, withdrawal_id: withdrawal, attempt_id: attempt,
            principal: amounts.principal, outward_fee: amounts.outward_fee,
            return_reserve: amounts.return_reserve, operation_fee: amounts.operation_fee,
            balance_points, context: context.as_ptr(), context_bytes: context.len(),
            commitments: proof.commitments.as_ptr(), commitment_count: proof.commitments.len(),
            responses: proof.responses.as_ptr(), response_count: proof.responses.len(),
            proof: proof.range_proof.as_ptr(), proof_bytes: proof.range_proof.len(),
        };
        assert_eq!(unsafe { uno_crypto_verify_withdrawal_v1(&request) }, 0, "real proof through dedicated ABI");
        request.operation_fee += 1;
        assert_eq!(unsafe { uno_crypto_verify_withdrawal_v1(&request) }, 3, "changed statement must fail verification, not decoding");
        request.context_bytes = 565;
        assert_eq!(unsafe { uno_crypto_verify_withdrawal_v1(&request) }, 2, "noncanonical context length");
    }
    let split = WithdrawalAmounts { outward_fee: amounts.outward_fee.checked_add(1).expect("fee increment"),
        return_reserve: amounts.return_reserve.checked_sub(1).expect("reserve decrement"), ..amounts };
    assert_eq!(split.total().expect("same total"), total);
    let changed = WithdrawalStatement::new(&limits, domain, withdrawal, attempt, split,
        context, balance_points).expect("new split");
    assert_eq!(changed.points(), rebuilt.points());
    assert_eq!(changed.verify(&limits, &proof.commitments, &proof.responses, &proof.range_proof),
        Err(AbiStatus::UNO_CRYPTO_VERIFY), "same total must not erase the fee/reserve split from the challenge");
    // Corrupt each generated point after construction, retaining an otherwise
    // valid proof. This tests wrong-point rejection, not deletion of a check.
    for index in [6, 7, 8] {
        let mut wrong = *rebuilt.points();
        wrong[index] = (curve25519_dalek::ristretto::CompressedRistretto(wrong[index])
            .decompress().expect("generated point") + gens.B).compress().to_bytes();
        assert_eq!(tos_uno_crypto_prototype::verify_relation(UNO_RELATION_SEND, &limits, rebuilt.domain(),
            rebuilt.fee(), rebuilt.context(), &wrong, &[], &proof.commitments, &proof.responses,
            &proof.range_proof), Err(AbiStatus::UNO_CRYPTO_VERIFY),
            "wrong generated point {index} must fail at cryptographic verification");
    }
    let prepared = PreparedStatement::new(UNO_RELATION_SEND, &limits, rebuilt.domain(), rebuilt.fee(),
        rebuilt.context(), rebuilt.points(), &[]).expect("unchanged relation shape");
    assert_eq!(prepared.rows().len(), 8);
    assert!(prepared.rows().iter().all(|row| row.len() == 6));
    assert_eq!(prepared.ranges().len(), 8); // Six range objects plus two padding objects.
    assert_eq!(prepared.rows()[6], prepared.rows()[7]);
    assert_eq!(prepared.targets()[6], prepared.targets()[7]);
    // Redundant handles are retained. No claim that omitting one permits minting.
}

#[test]
fn withdrawal_real_proof_and_wrong_generated_points() { run_case(None); }

#[test]
fn withdrawal_dedicated_abi_real_proof() { run_case_context(None, &[42; 566], true); }

#[test]
fn withdrawal_public_bound_is_not_a_constructor_gate() {
    let limits = KernelLimits { max_balance: 10000, max_value: 1000,
        max_collect: 8, max_context_bytes: 1024, max_proof_bytes: 4096 };
    let p = PedersenGens::default().B_blinding.compress().to_bytes();
    let amounts = WithdrawalAmounts { principal: 1001, outward_fee: 0,
        return_reserve: 0, operation_fee: 0 };
    assert!(WithdrawalStatement::new(&limits, [42; 80], [7; 32], [8; 32],
        amounts, b"D66 constructor boundary", [p; 6]).is_ok(),
        "D66: the existing range proof, not construction, enforces T <= V_max");
    // This only tests construction. It does not claim an out-of-range proof
    // can be produced or accepted, or count a transcript mismatch as a range test.
}

#[test]
fn withdrawal_smaller_debit_raw_send_passes_specialization_rejects() { run_case(Some(6)); }

#[test]
fn withdrawal_amount_overflow_and_public_identity_binding() {
    let mut amounts = WithdrawalAmounts { principal: u64::MAX, outward_fee: 1, return_reserve: 0, operation_fee: 0 };
    assert!(amounts.total().is_err());
    amounts.principal = 1;
    amounts.return_reserve = u64::MAX;
    assert!(amounts.total().is_err());
    amounts.principal = 0;
    assert!(amounts.total().is_err());
    let domain = [42; 80];
    let p = PedersenGens::default().B_blinding.compress().to_bytes();
    let r = public_opening(&domain, &[7;32], &[8;32], &p, 177).expect("opening");
    assert_ne!(r, public_opening(&domain, &[9;32], &[8;32], &p, 177).expect("different withdrawal"));
    assert_ne!(r, public_opening(&domain, &[7;32], &[9;32], &p, 177).expect("different attempt"));
    assert_ne!(r, public_opening(&domain, &[7;32], &[8;32], &p, 178).expect("different total"));
    assert!(public_opening(&domain, &[7;32], &[8;32], &[0;32], 177).is_err());
}
