//! TEST ONLY. Explicit configurations; no host admission or default policy.
use super::*;
use bulletproofs::{BulletproofGens, RangeProof};
use curve25519_dalek::traits::MultiscalarMul;
use rand::{SeedableRng, TryRng};
use tos_uno_crypto_prototype::statement::PreparedStatement;

struct Boundary {
    limits: KernelLimits,
    fee: u64,
    points: Vec<[u8; 32]>,
    ids: Vec<[u8; 32]>,
    scalars: Vec<Scalar>,
    ranges: Vec<u64>,
    blinds: Vec<Scalar>,
    total: u128,
    valid: bool,
}
impl Boundary {
    fn new(bmax: u64, vmax: u64, old: u64, fee: u64, receipts: &[Receipt]) -> Self {
        let mut selected = receipts.to_vec();
        selected.sort_by_key(|r| r.id);
        let total = selected
            .iter()
            .try_fold(u128::from(old), |s, r| s.checked_add(u128::from(r.amount)))
            .and_then(|s| s.checked_sub(u128::from(fee)))
            .expect("checked wide balance");
        let valid = old <= bmax
            && total <= u128::from(bmax)
            && selected.iter().all(|r| r.amount >= 1 && r.amount <= vmax);
        let pc = PedersenGens::default();
        let (s, p) = owner();
        let rho = Scalar::from(887u64);
        let t = Scalar::from(431u64);
        // Group arithmetic constructs even out-of-range negative-test statements;
        // the monetary total above remains checked u128, never a field residue.
        let total_scalar =
            selected.iter().fold(Scalar::from(old), |a, r| a + Scalar::from(r.amount))
                - Scalar::from(fee);
        let mut points = vec![
            p,
            Scalar::from(old) * pc.B + Scalar::from(37u64) * pc.B_blinding,
            Scalar::from(37u64) * p,
            total_scalar * pc.B + rho * pc.B_blinding,
            rho * p,
            Scalar::from(old) * pc.B + t * pc.B_blinding,
        ];
        let mut scalars = vec![s, Scalar::from(old)];
        scalars.extend(selected.iter().map(|r| Scalar::from(r.amount)));
        scalars.extend([rho, t]);
        // Zero is an intentionally FALSE opening only in rejection cases. It
        // lets the test construct a well-shaped proof with valid Sigma equations
        // and isolate the actual verifier's range failure, rather than decoding.
        let mut ranges = vec![
            old,
            bmax.checked_sub(old).unwrap_or(0),
            u64::try_from(total).unwrap_or(0),
            u128::from(bmax).checked_sub(total).and_then(|x| u64::try_from(x).ok()).unwrap_or(0),
        ];
        let mut blinds = vec![t, -t, rho, -rho];
        for (i, r) in selected.iter().enumerate() {
            let ti = Scalar::from(
                503u64.checked_add(u64::try_from(i).expect("index")).expect("auxiliary"),
            );
            points.extend([
                point(r.c),
                point(r.d),
                Scalar::from(r.amount) * pc.B + ti * pc.B_blinding,
            ]);
            scalars.push(ti);
            ranges.extend([
                r.amount.checked_sub(1).unwrap_or(0),
                vmax.checked_sub(r.amount).unwrap_or(0),
            ]);
            blinds.extend([ti, -ti]);
        }
        let n = ranges.len().checked_next_power_of_two().expect("padding");
        ranges.resize(n, 0);
        blinds.resize(n, Scalar::ZERO);
        Self {
            limits: KernelLimits {
                max_balance: bmax,
                max_value: vmax,
                max_collect: 8,
                max_context_bytes: 1024,
                max_proof_bytes: 4096,
            },
            fee,
            points: points.iter().map(|p| p.compress().to_bytes()).collect(),
            ids: selected.iter().map(|r| r.id).collect(),
            scalars,
            ranges,
            blinds,
            total,
            valid,
        }
    }
    fn exercise(&self, label: &str) {
        let domain = domain();
        let statement = Statement {
            kind: UNO_RELATION_COLLECT,
            limits: &self.limits,
            domain: &domain,
            fee: self.fee,
            context: CONTEXT,
            points: &self.points,
            receipt_ids: &self.ids,
        };
        let witness = Witness {
            scalars: &self.scalars,
            range_values: &self.ranges,
            range_blindings: &self.blinds,
        };
        let prepared = PreparedStatement::new(
            statement.kind,
            statement.limits,
            statement.domain,
            statement.fee,
            statement.context,
            statement.points,
            statement.receipt_ids,
        )
        .expect("canonical statement accepted");
        for (row, target) in prepared.rows().iter().zip(prepared.targets()) {
            assert_eq!(
                Point::multiscalar_mul(&self.scalars, row),
                *target,
                "Sigma witness equation"
            );
        }
        if self.valid {
            let proof = prove(&statement, &witness).expect("valid boundary proof");
            assert_eq!(
                verify_relation(
                    statement.kind,
                    statement.limits,
                    statement.domain,
                    statement.fee,
                    statement.context,
                    statement.points,
                    statement.receipt_ids,
                    &proof.commitments,
                    &proof.responses,
                    &proof.range_proof
                ),
                Ok(())
            );
            assert_eq!(
                point(self.points[3]) - owner().0 * point(self.points[4]),
                Scalar::from(u64::try_from(self.total).expect("balance"))
                    * PedersenGens::default().B
            );
            println!("BOUNDARY {label}: b={} prover OK / kernel OK", self.total);
        } else {
            assert_eq!(prove(&statement, &witness), Err(ProverError::RangeOpening));
            let mut seed = [0u8; 32];
            rand::rngs::SysRng.try_fill_bytes(&mut seed).expect("test entropy");
            let mut rng = chacha20::ChaCha12Rng::from_seed(seed);
            let masks: Vec<_> = self.scalars.iter().map(|_| Scalar::random(&mut rng)).collect();
            let commitments: Vec<_> = prepared
                .rows()
                .iter()
                .map(|row| Point::multiscalar_mul(&masks, row).compress().to_bytes())
                .collect();
            let e = prepared.sigma_challenge(&commitments);
            let zs: Vec<_> = masks.iter().zip(&self.scalars).map(|(m, s)| m + e * s).collect();
            for ((row, target), commitment) in
                prepared.rows().iter().zip(prepared.targets()).zip(&commitments)
            {
                assert_eq!(
                    Point::multiscalar_mul(&zs, row),
                    point(*commitment) + e * target,
                    "Sigma verification passes before range rejection"
                );
            }
            let (range, openings) = RangeProof::prove_multiple_with_rng(
                &BulletproofGens::new(64, self.ranges.len()),
                &PedersenGens::default(),
                &mut prepared.range_transcript(),
                &self.ranges,
                &self.blinds,
                64,
                &mut rng,
            )
            .expect("well-formed false-opening range proof");
            assert_ne!(openings, prepared.ranges());
            let responses: Vec<_> = zs.iter().map(Scalar::to_bytes).collect();
            assert_eq!(
                verify_relation(
                    statement.kind,
                    statement.limits,
                    statement.domain,
                    statement.fee,
                    statement.context,
                    statement.points,
                    statement.receipt_ids,
                    &commitments,
                    &responses,
                    &range.to_bytes()
                ),
                Err(AbiStatus::UNO_CRYPTO_VERIFY)
            );
            println!("BOUNDARY {label}: b={} prover RangeOpening / canonical+Sigma OK / kernel range VERIFY=3; u64_fit={}",self.total,u64::try_from(self.total).is_ok());
        }
    }
}
#[test]
fn collect_boundaries_two_explicit_configurations() {
    const FROZEN: u64 = (1u64 << 62) - 1;
    for (label, bmax, vmax) in [("test100to1", 1_000_000, 10_000), ("frozen1to1", FROZEN, FROZEN)] {
        for (case, amount) in [
            ("Vmin", 1_000_000_000),
            ("Vmax", vmax),
            ("VmaxMinus1", vmax.checked_sub(1).expect("positive")),
            ("VmaxPlus1", vmax.checked_add(1).expect("u64")),
        ] {
            let receipt = system(word(ids()["system1"]), amount);
            Boundary::new(bmax, vmax, 0, 17, &[receipt])
                .exercise(&format!("{label}/{case}/old0/fee17"));
        }
        let sys = system(word(ids()["system1"]), vmax);
        let send = user_send();
        Boundary::new(bmax, vmax, 0, 17, &[sys.clone(), send])
            .exercise(&format!("{label}/maxPlusSEND137/old0/fee17"));
        Boundary::new(
            bmax,
            vmax,
            bmax.checked_sub(vmax).expect("ratio").checked_add(17).expect("old"),
            17,
            &[sys.clone()],
        )
        .exercise(&format!("{label}/exactBalanceHard"));
        Boundary::new(
            bmax,
            vmax,
            bmax.checked_sub(vmax).expect("ratio").checked_add(18).expect("old"),
            17,
            &[sys],
        )
        .exercise(&format!("{label}/balanceHardPlus1"));
        let eight: Vec<_> = (1u8..=8).map(|i| system([i; 32], vmax)).collect();
        // Arbitrary explicit test IDs suffice here: this test is range/amount
        // arithmetic, not Native DepositID authentication or system-slot admission.
        Boundary::new(bmax, vmax, 0, 17, &eight).exercise(&format!("{label}/eightMax/old0/fee17"));
    }
    let pair = vec![system([1; 32], FROZEN), system([2; 32], FROZEN)];
    Boundary::new(FROZEN, FROZEN, 0, FROZEN, &pair)
        .exercise("frozen1to1/twoMax/feeVmax/not-a-tariff-proposal");
}
