use super::*;
use rand::TryRng;

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i.checked_add(2).expect("hex index")], 16)
        .expect("frozen hex")).collect()
}

fn words(s: &str) -> Vec<[u8; 32]> {
    let bytes = hex(s);
    assert_eq!(bytes.len() % 32, 0);
    bytes.chunks_exact(32).map(|x| x.try_into().expect("word")).collect()
}

struct Fixture {
    limits: KernelLimits, domain: [u8; 80], kind: u32, fee: u64, context: Vec<u8>,
    points: Vec<[u8; 32]>, ids: Vec<[u8; 32]>, expected: Proof,
    scalars: Vec<Scalar>, values: Vec<u64>, blinds: Vec<Scalar>,
}

impl Fixture {
    fn statement(&self) -> Statement<'_> {
        Statement { kind: self.kind, limits: &self.limits, domain: &self.domain, fee: self.fee,
            context: &self.context, points: &self.points, receipt_ids: &self.ids }
    }
    fn witness(&self) -> Witness<'_> {
        Witness { scalars: &self.scalars, range_values: &self.values, range_blindings: &self.blinds }
    }
}

fn fixture(k: usize) -> Fixture {
    // Public inputs come from the independently frozen verifier artifact. Only
    // the known fixture secrets are reconstructed here; this is not a builder.
    let lines: Vec<_> = include_str!("../../crypto/fixtures/balance-kernel-v2.txt").lines().collect();
    assert_eq!(lines.len(), 9);
    let row: Vec<_> = lines[k].split('|').collect();
    assert_eq!(row.len(), 12);
    let limits = KernelLimits { max_balance: row[1].parse().expect("balance limit"),
        max_value: row[2].parse().expect("value limit"), max_collect: row[3].parse().expect("k limit"),
        max_context_bytes: 1024, max_proof_bytes: 4096 };
    let fee: u64 = row[11].parse().expect("fee");
    let old = 1000u64;
    let s = Scalar::from(11u64); let rho = Scalar::from(19u64); let t = Scalar::from(23u64);
    let (scalars, mut values, mut blinds) = if k == 0 {
        let v = 7u64; let new = old.checked_sub(v).and_then(|v| v.checked_sub(fee)).expect("funded");
        let r = Scalar::from(17u64);
        (vec![s, Scalar::from(new), Scalar::from(v), r, rho, t],
         vec![old, limits.max_balance.checked_sub(old).expect("bound"), new,
              limits.max_balance.checked_sub(new).expect("bound"), v.checked_sub(1).expect("positive"),
              limits.max_value.checked_sub(v).expect("bound")], vec![t, -t, rho, -rho, r, -r])
    } else {
        let amounts: Vec<_> = (0..k).map(|i| 7u64.checked_add(u64::try_from(i).expect("k")).expect("v")).collect();
        let ts: Vec<_> = (0..k).map(|i| Scalar::from(101u64.checked_add(u64::try_from(i).expect("k")).expect("t"))).collect();
        let new = amounts.iter().try_fold(old, |a, b| a.checked_add(*b)).and_then(|a| a.checked_sub(fee)).expect("funded");
        let mut scalars = vec![s, Scalar::from(old)];
        scalars.extend(amounts.iter().copied().map(Scalar::from)); scalars.extend([rho, t]); scalars.extend(&ts);
        let mut values = vec![old, limits.max_balance.checked_sub(old).expect("bound"), new,
            limits.max_balance.checked_sub(new).expect("bound")];
        let mut blinds = vec![t, -t, rho, -rho];
        for (v, t) in amounts.iter().zip(ts) {
            values.extend([v.checked_sub(1).expect("positive"), limits.max_value.checked_sub(*v).expect("bound")]);
            blinds.extend([t, -t]);
        }
        (scalars, values, blinds)
    };
    let m = values.len().checked_next_power_of_two().expect("padding");
    values.resize(m, 0); blinds.resize(m, Scalar::ZERO);
    Fixture { limits, domain: hex(row[10]).try_into().expect("domain"), kind: row[0].parse().expect("kind"),
        fee, context: hex(row[4]), points: words(row[5]), ids: words(row[6]),
        expected: Proof { commitments: words(row[7]), responses: words(row[8]), range_proof: hex(row[9]) },
        scalars, values, blinds }
}

#[test]
fn reproduces_all_frozen_send_and_collect_proofs() {
    for k in 0..=8 {
        let f = fixture(k);
        let p = prepare(&f.statement(), &f.witness()).expect("valid fixture");
        let mut rng = ChaCha12Rng::seed_from_u64(20260907u64.checked_add(u64::try_from(k).expect("k")).expect("seed"));
        let actual = generate(&f.statement(), &f.witness(), &p, &mut rng).expect("production generator");
        assert_eq!(actual.commitments.len(), f.expected.commitments.len(), "commitment count k={k}");
        assert_eq!(actual.responses.len(), f.expected.responses.len(), "response count k={k}");
        assert_eq!(actual.range_proof.len(), f.expected.range_proof.len(), "range bytes k={k}");
        assert_eq!(actual.commitments.iter().zip(&f.expected.commitments).position(|(a,b)| a != b),
            None, "first differing commitment k={k}");
        assert_eq!(actual.responses.iter().zip(&f.expected.responses).position(|(a,b)| a != b),
            None, "first differing response k={k}");
        assert_eq!(actual.range_proof.iter().zip(&f.expected.range_proof).position(|(a,b)| a != b),
            None, "first differing range byte k={k}");
    }
}

#[test]
fn fresh_entropy_proofs_verify_for_every_supported_size() {
    for k in 0..=8 {
        let f = fixture(k);
        let a = prove(&f.statement(), &f.witness()).expect("fresh proof");
        let b = prove(&f.statement(), &f.witness()).expect("second fresh proof");
        assert_ne!(a.commitments, b.commitments, "fresh masks k={k}");
        for proof in [a, b] {
            assert_eq!(tos_uno_crypto_prototype::verify_relation(f.kind, &f.limits, &f.domain, f.fee,
                &f.context, &f.points, &f.ids, &proof.commitments, &proof.responses, &proof.range_proof), Ok(()));
        }
    }
}

struct Unavailable { calls: usize }
impl TryRng for Unavailable {
    type Error = std::io::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> { panic!("seed must use fill") }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> { panic!("seed must use fill") }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
        self.calls = self.calls.checked_add(1).expect("calls");
        Err(std::io::Error::other("injected entropy failure"))
    }
}
impl TryCryptoRng for Unavailable {}

#[test]
fn invalid_witnesses_are_rejected_before_entropy_and_entropy_failure_is_reported() {
    let mut f = fixture(0); let mut entropy = Unavailable { calls: 0 };
    assert_eq!(prove_from_entropy(&f.statement(), &f.witness(), &mut entropy), Err(ProverError::EntropyUnavailable));
    assert_eq!(entropy.calls, 1, "entropy counter positive control"); entropy.calls = 0;
    f.scalars[0] += Scalar::ONE;
    assert_eq!(prove_from_entropy(&f.statement(), &f.witness(), &mut entropy), Err(ProverError::WitnessEquation));
    assert_eq!(entropy.calls, 0); f.scalars[0] -= Scalar::ONE;
    f.values[0] = f.values[0].checked_add(1).expect("mutation");
    assert_eq!(prove_from_entropy(&f.statement(), &f.witness(), &mut entropy), Err(ProverError::RangeOpening));
    assert_eq!(entropy.calls, 0); f.values[0] = f.values[0].checked_sub(1).expect("restore");
    f.scalars.pop().expect("fixture witness");
    assert_eq!(prove_from_entropy(&f.statement(), &f.witness(), &mut entropy), Err(ProverError::WitnessShape));
    assert_eq!(entropy.calls, 0);
}

#[test]
fn invalid_public_statement_is_local_and_precedes_entropy() {
    let mut f = fixture(0); let mut entropy = Unavailable { calls: 0 };
    assert_eq!(prove_from_entropy(&f.statement(), &f.witness(), &mut entropy), Err(ProverError::EntropyUnavailable));
    assert_eq!(entropy.calls, 1); entropy.calls = 0;
    f.limits.max_value = 0;
    assert_eq!(prove_from_entropy(&f.statement(), &f.witness(), &mut entropy),
        Err(ProverError::Statement(AbiStatus::UNO_CRYPTO_ARGUMENTS)));
    assert_eq!(entropy.calls, 0);
    f.limits.max_value = 10000; f.context.clear();
    assert_eq!(prove_from_entropy(&f.statement(), &f.witness(), &mut entropy),
        Err(ProverError::Statement(AbiStatus::UNO_CRYPTO_DECODE)));
    assert_eq!(entropy.calls, 0);
}

mod system_collect;
