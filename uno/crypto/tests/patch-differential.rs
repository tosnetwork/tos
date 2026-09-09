//! Reproducible primitive corpus; test seeds must never be used by a wallet.
use bulletproofs::{BulletproofGens, InnerProductProof, PedersenGens, RangeProof};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::Transcript;
use rand::{rngs::StdRng, Rng, SeedableRng};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn emit(id: &str, proof: &[u8], commitments: &[u8], t: &mut Transcript, rng: &mut StdRng) {
    let mut tail = [0; 32];
    t.challenge_bytes(b"differential-tail", &mut tail);
    let mut next_rng = [0; 32];
    rng.fill_bytes(&mut next_rng);
    println!("{id}\t{}\t{}\t{}\t{}", hex(proof), hex(commitments), hex(&tail), hex(&next_rng));
}

fn main() {
    let pc = PedersenGens::default();
    for seed in [0u64, 1, 20260909] {
        for n in [1usize, 2, 4, 8, 64, 256] {
            let mut rng = StdRng::seed_from_u64(seed);
            let mut scalar = || Scalar::random(&mut rng);
            let a: Vec<_> = (0..n).map(|_| scalar()).collect();
            let b: Vec<_> = (0..n).map(|_| scalar()).collect();
            let gf: Vec<_> = (0..n).map(|_| scalar()).collect();
            let hf: Vec<_> = (0..n).map(|_| scalar()).collect();
            let g: Vec<RistrettoPoint> = (0..n).map(|_| scalar() * pc.B).collect();
            let h: Vec<RistrettoPoint> = (0..n).map(|_| scalar() * pc.B_blinding).collect();
            let mut t = Transcript::new(b"patch-differential/inner-product");
            let proof = InnerProductProof::create(&mut t, &pc.B, &gf, &hf, g, h, a, b);
            emit(&format!("ip/{seed}/{n}"), &proof.to_bytes(), &[], &mut t, &mut rng);
        }
        for n in [8usize, 16, 32, 64] {
            for m in [1usize, 2, 4, 8, 16, 32] {
                let mut rng = StdRng::seed_from_u64(seed);
                let max = u64::MAX >> (64 - n);
                let values: Vec<_> = (0..m).map(|i| match i % 4 {
                    0 => 0, 1 => max, 2 => 1, _ => rng.next_u64() & max,
                }).collect();
                // Include identity commitments as well as nonzero blindings.
                let blindings: Vec<_> = (0..m).map(|i| if i == 0 { Scalar::ZERO } else { Scalar::random(&mut rng) }).collect();
                let bp = BulletproofGens::new(n, m);
                let mut t = Transcript::new(b"patch-differential/range");
                let (proof, commitments) = RangeProof::prove_multiple_with_rng(
                    &bp, &pc, &mut t, &values, &blindings, n, &mut rng,
                ).expect("valid differential proving inputs");
                let bytes: Vec<_> = commitments.iter().flat_map(|p| p.to_bytes()).collect();
                emit(&format!("range/{seed}/{n}/{m}"), &proof.to_bytes(), &bytes, &mut t, &mut rng);
            }
        }
    }
}
