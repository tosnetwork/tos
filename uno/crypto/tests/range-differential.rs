//! Finite primitive comparison corpus. Chosen RNG outputs are test inputs only.
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use merlin::Transcript;
use rand::{TryCryptoRng, TryRng};
use std::{convert::Infallible, env, fs};

struct Factor(u8);
impl TryRng for Factor {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> { Ok(u32::from(self.0)) }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> { Ok(u64::from(self.0)) }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Infallible> {
        bytes.fill(0);
        if let Some(first) = bytes.first_mut() { *first = self.0; }
        Ok(())
    }
}
// This satisfies an API bound for chosen entropy-output testing, not security.
impl TryCryptoRng for Factor {}

fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).expect("hex")).collect()
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

fn check(id: &str, raw: &[u8], values: &[CompressedRistretto], n: usize,
         gens_n: usize, gens_m: usize, domain: &'static [u8], factor: u8) {
    let mut transcript = Transcript::new(domain);
    let bp = BulletproofGens::new(gens_n, gens_m);
    let pc = PedersenGens::default();
    // These markers associate optional residual observations with exact inputs.
    eprintln!("BEGIN\t{id}");
    let accepted = match RangeProof::from_bytes(raw) {
        Err(_) => false,
        Ok(proof) => {
            #[cfg(feature = "independent")]
            { let _ = factor; proof.verify_independent(&bp, &pc, &mut transcript, values, n).is_ok() }
            #[cfg(not(feature = "independent"))]
            { proof.verify_multiple_with_rng(&bp, &pc, &mut transcript, values, n, &mut Factor(factor)).is_ok() }
        }
    };
    let mut tail = [0; 32];
    transcript.challenge_bytes(b"post-verify", &mut tail);
    println!("{id}\t{}\t{}", u8::from(accepted), hex(&tail));
}

#[cfg(feature = "residual-export")]
fn residual_cases() {
    use bulletproofs::independent_residuals_zero;
    use curve25519_dalek::traits::{Identity, IsIdentity};
    let zero = curve25519_dalek::ristretto::RistrettoPoint::identity();
    let g = PedersenGens::default().B;
    for (id, ip, poly) in [("zero", zero, zero), ("ip", g, zero), ("poly", zero, g)] {
        println!("boundary/{id}\t{}", u8::from(independent_residuals_zero(ip, poly)));
    }
    for i in 0..16u64 {
        let mut t = Transcript::new(b"range-residual-boundary");
        t.append_u64(b"index", i);
        let mut wide = [0; 64];
        t.challenge_bytes(b"c", &mut wide);
        let c = if i == 0 { Scalar::ONE } else { Scalar::from_bytes_mod_order_wide(&wide) };
        assert_ne!(c, Scalar::ZERO);
        let poly = Scalar::from(i + 1) * g;
        let ip = -c * poly;
        println!("collision/{i}\t{}\t{}\t{}", u8::from((ip+c*poly).is_identity()),
                 u8::from(independent_residuals_zero(ip, poly)), hex(&c.to_bytes()));
    }
}

fn main() {
    let args: Vec<_> = env::args().collect();
    #[cfg(feature = "residual-export")]
    if args.get(1).map(String::as_str) == Some("residuals") { residual_cases(); return; }
    assert_eq!(args.len(), 3, "corpus and nonzero outer factor required");
    let factor: u8 = args[2].parse().expect("outer factor");
    assert_ne!(factor, 0, "zero factor has separate evidence, not the D41 baseline");
    let corpus = fs::read_to_string(&args[1]).expect("required corpus");
    let mut valid_count = 0;
    for line in corpus.lines() {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 5);
        let parts: Vec<_> = fields[0].split('/').collect();
        if parts[0] != "range" { continue; }
        valid_count += 1;
        let n: usize = parts[2].parse().expect("bits");
        let m: usize = parts[3].parse().expect("parties");
        let proof = unhex(fields[1]);
        let values: Vec<_> = unhex(fields[2]).chunks_exact(32)
            .map(|p| CompressedRistretto(p.try_into().expect("point"))).collect();
        let run = |suffix: &str, bytes: &[u8], vs: &[CompressedRistretto], bits, gn, gm, domain| {
            check(&format!("{}/{suffix}", fields[0]), bytes, vs, bits, gn, gm, domain, factor);
        };
        let domain: &'static [u8] = b"patch-differential/range";
        run("valid", &proof, &values, n, n, m, domain);
        // Exercise all supported shapes without multiplying the expensive
        // maximum-size proof by the complete malformed-field matrix.
        let mut changed = proof.clone();
        let e_blinding = Option::<Scalar>::from(Scalar::from_canonical_bytes(
            proof[192..224].try_into().expect("response bytes"))).expect("canonical response");
        changed[192..224].copy_from_slice(&(e_blinding+Scalar::ONE).to_bytes());
        run("ip-only-response", &changed, &values, n, n, m, domain);
        run("wrong-domain", &proof, &values, n, n, m, b"wrong-domain");
        if parts[1] != "0" || !((n == 8 && m == 1) || (n == 64 && m == 2)) { continue; }
        for block in 0..proof.len()/32 {
            for (label, replacement) in [("zero", [0u8;32]), ("invalid", [255u8;32]),
                                         ("point", PedersenGens::default().B.compress().to_bytes())] {
                let mut changed = proof.clone();
                changed[block*32..block*32+32].copy_from_slice(&replacement);
                if changed == proof { continue; }
                run(&format!("field-{block}-{label}"), &changed, &values, n, n, m, domain);
            }
        }
        for i in 0..m {
            for (label, p) in [("zero", [0u8;32]), ("invalid", [255u8;32]),
                              ("point", PedersenGens::default().B.compress().to_bytes())] {
                let mut changed = values.clone(); changed[i] = CompressedRistretto(p);
                if changed == values { continue; }
                run(&format!("commitment-{i}-{label}"), &proof, &changed, n, n, m, domain);
            }
        }
        for length in [0, 1, proof.len()-1, proof.len()-32] {
            run(&format!("truncated-{length}"), &proof[..length], &values, n, n, m, domain);
        }
        let mut trailing = proof.clone(); trailing.push(0);
        run("trailing", &trailing, &values, n, n, m, domain);
        run("invalid-bits", &proof, &values, 7, n, m, domain);
        run("short-generators", &proof, &values, n, n-1, m, domain);
        run("short-parties", &proof, &values, n, n, m-1, domain);
        run("empty-values", &proof, &[], n, n, m, domain);
        let mut nonpower = values.clone(); nonpower.resize(3, values[0]);
        run("nonpower-values", &proof, &nonpower, n, n, 3, domain);
    }
    assert_eq!(valid_count, 72, "incomplete corpus");
}
