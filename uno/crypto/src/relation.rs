//! Read-only balance relations. State authentication and settlement are caller obligations.
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{RistrettoPoint as Point, Scalar, ristretto::CompressedRistretto,
    traits::{Identity, IsIdentity, VartimeMultiscalarMul}};
use merlin::Transcript;
use crate::ffi::{AbiStatus as Error, KernelLimits, UNO_RELATION_COLLECT, UNO_RELATION_SEND};

pub(crate) struct Relation {
    pub rows: Vec<Vec<Point>>,
    pub targets: Vec<Point>,
    pub ranges: Vec<CompressedRistretto>,
    pub transcript: Transcript,
}

fn decode(bytes: &[u8; 32]) -> Result<Point, Error> {
    CompressedRistretto(*bytes).decompress().ok_or(Error::UNO_CRYPTO_DECODE)
}

pub(crate) fn shapes(kind: u32, k: usize) -> Result<(usize, usize, usize, usize), Error> {
    if kind == UNO_RELATION_SEND && k == 0 { return Ok((10, 8, 6, 8)); }
    if kind != UNO_RELATION_COLLECT || k == 0 { return Err(Error::UNO_CRYPTO_DECODE); }
    let twice = k.checked_mul(2).ok_or(Error::UNO_CRYPTO_DECODE)?;
    Ok((k.checked_mul(3).and_then(|x| x.checked_add(6)).ok_or(Error::UNO_CRYPTO_DECODE)?,
        twice.checked_add(5).ok_or(Error::UNO_CRYPTO_DECODE)?,
        twice.checked_add(4).ok_or(Error::UNO_CRYPTO_DECODE)?,
        twice.checked_add(4).and_then(usize::checked_next_power_of_two).ok_or(Error::UNO_CRYPTO_DECODE)?))
}

pub(crate) fn range_size(m: usize) -> Result<usize, Error> {
    let n = m.checked_mul(64).ok_or(Error::UNO_CRYPTO_DECODE)?;
    let log = n.checked_ilog2().ok_or(Error::UNO_CRYPTO_DECODE)? as usize;
    log.checked_mul(2).and_then(|x| x.checked_add(9)).and_then(|x| x.checked_mul(32))
        .ok_or(Error::UNO_CRYPTO_DECODE)
}

pub(crate) fn validate_limits(limits: &KernelLimits) -> Result<(), Error> {
    // A policy beyond this implementation ceiling is unsupported, not a
    // candidate-invalid result. This bounds the dense matrix before allocation.
    if limits.max_collect > 64 { return Err(Error::UNO_CRYPTO_ARGUMENTS); }
    // Nonzero max_value <= max_balance implies nonzero max_balance.
    if limits.max_value == 0 || limits.max_value > limits.max_balance
        || limits.max_collect == 0 || limits.max_context_bytes == 0 || limits.max_proof_bytes == 0 {
        return Err(Error::UNO_CRYPTO_ARGUMENTS);
    }
    Ok(())
}

pub(crate) fn prepare(
    kind: u32, limits: &KernelLimits, context: &[u8], encoded: &[[u8; 32]], ids: &[[u8; 32]],
) -> Result<Relation, Error> {
    validate_limits(limits)?;
    if ids.len() > limits.max_collect || context.is_empty() || context.len() > limits.max_context_bytes {
        return Err(Error::UNO_CRYPTO_DECODE);
    }
    if ids.windows(2).any(|pair| pair[0] >= pair[1]) { return Err(Error::UNO_CRYPTO_DECODE); }
    let (point_count, equation_count, witnesses, m) = shapes(kind, ids.len())?;
    if encoded.len() != point_count || range_size(m)? > limits.max_proof_bytes {
        return Err(Error::UNO_CRYPTO_DECODE);
    }
    let points: Vec<_> = encoded.iter().map(decode).collect::<Result<_, _>>()?;
    let pc = PedersenGens::default();
    let g = pc.B;
    let h = pc.B_blinding;
    let zero = Point::identity();
    let bmax = Scalar::from(limits.max_balance) * g;
    let vmax = Scalar::from(limits.max_value) * g;
    let mut rows = Vec::with_capacity(equation_count);
    let mut targets = Vec::with_capacity(equation_count);
    let mut push = |terms: &[(usize, Point)], target: Point| -> Result<(), Error> {
        let mut row = vec![zero; witnesses];
        for (index, point) in terms {
            *row.get_mut(*index).ok_or(Error::UNO_CRYPTO_ARGUMENTS)? += point;
        }
        rows.push(row); targets.push(target); Ok(())
    };
    let mut ranges;
    // Exact point counts were checked before indexing. Group subtraction is
    // field arithmetic; no monetary integer is subtracted here.
    if kind == UNO_RELATION_SEND {
        let p = &points;
        if [p[0], p[1], p[5], p[7], p[8]].iter().any(Point::is_identity) {
            return Err(Error::UNO_CRYPTO_DECODE);
        }
        push(&[(0, p[0])], h)?;
        push(&[(0, p[3]), (1, g), (2, g)], p[2])?;
        push(&[(1, g), (2, g), (5, h)], p[9])?;
        push(&[(1, g), (4, h)], p[4])?;
        push(&[(4, p[0])], p[5])?;
        push(&[(2, g), (3, h)], p[6])?;
        push(&[(3, p[0])], p[7])?;
        push(&[(3, p[1])], p[8])?;
        ranges = vec![p[9], bmax - p[9], p[4], bmax - p[4], p[6] - g, vmax - p[6]];
    } else {
        let p = &points;
        if p[0].is_identity() || p[4].is_identity() { return Err(Error::UNO_CRYPTO_DECODE); }
        let k = ids.len();
        let rho = k.checked_add(2).ok_or(Error::UNO_CRYPTO_DECODE)?;
        let t0 = k.checked_add(3).ok_or(Error::UNO_CRYPTO_DECODE)?;
        push(&[(0, p[0])], h)?;
        push(&[(0, p[2]), (1, g)], p[1])?;
        for (i, receipt) in p[6..].chunks_exact(3).enumerate() {
            if receipt[1].is_identity() { return Err(Error::UNO_CRYPTO_DECODE); }
            let vi = i.checked_add(2).ok_or(Error::UNO_CRYPTO_DECODE)?;
            push(&[(0, receipt[1]), (vi, g)], receipt[0])?;
        }
        push(&[(1, g), (t0, h)], p[5])?;
        ranges = vec![p[5], bmax - p[5], p[3], bmax - p[3]];
        for (i, receipt) in p[6..].chunks_exact(3).enumerate() {
            let vi = i.checked_add(2).ok_or(Error::UNO_CRYPTO_DECODE)?;
            let ti = t0.checked_add(1).and_then(|x| x.checked_add(i)).ok_or(Error::UNO_CRYPTO_DECODE)?;
            push(&[(vi, g), (ti, h)], receipt[2])?;
            ranges.extend([receipt[2] - g, vmax - receipt[2]]);
        }
        let mut terms = vec![(1, g), (rho, h)];
        for i in 0..k { terms.push((i.checked_add(2).ok_or(Error::UNO_CRYPTO_DECODE)?, g)); }
        push(&terms, p[3])?;
        push(&[(rho, p[0])], p[4])?;
    }
    ranges.resize(m, zero);
    let mut transcript = Transcript::new(b"TOS-UNO-BALANCE-KERNEL-EXPERIMENTAL-v1");
    transcript.append_u64(b"relation", u64::from(kind));
    transcript.append_u64(b"max-balance", limits.max_balance);
    transcript.append_u64(b"max-value", limits.max_value);
    transcript.append_message(b"authenticated-context", context);
    transcript.append_u64(b"point-count", u64::try_from(encoded.len()).map_err(|_| Error::UNO_CRYPTO_ARGUMENTS)?);
    for point in encoded { transcript.append_message(b"public-point", point); }
    transcript.append_u64(b"receipt-count", u64::try_from(ids.len()).map_err(|_| Error::UNO_CRYPTO_ARGUMENTS)?);
    for id in ids { transcript.append_message(b"receipt-id", id); }
    Ok(Relation { rows, targets, ranges: ranges.iter().map(Point::compress).collect(), transcript })
}

pub(crate) fn sigma_transcript(mut t: Transcript, commitments: &[[u8; 32]]) -> (Transcript, Scalar) {
    t.append_message(b"subprotocol", b"shared-witness-AND-v1");
    for commitment in commitments { t.append_message(b"T", commitment); }
    let mut wide = [0; 64];
    t.challenge_bytes(b"e", &mut wide);
    (t, Scalar::from_bytes_mod_order_wide(&wide))
}

pub(crate) fn range_transcript(mut t: Transcript) -> Transcript {
    t.append_message(b"subprotocol", b"range-v1"); t
}

/// This checks cryptography only, not whether context describes an authentic
/// account, an unconsumed nonce, a registered recipient or reserved capacity.
pub fn verify_relation(
    kind: u32, limits: &KernelLimits, context: &[u8], points: &[[u8; 32]], ids: &[[u8; 32]],
    commitments: &[[u8; 32]], responses: &[[u8; 32]], proof: &[u8],
) -> Result<(), Error> {
    validate_limits(limits)?;
    let (_, equations, witnesses, m) = shapes(kind, ids.len())?;
    if commitments.len() != equations || responses.len() != witnesses || proof.len() != range_size(m)? {
        return Err(Error::UNO_CRYPTO_DECODE);
    }
    let relation = prepare(kind, limits, context, points, ids)?;
    let ts: Vec<_> = commitments.iter().map(decode).collect::<Result<_, _>>()?;
    let zs: Vec<Scalar> = responses.iter().map(|s| Option::<Scalar>::from(Scalar::from_canonical_bytes(*s))
        .ok_or(Error::UNO_CRYPTO_DECODE)).collect::<Result<_, _>>()?;
    let (_, e) = sigma_transcript(relation.transcript.clone(), commitments);
    check_sigma(&relation.rows, &relation.targets, &ts, &zs, e)?;
    let range = RangeProof::from_bytes(proof).map_err(|_| Error::UNO_CRYPTO_DECODE)?;
    let generators = BulletproofGens::new(64, m);
    range.verify_independent(&generators, &PedersenGens::default(),
        &mut range_transcript(relation.transcript), &relation.ranges, 64)
        .map_err(|_| Error::UNO_CRYPTO_VERIFY)
}

pub(crate) fn check_sigma(rows: &[Vec<Point>], targets: &[Point], ts: &[Point], zs: &[Scalar], e: Scalar)
    -> Result<(), Error> {
    if rows.is_empty() || rows.len() != targets.len() || rows.len() != ts.len()
        || rows.iter().any(|row| row.len() != zs.len()) {
        return Err(Error::UNO_CRYPTO_DECODE);
    }
    for ((row, target), t) in rows.iter().zip(targets).zip(ts) {
        // One response slot per witness is shared by every equation.
        if Point::vartime_multiscalar_mul(zs, row) != t + e * target {
            return Err(Error::UNO_CRYPTO_VERIFY);
        }
    }
    Ok(())
}
