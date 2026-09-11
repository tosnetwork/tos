//! TEST WALLET ONLY: known witnesses for the continuous M3 scenario. Not a deployment wallet.
use bulletproofs::PedersenGens;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint as Point, Scalar};
use sha2::{Digest, Sha512};
use std::{collections::BTreeMap, error::Error, fs};
use tos_uno_crypto_prototype::ffi::KernelLimits;
use tos_uno_wallet_prover::{prove, Statement, Witness};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn fail(s: &str) -> Box<dyn Error> {
    std::io::Error::other(s).into()
}
fn unhex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(fail("odd hex"));
    }
    (0..s.len()).step_by(2).map(|i| Ok(u8::from_str_radix(&s[i..i + 2], 16)?)).collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn points(p: &[Point]) -> String {
    p.iter().map(|x| hex(x.compress().as_bytes())).collect()
}
fn bytes32(s: &str) -> Result<Vec<[u8; 32]>> {
    let b = unhex(s)?;
    if b.len() % 32 != 0 {
        return Err(fail("word size"));
    }
    b.chunks_exact(32).map(|v| v.try_into().map_err(|_| fail("word"))).collect()
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err(fail("m3-scenario MODE request.txt output.txt"));
    }
    let mut m = BTreeMap::new();
    for l in fs::read_to_string(&args[2])?.lines() {
        let (k, v) = l.split_once('=').ok_or_else(|| fail("key=value"))?;
        if m.insert(k.to_string(), v.to_string()).is_some() {
            return Err(fail("duplicate field"));
        }
    }
    let f = |k: &str| m.get(k).map(String::as_str).ok_or_else(|| fail(k));
    let n = |k: &str| -> Result<u64> { Ok(f(k)?.parse()?) };
    let s = Scalar::from(n("secret")?);
    let pc = PedersenGens::default();
    let g = pc.B;
    let h = pc.B_blinding;
    let p = s.invert() * h;
    if args[1] == "key" {
        fs::write(&args[3], format!("public_key={}\n", points(&[p])))?;
        return Ok(());
    }
    if args[1] == "register" || args[1] == "close" {
        // Fixed TEST nonce. This tool must never sign real-value wallet requests.
        let k = Scalar::from(997u64);
        let r1 = k * p;
        let mut hash = Sha512::new();
        let closing = args[1] == "close";
        hash.update(if closing {
            b"TOS/UNO/CLOSE/KEY-POSSESSION/v2".as_slice()
        } else {
            b"TOS/UNO/REGISTER/KEY-POSSESSION/v2".as_slice()
        });
        let context = unhex(f("context")?)?;
        if context.len() != 426 {
            return Err(fail("possession v2 requires 426 context bytes").into());
        }
        hash.update(context);
        hash.update(unhex(f("prefix")?)?);
        hash.update(p.compress().as_bytes());
        let r2 = if closing {
            let d = curve25519_dalek::ristretto::CompressedRistretto(bytes32(f("handle")?)?[0])
                .decompress()
                .ok_or_else(|| fail("D"))?;
            hash.update(h.compress().as_bytes());
            hash.update(unhex(f("handle")?)?);
            hash.update(unhex(f("commitment")?)?);
            let r2 = k * d;
            hash.update(r1.compress().as_bytes());
            hash.update(r2.compress().as_bytes());
            Some(r2)
        } else {
            hash.update(r1.compress().as_bytes());
            None
        };
        let c = Scalar::from_bytes_mod_order_wide(&hash.finalize().into());
        let z = k + c * s;
        let mut proof = points(&[r1]);
        if let Some(r2) = r2 {
            proof += &points(&[r2]);
        }
        proof += &hex(&z.to_bytes());
        fs::write(&args[3], format!("proof={proof}\n"))?;
        return Ok(());
    }
    let old = n("old_value")?;
    let oldr = Scalar::from(n("old_blind")?);
    let rho = Scalar::from(n("new_blind")?);
    let t = Scalar::from(n("aux_blind")?);
    let fee = n("fee")?;
    let oldc = Scalar::from(old) * g + oldr * h;
    let oldd = oldr * p;
    if args[1] == "seed" {
        fs::write(&args[3], format!("available={}\n", points(&[oldc, oldd])))?;
        return Ok(());
    }
    if args[1] == "withdrawal-points" || args[1] == "withdrawal-prove" {
        use tos_uno_crypto_prototype::withdrawal_statement::{WithdrawalAmounts, WithdrawalStatement, public_opening};
        let amounts = WithdrawalAmounts { principal: n("principal")?, outward_fee: n("outward_fee")?,
            return_reserve: n("return_reserve")?, operation_fee: fee };
        let total = amounts.total().map_err(|e| fail(&format!("total {e:?}")))?;
        let new = old.checked_sub(total).and_then(|v| v.checked_sub(fee)).ok_or_else(|| fail("Withdrawal debit"))?;
        let balance = [p, oldc, oldd, Scalar::from(new)*g + rho*h, rho*p, Scalar::from(old)*g+t*h];
        if args[1] == "withdrawal-points" {
            fs::write(&args[3], format!("points={}\n", points(&balance[3..])))?;
            return Ok(());
        }
        let limits = KernelLimits { max_balance:n("max_balance")?, max_value:n("max_value")?,
            max_collect:8, max_context_bytes:1024, max_proof_bytes:4096 };
        let domain:[u8;80] = unhex(f("domain")?)?.try_into().map_err(|_| fail("domain"))?;
        let wid = bytes32(f("withdrawal_id")?)?[0]; let aid = bytes32(f("attempt_id")?)?[0];
        let encoded = balance.map(|v| v.compress().to_bytes());
        let statement = WithdrawalStatement::new(&limits, domain, wid, aid, amounts,
            &unhex(f("context")?)?, encoded).map_err(|e| fail(&format!("statement {e:?}")))?;
        let r = public_opening(&domain, &wid, &aid, &encoded[0], total).map_err(|e| fail(&format!("opening {e:?}")))?;
        let values = [old, limits.max_balance.checked_sub(old).ok_or_else(||fail("old bound"))?,
            new, limits.max_balance.checked_sub(new).ok_or_else(||fail("new bound"))?,
            total.checked_sub(1).ok_or_else(||fail("positive total"))?,
            limits.max_value.checked_sub(total).ok_or_else(||fail("total bound"))?,0,0];
        let scalars = [s, Scalar::from(new), Scalar::from(total), r, rho, t];
        let blinds = [t,-t,rho,-rho,r,-r,Scalar::ZERO,Scalar::ZERO];
        let proof = prove(&Statement {kind:1,limits:&limits,domain:statement.domain(),fee,
            context:statement.context(),points:statement.points(),receipt_ids:&[]},
            &Witness {scalars:&scalars,range_values:&values,range_blindings:&blinds})
            .map_err(|e|fail(&format!("prove {e:?}")))?;
        fs::write(&args[3],format!("commitments={}\nresponses={}\nrange_proof={}\n",
            proof.commitments.iter().map(|p|hex(p)).collect::<String>(),
            proof.responses.iter().map(|p|hex(p)).collect::<String>(),hex(&proof.range_proof)))?;
        return Ok(());
    }
    let kind = n("kind")? as u32;
    let maxb = n("max_balance")?;
    let maxv = n("max_value")?;
    let (pp, scalars, mut values, mut blinds, new) = if kind == 1 {
        let v = n("value")?;
        let r = Scalar::from(n("transfer_blind")?);
        let pb = Scalar::from(n("receiver_secret")?).invert() * h;
        let new = old
            .checked_sub(v)
            .and_then(|x| x.checked_sub(fee))
            .ok_or_else(|| fail("SEND underflow"))?;
        (
            vec![
                p,
                pb,
                oldc,
                oldd,
                Scalar::from(new) * g + rho * h,
                rho * p,
                Scalar::from(v) * g + r * h,
                r * p,
                r * pb,
                Scalar::from(old) * g + t * h,
            ],
            vec![s, Scalar::from(new), Scalar::from(v), r, rho, t],
            vec![
                old,
                maxb.checked_sub(old).ok_or_else(|| fail("old range"))?,
                new,
                maxb.checked_sub(new).ok_or_else(|| fail("new range"))?,
                v.checked_sub(1).ok_or_else(|| fail("positive SEND"))?,
                maxv.checked_sub(v).ok_or_else(|| fail("value range"))?,
            ],
            vec![t, -t, rho, -rho, r, -r],
            new,
        )
    } else if kind == 2 {
        let authenticated_receipts =
            matches!(args[1].as_str(), "points-receipts" | "prove-receipts");
        let list = |key: &str| -> Result<Vec<u64>> {
            f(key)?.split(',').map(|x| Ok(x.parse()?)).collect()
        };
        let vv = list("values")?;
        let rr = if authenticated_receipts { Vec::new() } else { list("blinds")? };
        let receipts =
            if authenticated_receipts { bytes32(f("receipt_ciphertexts")?)? } else { Vec::new() };
        let tt = list("auxiliaries")?;
        if vv.is_empty()
            || vv.len() > 8
            || vv.len() != tt.len()
            || (!authenticated_receipts && vv.len() != rr.len())
            || (authenticated_receipts
                && receipts.len()
                    != vv.len().checked_mul(2).ok_or_else(|| fail("receipt count"))?)
        {
            return Err(fail("selected witness shape"));
        }
        let total = vv
            .iter()
            .try_fold(old, |a, b| a.checked_add(*b))
            .ok_or_else(|| fail("COLLECT overflow"))?;
        let new = total.checked_sub(fee).ok_or_else(|| fail("COLLECT fee"))?;
        let mut pp = vec![
            p,
            oldc,
            oldd,
            Scalar::from(new) * g + rho * h,
            rho * p,
            Scalar::from(old) * g + t * h,
        ];
        let mut ss = vec![s, Scalar::from(old)];
        ss.extend(vv.iter().map(|v| Scalar::from(*v)));
        ss.extend([rho, t]);
        ss.extend(tt.iter().map(|v| Scalar::from(*v)));
        let mut values = vec![
            old,
            maxb.checked_sub(old).ok_or_else(|| fail("old range"))?,
            new,
            maxb.checked_sub(new).ok_or_else(|| fail("new range"))?,
        ];
        let mut blinds = vec![t, -t, rho, -rho];
        for i in 0..vv.len() {
            let v = vv[i];
            let ti = Scalar::from(tt[i]);
            let (c, d) = if authenticated_receipts {
                // Existing COLLECT witnesses contain s and v, never receipt r.
                // Consume the authenticated ciphertext for either source kind.
                let index = i.checked_mul(2).ok_or_else(|| fail("receipt index"))?;
                let c = CompressedRistretto(receipts[index])
                    .decompress()
                    .ok_or_else(|| fail("receipt C"))?;
                let d = CompressedRistretto(receipts[index + 1])
                    .decompress()
                    .ok_or_else(|| fail("receipt D"))?;
                (c, d)
            } else {
                let r = Scalar::from(rr[i]);
                (Scalar::from(v) * g + r * h, r * p)
            };
            pp.extend([c, d, Scalar::from(v) * g + ti * h]);
            values.extend([
                v.checked_sub(1).ok_or_else(|| fail("positive receipt"))?,
                maxv.checked_sub(v).ok_or_else(|| fail("receipt range"))?,
            ]);
            blinds.extend([ti, -ti]);
        }
        (pp, ss, values, blinds, new)
    } else {
        return Err(fail("kind"));
    };
    if args[1] == "points-receipts" && kind != 2 {
        return Err(fail("COLLECT-only mode"));
    }
    if args[1] == "points" || args[1] == "points-receipts" {
        fs::write(&args[3], format!("points={}\nnew_value={new}\n", points(&pp)))?;
        return Ok(());
    }
    if args[1] == "prove-receipts" && kind != 2 {
        return Err(fail("COLLECT-only mode"));
    }
    if args[1] != "prove" && args[1] != "prove-receipts" {
        return Err(fail("mode"));
    }
    let encoded: Vec<_> = pp.iter().map(|x| x.compress().to_bytes()).collect();
    if encoded != bytes32(f("points")?)? {
        return Err(fail("authenticated statement differs from wallet witness"));
    }
    let domain: [u8; 80] = unhex(f("domain")?)?.try_into().map_err(|_| fail("domain"))?;
    let context = unhex(f("context")?)?;
    let ids = bytes32(f("receipt_ids")?)?;
    let size = values.len().checked_next_power_of_two().ok_or_else(|| fail("range size"))?;
    values.resize(size, 0);
    blinds.resize(size, Scalar::ZERO);
    let limits = KernelLimits {
        max_balance: maxb,
        max_value: maxv,
        max_collect: 8,
        max_context_bytes: 1024,
        max_proof_bytes: 4096,
    };
    let proof = prove(
        &Statement {
            kind,
            limits: &limits,
            domain: &domain,
            fee,
            context: &context,
            points: &encoded,
            receipt_ids: &ids,
        },
        &Witness { scalars: &scalars, range_values: &values, range_blindings: &blinds },
    )
    .map_err(|e| fail(&format!("prove {e:?}")))?;
    fs::write(
        &args[3],
        format!(
            "commitments={}\nresponses={}\nrange_proof={}\n",
            proof.commitments.iter().map(|x| hex(x)).collect::<String>(),
            proof.responses.iter().map(|x| hex(x)).collect::<String>(),
            hex(&proof.range_proof)
        ),
    )?;
    Ok(())
}
