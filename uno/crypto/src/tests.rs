use super::{ffi::*, relation::*, verify_relation};
use crate::ffi::AbiStatus::*;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{Scalar as S, RistrettoPoint as P, traits::VartimeMultiscalarMul};
use rand::{SeedableRng, rngs::StdRng};

pub(crate) struct Fixture {
    kind: u32, limits: KernelLimits, context: Vec<u8>, points: Vec<[u8;32]>, ids: Vec<[u8;32]>,
    ts: Vec<[u8;32]>, zs: Vec<[u8;32]>, proof: Vec<u8>,
}

impl Fixture {
    fn verify(&self) -> Result<(), AbiStatus> {
        verify_relation(self.kind, &self.limits, &self.context, &self.points, &self.ids, &self.ts, &self.zs, &self.proof)
    }
    fn request(&self) -> VerifyRequest {
        VerifyRequest { abi_version: UNO_CRYPTO_ABI_VERSION, relation: self.kind, limits: self.limits,
            context: self.context.as_ptr(), context_bytes: self.context.len(), points: self.points.as_ptr(),
            point_count: self.points.len(), receipt_ids: self.ids.as_ptr(), receipt_count: self.ids.len(),
            commitments: self.ts.as_ptr(), commitment_count: self.ts.len(), responses: self.zs.as_ptr(),
            response_count: self.zs.len(), proof: self.proof.as_ptr(), proof_bytes: self.proof.len() }
    }
}

fn fixture(k: usize) -> Fixture {
    let pc = PedersenGens::default(); let g = pc.B; let h = pc.B_blinding;
    let s = S::from(11u64); let p = s.invert()*h; let rho = S::from(19u64);
    let blind = S::from(23u64); let old_r = S::from(29u64);
    let b = 1000u64; let bmax = 1_000_000u64; let vmax = 10000u64;
    let ca = S::from(b)*g+old_r*h; let da=old_r*p;
    let (points, witnesses, mut values, mut blinds) = if k == 0 {
        let v=7u64; let new=b.checked_sub(v).expect("funded transfer");
        let r=S::from(17u64); let pb=S::from(13u64).invert()*h;
        (vec![p,pb,ca,da,S::from(new)*g+rho*h,rho*p,S::from(v)*g+r*h,r*p,r*pb,S::from(b)*g+blind*h],
            vec![s,S::from(new),S::from(v),r,rho,blind],
            vec![b,bmax.checked_sub(b).expect("old bound"),new,bmax.checked_sub(new).expect("new bound"),
                v.checked_sub(1).expect("positive transfer"),vmax.checked_sub(v).expect("transfer bound")],
            vec![blind,-blind,rho,-rho,r,-r])
    } else {
        let mut amounts=Vec::new(); let mut cs=Vec::new(); let mut ds=Vec::new(); let mut js=Vec::new();
        let mut new=b; let mut receipt_blinds=Vec::new();
        for i in 0..k {
            let offset=u64::try_from(i).expect("fixture index");
            let v=7u64.checked_add(offset).expect("fixture amount"); new=new.checked_add(v).expect("fixture sum");
            let r=S::from(31u64.checked_add(offset).expect("opening"));
            let ti=S::from(101u64.checked_add(offset).expect("auxiliary opening"));
            amounts.push(v); cs.push(S::from(v)*g+r*h); ds.push(r*p); js.push(S::from(v)*g+ti*h); receipt_blinds.push(ti);
        }
        let mut points=vec![p,ca,da,S::from(new)*g+rho*h,rho*p,S::from(b)*g+blind*h];
        for i in 0..k { points.extend([cs[i],ds[i],js[i]]); }
        let mut witnesses=vec![s,S::from(b)]; witnesses.extend(amounts.iter().copied().map(S::from));
        witnesses.extend([rho,blind]); witnesses.extend(&receipt_blinds);
        let mut values=vec![b,bmax.checked_sub(b).expect("old bound"),new,bmax.checked_sub(new).expect("new bound")];
        let mut blinds=vec![blind,-blind,rho,-rho];
        for (v, ti) in amounts.iter().zip(receipt_blinds) {
            values.extend([v.checked_sub(1).expect("positive receipt"),vmax.checked_sub(*v).expect("receipt bound")]);
            blinds.extend([ti,-ti]);
        }
        (points,witnesses,values,blinds)
    };
    let limits=KernelLimits { max_balance:bmax,max_value:vmax,max_collect:8,max_context_bytes:1024,max_proof_bytes:4096 };
    let ids=(0..k).map(|i| {let mut id=[0;32];id[0]=u8::try_from(i).expect("fixture receipt");id}).collect();
    let mut f=Fixture {kind:if k==0 {UNO_RELATION_SEND} else {UNO_RELATION_COLLECT},limits,
        context:b"test network/instance/account/nonce/policy; NOT production context".to_vec(),
        points:points.iter().map(P::compress).map(|p|p.to_bytes()).collect(),ids,ts:vec![],zs:vec![],proof:vec![]};
    let relation=prepare(f.kind,&f.limits,&f.context,&f.points,&f.ids).expect("fixture statement");
    for (row,y) in relation.rows.iter().zip(&relation.targets) {
        assert_eq!(P::vartime_multiscalar_mul(&witnesses,row),*y,"known amount witness equation");
    }
    let mut rng=StdRng::seed_from_u64(20260907u64.checked_add(u64::try_from(k).expect("k")).expect("seed"));
    let masks:Vec<_>=witnesses.iter().map(|_|S::random(&mut rng)).collect();
    f.ts=relation.rows.iter().map(|row|P::vartime_multiscalar_mul(&masks,row).compress().to_bytes()).collect();
    let (_,e)=sigma_transcript(relation.transcript.clone(),&f.ts);
    f.zs=masks.iter().zip(&witnesses).map(|(mask,w)| (mask+e*w).to_bytes()).collect();
    let m=values.len().checked_next_power_of_two().expect("range padding");
    values.resize(m,0);blinds.resize(m,S::ZERO);
    let (proof,commitments)=RangeProof::prove_multiple_with_rng(&BulletproofGens::new(64,m),&pc,
        &mut range_transcript(relation.transcript.clone()),&values,&blinds,64,&mut rng).expect("reference prover");
    assert_eq!(commitments,relation.ranges,"verifier-derived commitments bind the actual amounts");
    proof.verify_multiple_with_rng(&BulletproofGens::new(64,m),&pc,&mut range_transcript(relation.transcript),
        &commitments,64,&mut rng).expect("reference randomized verifier agrees on valid proof");
    f.proof=proof.to_bytes(); f
}

#[test]
fn full_send_and_collect_all_candidate_sizes() {
    for k in 0..=8 {
        let f=fixture(k); assert_eq!(f.verify(),Ok(()),"positive relation k={k}");
        assert_eq!(unsafe {uno_crypto_verify_v1(&f.request())},UNO_CRYPTO_OK as u32,"FFI k={k}");
        let (_,equations,witnesses,m)=shapes(f.kind,k).expect("shape");
        assert_eq!((f.ts.len(),f.zs.len(),f.proof.len()),(equations,witnesses,range_size(m).expect("size")));
    }
}

#[test]
fn every_public_field_and_proof_component_is_bound() {
    for k in [0,1,8] {
        let mut f=fixture(k); assert_eq!(f.verify(),Ok(()));
        f.context[0]^=1; assert!(f.verify().is_err(),"context k={k}"); f.context[0]^=1;
        for i in 0..f.points.len() {
            let old=f.points[i]; f.points[i]=(CompressedPoint(old)+PedersenGens::default().B).compress().to_bytes();
            assert!(f.verify().is_err(),"public point {i}, k={k}"); f.points[i]=old;
        }
        for i in 0..f.ts.len() {
            let old=f.ts[i];f.ts[i]=(CompressedPoint(old)+PedersenGens::default().B).compress().to_bytes();
            assert!(f.verify().is_err(),"AND commitment {i}, k={k}");f.ts[i]=old;
        }
        for i in 0..f.zs.len() {
            let old=f.zs[i]; f.zs[i]=(S::from_bytes_mod_order(old)+S::ONE).to_bytes();
            assert_eq!(f.verify(),Err(AbiStatus::UNO_CRYPTO_VERIFY),"shared response {i}, k={k}"); f.zs[i]=old;
        }
        for i in (0..f.proof.len()).step_by(32) {
            f.proof[i]^=1;assert!(f.verify().is_err(),"range component {i}, k={k}");f.proof[i]^=1;
        }
        if k>0 { f.ids[0][31]^=1;assert!(f.verify().is_err(),"receipt identity"); }
    }
}

#[allow(non_snake_case)]
fn CompressedPoint(bytes:[u8;32])->P {
    curve25519_dalek::ristretto::CompressedRistretto(bytes).decompress().expect("valid fixture point")
}

#[test]
fn policy_and_encoding_boundaries() {
    let mut f=fixture(8); f.limits.max_collect=7; assert_eq!(f.verify(),Err(AbiStatus::UNO_CRYPTO_DECODE));
    f.limits.max_collect=8; assert_eq!(f.verify(),Ok(()));
    f.ids[1]=f.ids[0]; assert_eq!(f.verify(),Err(AbiStatus::UNO_CRYPTO_DECODE));
    let mut f=fixture(0); f.limits.max_value=0; assert_eq!(f.verify(),Err(AbiStatus::UNO_CRYPTO_ARGUMENTS));
    f.limits.max_value=10000; f.proof.push(0);assert_eq!(f.verify(),Err(AbiStatus::UNO_CRYPTO_DECODE));
    f.proof.pop(); f.zs[0]=[255;32];assert_eq!(f.verify(),Err(AbiStatus::UNO_CRYPTO_DECODE));
    f.zs.pop();assert_eq!(f.verify(),Err(AbiStatus::UNO_CRYPTO_DECODE));
    assert!(shapes(UNO_RELATION_COLLECT,usize::MAX).is_err());
    assert!(range_size(usize::MAX).is_err());
}

#[test]
fn admission_predicates_have_independent_witnesses() {
    let f=fixture(1);
    let check=|limits:&KernelLimits,context:&[u8],points:&[[u8;32]]| {
        prepare(f.kind,limits,context,points,&f.ids).map(|_|())
    };
    assert_eq!(check(&f.limits,&f.context,&f.points),Ok(()));
    let mut invalid=Vec::new();
    let mut p=f.limits;p.max_balance=0;invalid.push(p);
    let mut p=f.limits;p.max_value=0;invalid.push(p);
    let mut p=f.limits;p.max_value=p.max_balance.checked_add(1).expect("test bound");invalid.push(p);
    let mut p=f.limits;p.max_collect=0;invalid.push(p);
    let mut p=f.limits;p.max_context_bytes=0;invalid.push(p);
    let mut p=f.limits;p.max_proof_bytes=0;invalid.push(p);
    for (i,p) in invalid.iter().enumerate() {
        assert_eq!(check(p,&f.context,&f.points),Err(UNO_CRYPTO_ARGUMENTS),"policy {i}");
        let mut request=f.request();request.limits=*p;
        assert_eq!(unsafe{uno_crypto_verify_v1(&request)},UNO_CRYPTO_ARGUMENTS as u32,"FFI policy {i}");
    }
    assert_eq!(check(&f.limits,&[],&f.points),Err(UNO_CRYPTO_DECODE));
    let mut p=f.limits;p.max_context_bytes=f.context.len().checked_sub(1).expect("nonempty context");
    assert_eq!(check(&p,&f.context,&f.points),Err(UNO_CRYPTO_DECODE));
    let mut p=f.limits;p.max_proof_bytes=f.proof.len().checked_sub(1).expect("nonempty proof");
    assert_eq!(check(&p,&f.context,&f.points),Err(UNO_CRYPTO_DECODE));
    p.max_proof_bytes=f.proof.len();assert_eq!(check(&p,&f.context,&f.points),Ok(()));
    assert!(shapes(99,0).is_err());
    assert!(shapes(UNO_RELATION_SEND,1).is_err());
    assert!(shapes(UNO_RELATION_COLLECT,0).is_err());
    let aligned=&f.limits as *const KernelLimits as usize;
    let misaligned=aligned.checked_add(1).expect("test pointer");
    assert!(!bounded_span(misaligned as *const VerifyRequest,1));
}

#[test]
fn nonidentity_handles_are_checked_before_proof_verification() {
    for k in [0,1,8] {
        let f=fixture(k);
        let indices:Vec<usize>=if k==0 {vec![0,1,5,7,8]} else {
            let mut v=vec![0,4];
            for i in 0usize..k {v.push(i.checked_mul(3).and_then(|x|x.checked_add(7)).expect("receipt index"));}
            v
        };
        assert!(prepare(f.kind,&f.limits,&f.context,&f.points,&f.ids).is_ok());
        for index in indices {
            let mut points=f.points.clone();points[index]=[0;32];
            assert!(matches!(prepare(f.kind,&f.limits,&f.context,&points,&f.ids),Err(UNO_CRYPTO_DECODE)),
                "identity handle k={k}, index={index}");
        }
    }
}

#[test]
fn each_sigma_equation_has_an_independent_negative_witness() {
    for k in 0..=8 {
        let f=fixture(k);
        let mut relation=prepare(f.kind,&f.limits,&f.context,&f.points,&f.ids).expect("statement");
        let ts:Vec<_>=f.ts.iter().copied().map(CompressedPoint).collect();
        let zs:Vec<_>=f.zs.iter().copied().map(S::from_bytes_mod_order).collect();
        let (_,e)=sigma_transcript(relation.transcript.clone(),&f.ts);
        assert_eq!(check_sigma(&relation.rows,&relation.targets,&ts,&zs,e),Ok(()));
        for index in 0..relation.targets.len() {
            relation.targets[index]+=PedersenGens::default().B;
            assert_eq!(check_sigma(&relation.rows,&relation.targets,&ts,&zs,e),Err(AbiStatus::UNO_CRYPTO_VERIFY),
                "independent residual k={k}, equation={index}");
            relation.targets[index]-=PedersenGens::default().B;
        }
        // The ABI has one response per witness, never per equation/witness pair.
        let mut extra=f.zs.clone();extra.extend(&f.zs);
        assert_eq!(verify_relation(f.kind,&f.limits,&f.context,&f.points,&f.ids,&f.ts,&extra,&f.proof),
            Err(AbiStatus::UNO_CRYPTO_DECODE));
    }
}

#[test]
fn borrowed_abi_layout_spans_and_panic_recovery() {
    assert_eq!(std::mem::size_of::<KernelLimits>(),40);
    assert_eq!(std::mem::size_of::<VerifyRequest>(),144);
    assert_eq!(std::mem::offset_of!(VerifyRequest,context),48);
    assert!(!bounded_span(usize::MAX as *const u8,1));
    assert!(!bounded_span(&0u64,usize::MAX));
    INJECT_UNWIND.with(|flag|flag.set(true));
    assert_eq!(unsafe{uno_crypto_verify_v1(std::ptr::null())},UNO_CRYPTO_PANIC as u32);
    assert_eq!(unsafe{uno_crypto_verify_v1(std::ptr::null())},UNO_CRYPTO_ARGUMENTS as u32);
    let f=fixture(0);let mut request=f.request();request.abi_version=0;
    assert_eq!(unsafe{uno_crypto_verify_v1(&request)},UNO_CRYPTO_ARGUMENTS as u32);
}

#[test]
fn concurrent_real_ffi_verification() {
    let send=fixture(0);let collect=fixture(8);
    std::thread::scope(|scope| {
        for f in [&send,&collect,&send,&collect] {scope.spawn(move|| {
            assert_eq!(unsafe{uno_crypto_verify_v1(&f.request())},UNO_CRYPTO_OK as u32);
        });}
    });
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b|format!("{b:02x}")).collect()
}

#[test]
fn cross_language_vectors_are_frozen() {
    let mut encoded=String::new();
    for k in 0..=8 {
        let f=fixture(k);
        encoded.push_str(&format!("{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",f.kind,
            f.limits.max_balance,f.limits.max_value,f.limits.max_collect,hex(&f.context),
            hex(&f.points.concat()),hex(&f.ids.concat()),hex(&f.ts.concat()),hex(&f.zs.concat()),hex(&f.proof)));
    }
    if let Some(path)=std::env::var_os("UNO_KERNEL_VECTOR_OUT") {
        std::fs::OpenOptions::new().write(true).create_new(true).open(path)
            .and_then(|mut file|std::io::Write::write_all(&mut file,encoded.as_bytes())).expect("export new vector artifact");
    }
    let expected=include_str!("../fixtures/balance-kernel-v1.txt");
    let offset=encoded.bytes().zip(expected.bytes()).position(|(a,b)|a!=b)
        .unwrap_or(encoded.len().min(expected.len()));
    let row=encoded.as_bytes()[..offset].iter().filter(|b|**b==b'\n').count();
    assert!(encoded==expected,"frozen cross-language vectors differ: offset {offset}, row {row}, expected {} bytes, generated {} bytes",
        expected.len(),encoded.len());
}

#[test]
fn range_residuals_cannot_cancel() {
    use curve25519_dalek::traits::Identity;
    let g=PedersenGens::default().B;let o=P::identity();
    assert!(bulletproofs::independent_residuals_zero(o,o));
    assert!(!bulletproofs::independent_residuals_zero(g,o));
    assert!(!bulletproofs::independent_residuals_zero(o,g));
    assert!(!bulletproofs::independent_residuals_zero(g,-g));
}

#[test]
fn transcript_matches_independent_c_reference() {
    let mut t=merlin::Transcript::new(b"kernel-transcript-reference-v1");
    let message:Vec<_>=(0..1024).map(|i|(i%256) as u8).collect();
    t.append_message(b"message",&message);
    t.append_u64(b"counter",0x0102030405060708);
    let mut first=[0;64];let mut second=[0;64];
    t.challenge_bytes(b"first",&mut first);
    t.append_message(b"response",&first);
    t.challenge_bytes(b"second",&mut second);
    assert_eq!(hex(&first),"931674cbeb23ad6f1092a28c2673adedb1f573428d8e8d2a856c1d25e5c64753053eed6a9e51daab08b09a34aaa9a9313820cd34e45c4e014ddb96d9ba488d9a");
    assert_eq!(hex(&second),"726559a787b0714110ed5bd86e0976dbd03e8cb621111f844a98c80fba10ac1ebadb0f00be585a872cde01839999b597ae140bd6b964428a354d204bec162c51");
}
