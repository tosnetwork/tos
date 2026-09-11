
use crate::{withdrawal_statement::{WithdrawalAmounts, WithdrawalStatement}, relation,
    ffi::{KernelLimits, UNO_RELATION_SEND, AbiStatus}};
use bulletproofs::PedersenGens;
use curve25519_dalek::{Scalar, RistrettoPoint, traits::Identity, ristretto::CompressedRistretto};
fn limits()->KernelLimits { KernelLimits { max_balance:10000, max_value:1000,
    max_collect:8, max_context_bytes:4096, max_proof_bytes:4096 } }
fn inputs()->[[u8;32];6] { let g=PedersenGens::default().B;
    [2u64,3,4,5,6,7].map(|n|(Scalar::from(n)*g).compress().to_bytes()) }
fn amounts()->WithdrawalAmounts { WithdrawalAmounts {
    principal:100, outward_fee:17, return_reserve:23, operation_fee:11 } }
#[test]
fn independent_d64_matrix_every_coefficient_target_and_range() {
    let l=limits(); let s=WithdrawalStatement::new(&l,[1;80],[2;32],[3;32],amounts(),b"review",inputs()).unwrap();
    let r=relation::prepare(UNO_RELATION_SEND,&l,s.domain(),s.fee(),s.context(),s.points(),&[]).unwrap();
    let p:Vec<_>=s.points().iter().map(|x|CompressedRistretto(*x).decompress().unwrap()).collect();
    let pc=PedersenGens::default();let g=pc.B;let h=pc.B_blinding;let o=RistrettoPoint::identity();
    // Independently transcribed dense columns: s_A, new_balance, v, r, rho, t.
    let expected=vec![vec![p[0],o,o,o,o,o], vec![p[3],g,g,o,o,o],
        vec![o,g,g,o,o,h],vec![o,g,o,o,h,o],vec![o,o,o,o,p[0],o],
        vec![o,o,g,h,o,o],vec![o,o,o,p[0],o,o],vec![o,o,o,p[1],o,o]];
    assert_eq!(r.rows,expected,"every row and witness column");
    let fg=Scalar::from(11u64)*g;
    assert_eq!(r.targets,vec![h,p[2]-fg,p[9]-fg,p[4],p[5],p[6],p[7],p[8]]);
    let bm=Scalar::from(l.max_balance)*g;let vm=Scalar::from(l.max_value)*g;
    let expected_ranges=[p[9],bm-p[9],p[4],bm-p[4],p[6]-g,vm-p[6],o,o];
    assert_eq!(r.ranges,expected_ranges.map(|p|p.compress()));
}
#[test]
fn independent_d64_points_total_and_fee_separate() {
    let l=limits();let a=amounts();let q=inputs();
    let s=WithdrawalStatement::new(&l,[1;80],[2;32],[3;32],a,b"review",q).unwrap();
    assert_eq!(a.total(),Ok(140));assert_eq!(s.fee(),11);
    assert_eq!(s.points()[0],q[0]);assert_eq!(s.points()[1],q[0]);
    assert_eq!(s.points()[7],s.points()[8]);
    let r=crate::withdrawal_statement::public_opening(&[1;80],&[2;32],&[3;32],&q[0],140).unwrap();
    let pc=PedersenGens::default();
    assert_eq!(s.points()[6],(Scalar::from(140u64)*pc.B+r*pc.B_blinding).compress().to_bytes());
    assert_eq!(s.points()[7],(r*CompressedRistretto(q[0]).decompress().unwrap()).compress().to_bytes());
    let arbitrary=WithdrawalAmounts{operation_fee:19,..a};
    let changed=WithdrawalStatement::new(&l,[1;80],[2;32],[3;32],arbitrary,b"review",q).unwrap();
    assert_eq!(changed.fee(),19);assert_eq!(changed.points(),s.points());
    assert_ne!(changed.context(),s.context()); // bound, not authenticated by this constructor
    for a in [WithdrawalAmounts{principal:u64::MAX,outward_fee:1,return_reserve:0,operation_fee:0},
        WithdrawalAmounts{principal:u64::MAX-1,outward_fee:1,return_reserve:1,operation_fee:0}] {
        assert_eq!(a.total(),Err(AbiStatus::UNO_CRYPTO_DECODE));
        assert!(WithdrawalStatement::new(&l,[1;80],[2;32],[3;32],a,b"review",q).is_err());
    }
}
