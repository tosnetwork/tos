//! TEST VECTORS ONLY. Known wallet secrets and balances, never real chain data.
//! C++ owns all TL-B/context/receipt encodings. This tool only builds witnesses
//! and public curve points, then calls the wallet prover and the real kernel ABI.
use std::{collections::BTreeMap, error::Error, fs, path::Path};
use bulletproofs::PedersenGens;
use curve25519_dalek::{RistrettoPoint as Point, Scalar};
use tos_uno_wallet_prover::{prove, Proof, Statement, Witness};
use tos_uno_crypto_prototype::ffi::{uno_crypto_verify_v2, KernelLimits, VerifyRequestV2};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn error(s: &str) -> Box<dyn Error> { std::io::Error::other(s).into() }
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|v| format!("{v:02x}")).collect() }
fn unhex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 { return Err(error("odd hex length")); }
    (0..s.len()).step_by(2).map(|i| Ok(u8::from_str_radix(&s[i..i+2],16)?)).collect()
}
fn words(s: &str) -> Result<Vec<[u8;32]>> {
    let bytes=unhex(s)?;
    if bytes.len()%32 != 0 { return Err(error("partial word")); }
    bytes.chunks_exact(32).map(|b| b.try_into().map_err(|_| error("word"))).collect()
}
fn encoded(points: &[Point]) -> Vec<[u8;32]> { points.iter().map(|p| p.compress().to_bytes()).collect() }
fn words_hex(words: &[[u8;32]]) -> String { words.iter().map(|p| hex(p)).collect() }
fn read(path: &Path) -> Result<BTreeMap<String,String>> {
    let mut values=BTreeMap::new();
    for line in fs::read_to_string(path)?.lines() {
        if line.starts_with('#') || line.is_empty() { continue; }
        let (k,v)=line.split_once('=').ok_or_else(||error("expected key=value"))?;
        if values.insert(k.into(),v.into()).is_some() { return Err(error("duplicate key")); }
    }
    Ok(values)
}
fn field<'a>(m: &'a BTreeMap<String,String>, key: &str) -> Result<&'a str> {
    m.get(key).map(String::as_str).ok_or_else(||error(&format!("missing {key}")))
}
struct Fixture {
    kind:u32, fee:u64, points:Vec<[u8;32]>, scalars:Vec<Scalar>, values:Vec<u64>, blinds:Vec<Scalar>,
    public:BTreeMap<String,String>,
}
fn fixture(scenario:&str, fee:u64, order:&[usize], limits:&KernelLimits) -> Result<Fixture> {
    let k=match scenario { "send"=>0, "collect1"=>1, "collect3"=>3, _=>return Err(error("unknown scenario")) };
    if order.len()!=k { return Err(error("selection order length")); }
    let pc=PedersenGens::default(); let g=pc.B; let h=pc.B_blinding;
    let alice_secret=Scalar::from(101u64); let bob_secret=Scalar::from(223u64);
    let pa=alice_secret.invert()*h; let pb=bob_secret.invert()*h;
    let alice_old=50_000u64; let bob_old=3_107u64;
    let ar=Scalar::from(23u64); let br=Scalar::from(37u64);
    let ac=Scalar::from(alice_old)*g+ar*h; let ad=ar*pa;
    let bc=Scalar::from(bob_old)*g+br*h; let bd=br*pb;
    let amounts=[137u64,251,89,433]; let openings=[47u64,53,61,73]; let aux=[83u64,97,107,127];
    let mut receipts=Vec::new();
    for i in 0..4 { let r=Scalar::from(openings[i]); receipts.push((Scalar::from(amounts[i])*g+r*h,r*pb,Scalar::from(amounts[i])*g+Scalar::from(aux[i])*h)); }
    let rho=Scalar::from(149u64); let t=Scalar::from(163u64);
    let mut public=BTreeMap::new();
    for (key,point) in [("alice_p",pa),("alice_c",ac),("alice_d",ad),("bob_p",pb),("bob_c",bc),("bob_d",bd)] { public.insert(key.into(),hex(&point.compress().to_bytes())); }
    for (i,(c,d,j)) in receipts.iter().enumerate() { for (label,p) in [("c",c),("d",d),("j",j)] { public.insert(format!("pending_{i}_{label}"),hex(&p.compress().to_bytes())); } }
    public.insert("scenario".into(),scenario.into()); public.insert("fee".into(),fee.to_string());
    public.insert("alice_old".into(),alice_old.to_string()); public.insert("bob_old".into(),bob_old.to_string());
    let (points,scalars,mut values,mut blinds,new_balance)=if k==0 {
        let v=137u64; let r=Scalar::from(179u64);
        let new=alice_old.checked_sub(v).and_then(|x|x.checked_sub(fee)).ok_or_else(||error("unfunded SEND"))?;
        let points=vec![pa,pb,ac,ad,Scalar::from(new)*g+rho*h,rho*pa,Scalar::from(v)*g+r*h,r*pa,r*pb,Scalar::from(alice_old)*g+t*h];
        (points,vec![alice_secret,Scalar::from(new),Scalar::from(v),r,rho,t],
         vec![alice_old,limits.max_balance.checked_sub(alice_old).ok_or_else(||error("old bound"))?,new,limits.max_balance.checked_sub(new).ok_or_else(||error("new bound"))?,v.checked_sub(1).ok_or_else(||error("positive"))?,limits.max_value.checked_sub(v).ok_or_else(||error("value bound"))?],
         vec![t,-t,rho,-rho,r,-r],new)
    } else {
        let mut seen=[false;4];
        for &i in order { if i>=4 || seen[i] {return Err(error("invalid selected index"));} seen[i]=true; }
        let total=order.iter().try_fold(bob_old,|sum,&i|sum.checked_add(amounts[i])).ok_or_else(||error("collect overflow"))?;
        let new=total.checked_sub(fee).ok_or_else(||error("unfunded COLLECT"))?;
        let mut points=vec![pb,bc,bd,Scalar::from(new)*g+rho*h,rho*pb,Scalar::from(bob_old)*g+t*h];
        let mut scalars=vec![bob_secret,Scalar::from(bob_old)];
        scalars.extend(order.iter().map(|&i|Scalar::from(amounts[i]))); scalars.extend([rho,t]);
        scalars.extend(order.iter().map(|&i|Scalar::from(aux[i])));
        let mut values=vec![bob_old,limits.max_balance.checked_sub(bob_old).ok_or_else(||error("old bound"))?,new,limits.max_balance.checked_sub(new).ok_or_else(||error("new bound"))?];
        let mut blinds=vec![t,-t,rho,-rho];
        for &i in order { let (c,d,j)=receipts[i]; points.extend([c,d,j]); values.extend([amounts[i].checked_sub(1).ok_or_else(||error("positive"))?,limits.max_value.checked_sub(amounts[i]).ok_or_else(||error("value bound"))?]);let ti=Scalar::from(aux[i]);blinds.extend([ti,-ti]); }
        (points,scalars,values,blinds,new)
    };
    let n=values.len().checked_next_power_of_two().ok_or_else(||error("range size"))?;
    values.resize(n,0); blinds.resize(n,Scalar::ZERO);
    let points=encoded(&points);
    public.insert("points".into(),words_hex(&points)); public.insert("new_balance".into(),new_balance.to_string());
    Ok(Fixture{kind:if k==0 {1}else{2},fee,points,scalars,values,blinds,public})
}
fn main() -> Result<()> {
    let args:Vec<_>=std::env::args().collect();
    if args.len()!=5 { return Err(error("usage: m3-vectors prepare SCENARIO FEE OUT | prove SCENARIO REQUEST OUT")); }
    let scenario=&args[2];
    if args[1]=="prepare" {
        let order:Vec<_>=match scenario.as_str(){"send"=>vec![],"collect1"=>vec![0],"collect3"=>vec![0,1,2],_=>return Err(error("scenario"))};
        let limits=KernelLimits{max_balance:1_000_000,max_value:10_000,max_collect:8,max_context_bytes:1024,max_proof_bytes:4096};
        let f=fixture(scenario,args[3].parse()?,&order,&limits)?;
        let mut text=String::from("# TEST VECTOR PUBLIC POINTS, not real chain data.\n");
        for (k,v) in f.public { text+=&format!("{k}={v}\n"); }
        fs::write(&args[4],text)?;
        return Ok(());
    }
    if args[1]!="prove" && args[1]!="verify" {return Err(error("unknown mode"));}
    let request=read(Path::new(&args[3]))?;
    let limits=KernelLimits{max_balance:field(&request,"max_balance")?.parse()?,max_value:field(&request,"max_value")?.parse()?,max_collect:field(&request,"max_collect")?.parse()?,max_context_bytes:field(&request,"max_context_bytes")?.parse()?,max_proof_bytes:field(&request,"max_proof_bytes")?.parse()?};
    let order=field(&request,"order")?.split(',').filter(|s|!s.is_empty()).map(str::parse).collect::<std::result::Result<Vec<usize>,_>>()?;
    let f=fixture(scenario,field(&request,"fee")?.parse()?,&order,&limits)?;
    let context=unhex(field(&request,"context")?)?;
    if context.len()!=427 {return Err(error("M3 context must be exactly 427 bytes"));}
    let domain:[u8;80]=unhex(field(&request,"domain")?)?.try_into().map_err(|_|error("domain width"))?;
    let points=words(field(&request,"points")?)?; let ids=words(field(&request,"receipt_ids")?)?;
    if points!=f.points || ids.len()!=order.len(){return Err(error("C++ and wallet statement mismatch"));}
    let proof=if args[1]=="prove" { prove(&Statement{kind:f.kind,limits:&limits,domain:&domain,fee:f.fee,context:&context,points:&points,receipt_ids:&ids},
                    &Witness{scalars:&f.scalars,range_values:&f.values,range_blindings:&f.blinds}).map_err(|e|error(&format!("prove: {e:?}")))? } else { Proof{commitments:words(field(&request,"commitments")?)?,responses:words(field(&request,"responses")?)?,range_proof:unhex(field(&request,"range_proof")?)?} };
    let r=VerifyRequestV2{abi_version:2,relation:f.kind,limits,domain,fee:f.fee,context:context.as_ptr(),context_bytes:context.len(),points:points.as_ptr(),point_count:points.len(),receipt_ids:ids.as_ptr(),receipt_count:ids.len(),commitments:proof.commitments.as_ptr(),commitment_count:proof.commitments.len(),responses:proof.responses.as_ptr(),response_count:proof.responses.len(),proof:proof.range_proof.as_ptr(),proof_bytes:proof.range_proof.len()};
    // All pointers refer to live owned vectors for the entire synchronous call.
    let status=unsafe{uno_crypto_verify_v2(&r)};
    if status!=0 {return Err(error(&format!("real ABI rejected proof: {status}")));}
    let mut changed=context.clone(); changed[0]^=1;
    let bad=VerifyRequestV2{context:changed.as_ptr(),..r};
    if unsafe{uno_crypto_verify_v2(&bad)}==0 {return Err(error("real ABI accepted changed context"));}
    fs::write(&args[4],format!("# TEST VECTOR authorization. Fresh wallet randomness; verified by uno_crypto_verify_v2.\ncommitments={}\nresponses={}\nrange_proof={}\nabi_status={status}\n",words_hex(&proof.commitments),words_hex(&proof.responses),hex(&proof.range_proof)))?;
    println!("{scenario}: uno_crypto_verify_v2={status}, new_balance={}",field(&f.public,"new_balance")?);
    Ok(())
}
