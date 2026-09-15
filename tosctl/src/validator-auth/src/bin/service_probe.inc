// Test-only file adapter for independent service trust and current context.
fn service_probe(kind: &str,dir: &str)->Result<(),Error> {
    use tos_validator_auth::{codec::Hash,service_auth::{self,ServiceKey,ServiceTrust,ReceiptWitness}};
    let input=|name:&str|fs::read(std::path::Path::new(dir).join(name)).map_err(|_|Error("fixture-file"));
    let count=input("count")?;
    if count.len()!=1 || count[0]>4 {return Err(Error("fixture-trust"));}
    let mut trust=ServiceTrust::default();
    for i in 0..count[0] {
        let prefix=format!("trust-{i}");let p=decode::<ServicePolicy>(&input(&format!("{prefix}-policy"))?)?;
        let key=input(&format!("{prefix}-key"))?;let id:Hash=input(&format!("{prefix}-id"))?.try_into().map_err(|_|Error("fixture-trust"))?;
        trust.install_trusted(&p,&ServiceKey{id,public_key:key})?;
    }
    let raw=input("value")?;let expected=input("expected")?;let context=input("context")?;
    match kind {
        "permit"=>{
            if context.len()!=13 || context[12]>1 {return Err(Error("fixture-context"));}
            let current=u32::from_be_bytes(context[..4].try_into().map_err(|_|Error("fixture-context"))?);
            let fence=u64::from_be_bytes(context[4..12].try_into().map_err(|_|Error("fixture-context"))?);
            service_auth::verify_permit(&decode(&raw)?,&decode(&expected)?,&trust,current,fence,context[12]==1)
        }
        "receipt"=>{
            struct Witness {sequence:u64,hash:Hash}
            impl ReceiptWitness for Witness {fn contains(&self,n:u64,h:&Hash)->Result<bool,Error>{Ok(n==self.sequence && *h==self.hash)}}
            if context.len()!=40 {return Err(Error("fixture-context"));}
            let sequence=u64::from_be_bytes(context[..8].try_into().map_err(|_|Error("fixture-context"))?);
            let hash=context[8..].try_into().map_err(|_|Error("fixture-context"))?;
            service_auth::verify_receipt(&decode(&raw)?,&decode(&expected)?,&trust,&Witness{sequence,hash})
        }
        "state"=>{let previous=decode(&expected)?;let id=context.try_into().map_err(|_|Error("fixture-context"))?;
            service_auth::observe_request_state(Some(&previous),&decode(&raw)?,&id)
        }
        _=>Err(Error("fixture-kind"))
    }
}
