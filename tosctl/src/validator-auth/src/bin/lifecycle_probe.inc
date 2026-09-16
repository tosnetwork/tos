// Controlled authority callbacks exercise replay; native proof tests are separate.
fn lifecycle_probe(args:&[String])->Result<(),Error> {
    use std::collections::BTreeMap;
    use tos_validator_auth::{codec::Hash,crypto::object_id,lifecycle::{self,KeyHistory,KeySlot,LifecycleAuthority}};
    struct History(BTreeMap<Hash,Key>);
    impl KeyHistory for History {
        fn find(&self,id:&Hash)->Result<Key,Error>{self.0.get(id).cloned().ok_or(Error("unknown-key"))}
        fn latest_epoch(&self,identity:&Hash,slot:KeySlot)->Result<u64,Error>{Ok(self.0.values().filter(|k|k.identity==*identity && (k.role,k.suite,k.parameters)==slot).map(|k|k.epoch).max().unwrap_or(0))}
        fn ever_registered(&self,identity:&Hash)->Result<bool,Error>{Ok(self.0.values().any(|k|k.identity==*identity))}
    }
    struct Authority<'a>(&'a str);
    impl LifecycleAuthority for Authority<'_> {
        fn owner(&self,_:&OwnerAuth,_:&Update,_:&Identity)->Result<bool,Error>{Ok(self.0!="owner")}
        fn possession(&self,_:&PossessionAuth,_:&Update,_:&Key)->Result<bool,Error>{Ok(self.0!="possession")}
        fn administration(&self,_:&IdentityAuth,_:&Update,_:&Identity,_:u32)->Result<bool,Error>{Ok(self.0!="administration")}
        // Global operations are outside what this probe authorizes. Refusing
        // explicitly keeps a fixture from silently admitting an operation it
        // was never built to reason about.
        fn governance(&self,_:&Update,_:&Authorizations,_:&Hash,_:u32)->Result<Anchor,Error>{Err(Error("fixture-governance"))}
    }
    let mut archive=History(BTreeMap::new());
    for entry in fs::read_dir(&args[3]).map_err(|_|Error("fixture-archive"))? {
        let key=decode::<Key>(&fs::read(entry.map_err(|_|Error("fixture-archive"))?.path()).map_err(|_|Error("fixture-archive"))?)?;
        archive.0.insert(object_id("key",&key)?,key);
    }
    let state=decode::<Identity>(&fs::read(&args[2]).map_err(|_|Error("fixture-file"))?)?;
    if args.len()==7 && args[1]=="select" {
        let at=args[4].parse().map_err(|_|Error("arguments"))?;
        let role=args[5].parse().map_err(|_|Error("arguments"))?;
        let keys=lifecycle::select_identity_keys(&state,&archive,at,&[(role,1,1)])?;
        let key=keys.first().ok_or(Error("fixture-keys"))?;
        return fs::write(&args[6],encode(key)?).map_err(|_|Error("fixture-output"));
    }
    let (result,output)=if args.len()==7 && args[1]=="due" {
        (lifecycle::apply_due_transitions(&state,&archive,args[4].parse().map_err(|_|Error("arguments"))?,args[5].parse().map_err(|_|Error("arguments"))?)?,&args[6])
    } else if args.len()==9 && args[1]=="apply" {
        let update=decode(&fs::read(&args[4]).map_err(|_|Error("fixture-file"))?)?;
        let evidence=decode(&fs::read(&args[5]).map_err(|_|Error("fixture-file"))?)?;
        (lifecycle::apply_identity_update(&state,&archive,&update,&evidence,args[6].parse().map_err(|_|Error("arguments"))?,&Authority(&args[8]))?.identity,&args[7])
    } else {return Err(Error("arguments"));};
    fs::write(output,encode(&result)?).map_err(|_|Error("fixture-output"))
}
