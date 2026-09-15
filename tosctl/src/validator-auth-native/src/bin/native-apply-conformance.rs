use std::{env, fs, path::Path};
use tos_validator_auth::{
    codec::{decode, Error},
    context::ChainContext,
    transfer::ObjectReader,
    types::*,
    verify::RegistrySnapshot,
};
use tos_validator_auth_native::{
    cells,
    native_apply::{apply_native_identity_block, FinalizedAnchorSource, NativeIdentityContext},
    native_registry::{NativeRegistry, NativeRegistryBlock},
    registry::{RegistryState, StateReadBudget},
};
struct History {
    anchor: Anchor,
    available: bool,
}
impl FinalizedAnchorSource for History {
    fn finalized_anchor(&self, at: u32) -> Result<Anchor, Error> {
        if !self.available || at != self.anchor.seqno {
            return Err(Error("finalized-anchor-unavailable"));
        }
        Ok(self.anchor.clone())
    }
}
fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    let transactions = args.get(1).is_some_and(|x| x == "--transactions");
    let persistent = transactions || args.get(1).is_some_and(|x| x == "--persistent");
    if args.len() != (if persistent { 3 } else { 2 }) {
        return Err("arguments".into());
    }
    let root = Path::new(&args[if persistent { 2 } else { 1 }]);
    let count: usize = fs::read_to_string(root.join("complete"))
        .map_err(|e| e.to_string())?
        .trim()
        .parse()
        .map_err(|_| "complete")?;
    if count < 30 {
        return Err("complete-corpus".into());
    }
    for i in 0..count {
        let folder = root.join(i.to_string());
        let read = |name: &str| fs::read(folder.join(name)).map_err(|_| Error("fixture-input"));
        let meta = fs::read_to_string(folder.join("case")).map_err(|e| e.to_string())?;
        let f: Vec<_> = meta.split_whitespace().collect();
        if f.len() != 6 {
            return Err("case-metadata".into());
        }
        let n = |index: usize| f[index].parse::<u32>().map_err(|_| Error("metadata-number"));
        let result = (|| -> Result<(), Error> {
            let parent = RegistryState::decode_cell(
                cells::read_boc(&read("parent")?, true)?,
                n(0)?,
                StateReadBudget::default(),
            )?;
            let before = parent.encode_cell()?.repr_hash();
            let raw = read("chain")?;
            if raw.len() != 100 {
                return Err(Error("chain-size"));
            }
            let chain = ChainContext {
                network: i32::from_be_bytes(raw[..4].try_into().map_err(|_| Error("network"))?),
                genesis_root: raw[4..36].try_into().map_err(|_| Error("root"))?,
                genesis_file: raw[36..68].try_into().map_err(|_| Error("file"))?,
                chain_domain: raw[68..].try_into().map_err(|_| Error("domain"))?,
            };
            let governing = RegistrySnapshot::compile(
                &decode::<Committee>(&read("committee")?)?,
                &decode::<Policy>(&read("policy")?)?,
            )?;
            let history =
                History { anchor: decode::<Anchor>(&read("anchor")?)?, available: n(2)? == 1 };
            let context = NativeIdentityContext { chain, governing: &governing, history: &history };
            let mut updates = Vec::new();
            for j in 0..n(3)? {
                updates.push((
                    decode::<Update>(&read(&format!("update{j}"))?)?,
                    decode::<Authorizations>(&read(&format!("auth{j}"))?)?,
                ));
            }
            let mut reader = ObjectReader::new(|_, _| Err(Error("unexpected-fetch")));
            let next = if persistent {
                let registry = NativeRegistry::bootstrap(
                    parent.encode_cell()?,
                    n(0)?,
                    StateReadBudget::default(),
                )?;
                let applied = if transactions {
                    (|| {
                        let mut prefix = NativeRegistryBlock::begin(
                            &registry,
                            n(1)?,
                            StateReadBudget::default(),
                        )?;
                        for (update, auth) in &updates {
                            let before = prefix.state().checkpoint()?.repr_hash();
                            let candidate =
                                prefix.apply_transaction(update, auth, &context, &mut reader);
                            if prefix.state().checkpoint()?.repr_hash() != before {
                                return Err(Error("transaction-immutable-prefix"));
                            }
                            let candidate = candidate?;
                            let retry =
                                prefix.apply_transaction(update, auth, &context, &mut reader)?;
                            if retry.state().checkpoint()?.repr_hash()
                                != candidate.state().checkpoint()?.repr_hash()
                            {
                                return Err(Error("transaction-discard-retry"));
                            }
                            prefix = candidate;
                            let mut bad = update.clone();
                            bad.nonce = u64::MAX;
                            let stable = prefix.state().checkpoint()?.repr_hash();
                            if !matches!(
                                prefix.apply_transaction(&bad, auth, &context, &mut reader),
                                Err(Error("nonce"))
                            ) {
                                return Err(Error("transaction-rejected-nonce"));
                            }
                            if prefix.state().checkpoint()?.repr_hash() != stable {
                                return Err(Error("transaction-rejected-prefix"));
                            }
                        }
                        if updates.len() == 2 {
                            let remaining = prefix.state().remaining()?;
                            let initial = StateReadBudget::default();
                            let budget = StateReadBudget {
                                entries: initial
                                    .entries
                                    .checked_sub(remaining.entries)
                                    .ok_or(Error("transaction-budget-fixture"))?,
                                bytes: initial
                                    .bytes
                                    .checked_sub(remaining.bytes)
                                    .and_then(|x| x.checked_sub(1))
                                    .ok_or(Error("transaction-budget-fixture"))?,
                            };
                            let limited = NativeRegistryBlock::begin(&registry, n(1)?, budget)?;
                            let limited = limited.apply_transaction(
                                &updates[0].0,
                                &updates[0].1,
                                &context,
                                &mut reader,
                            )?;
                            let stable = limited.state().checkpoint()?.repr_hash();
                            if !matches!(
                                limited.apply_transaction(
                                    &updates[1].0,
                                    &updates[1].1,
                                    &context,
                                    &mut reader
                                ),
                                Err(Error("state-resource"))
                            ) {
                                return Err(Error("transaction-cumulative-budget"));
                            }
                            if limited.state().checkpoint()?.repr_hash() != stable {
                                return Err(Error("transaction-resource-rollback"));
                            }
                        }
                        Ok(prefix.state().clone())
                    })()
                } else {
                    registry.apply_native_block(
                        n(1)?,
                        &updates,
                        &context,
                        &mut reader,
                        StateReadBudget::default(),
                    )
                };
                applied.and_then(|next| {
                    RegistryState::decode_cell(
                        next.encode_cell()?,
                        n(1)?,
                        StateReadBudget::default(),
                    )
                })
            } else {
                apply_native_identity_block(&parent, n(1)?, &updates, &context, &mut reader)
            };
            if parent.encode_cell()?.repr_hash() != before {
                return Err(Error("native-apply-atomic-parent"));
            }
            let next = next?;
            let bytes = |s: &RegistryState| {
                chain_block::write_boc(&s.encode_cell()?).map_err(|_| Error("state-boc"))
            };
            let expected = cells::read_boc(&read("result")?, true)?;
            if bytes(&next)?
                != chain_block::write_boc(&expected).map_err(|_| Error("expected-boc"))?
            {
                return Err(Error("native-apply-exact-bytes"));
            }
            let restored =
                RegistryState::decode_cell(next.encode_cell()?, n(1)?, StateReadBudget::default())?;
            if bytes(&restored)? != bytes(&next)? {
                return Err(Error("native-apply-checkpoint"));
            }
            Ok(())
        })();
        match result {
            Ok(()) if f[5] == "-" => (),
            Err(error) if error.0 == f[5] => (),
            result => {
                eprintln!("DETAIL: expected {}, got {:?}", f[5], result);
                return Err(f[4].into());
            }
        }
    }
    println!("PASS: independent native authenticated ordered apply persistent={persistent} transactions={transactions} {count} cases");
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("ASSERTION: {e}");
        std::process::exit(1);
    }
}
