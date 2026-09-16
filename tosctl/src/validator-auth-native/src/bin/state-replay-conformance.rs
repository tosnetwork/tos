use std::{env, fs, path::Path};
use tos_validator_auth::{
    codec,
    codec::{decode, Error},
    lifecycle::{KeyHistory, LifecycleAuthority},
    types::*,
};
use tos_validator_auth_native::{
    cells,
    registry::{RegistryState, StateReadBudget},
};
/// The deny variant, and the governing anchor the case was exported with.
///
/// The anchor is read rather than derived. Deriving it here would be a second
/// source for the one value the activation must be stamped with, and the whole
/// point of replaying this corpus is that both implementations reach the same
/// bytes from the same inputs.
struct Authority(u32, Option<Anchor>);
impl LifecycleAuthority for Authority {
    fn owner(&self, _: &OwnerAuth, _: &Update, _: &Identity) -> Result<bool, Error> {
        Ok(self.0 != 1)
    }
    fn possession(&self, _: &PossessionAuth, _: &Update, _: &Key) -> Result<bool, Error> {
        Ok(self.0 != 2)
    }
    fn administration(
        &self,
        _: &IdentityAuth,
        _: &Update,
        _: &Identity,
        _: u32,
    ) -> Result<bool, Error> {
        Ok(self.0 != 3)
    }
    fn governance(
        &self,
        _: &Update,
        _: &Authorizations,
        _: &codec::Hash,
        _: u32,
    ) -> Result<Anchor, Error> {
        if self.0 == 4 {
            return Err(Error("fixture-governance"));
        }
        self.1.clone().ok_or(Error("fixture-governance-anchor"))
    }
}
fn check(ok: bool, label: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(label.to_owned())
    }
}
fn value<T>(r: Result<T, Error>, label: &str) -> Result<T, String> {
    r.map_err(|e| format!("{label}: {}", e.0))
}
fn bytes(state: &RegistryState) -> Result<Vec<u8>, String> {
    chain_block::write_boc(&value(state.encode_cell(), "encode-cell")?).map_err(|e| e.to_string())
}
fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    check(args.len() == 2, "arguments")?;
    let path = Path::new(&args[1]);
    let count: usize = fs::read_to_string(path.join("complete"))
        .map_err(|e| e.to_string())?
        .trim()
        .parse()
        .map_err(|_| "count")?;
    check(count >= 30, "complete-corpus")?;
    let mut continuous = std::collections::BTreeMap::new();
    for i in 0..count {
        let read =
            |suffix: &str| fs::read(path.join(format!("{i}.{suffix}"))).map_err(|e| e.to_string());
        let meta = String::from_utf8(read("case")?).map_err(|_| "metadata")?;
        let f: Vec<_> = meta.split_whitespace().collect();
        check(f.len() == 7 || f.len() == 8, "metadata-fields")?;
        let n = |index: usize| f[index].parse::<u32>().map_err(|_| "metadata-number".to_owned());
        let label = f[6];
        let root = value(cells::read_boc(&read("boc")?, true), "fixture-root")?;
        let root_key = (n(1)?, root.repr_hash().as_slice().to_vec());
        let parent = RegistryState::decode_cell(root.clone(), n(1)?, StateReadBudget::default());
        let result = if n(0)? == 0 {
            let restored = value(parent, "parent-setup")?;
            let parent = continuous.get(&root_key).cloned().unwrap_or_else(|| restored.clone());
            let prior = bytes(&parent)?;
            check(
                parent.revision().to_string() == f[7] && parent.coordinate() == n(1)?,
                "checkpoint-metadata",
            )?;
            let mut updates = Vec::new();
            for j in 0..n(4)? {
                updates.push((
                    value(decode::<Update>(&read(&format!("update{j}"))?), "fixture-update")?,
                    value(decode::<Authorizations>(&read(&format!("auth{j}"))?), "fixture-auth")?,
                ));
            }
            let governing = match fs::read(path.join(format!("{i}.governance"))) {
                Ok(raw) => Some(value(decode::<Anchor>(&raw), "fixture-governance")?),
                Err(_) => None,
            };
            let result = parent.apply_block(n(2)?, &updates, &Authority(n(3)?, governing.clone()));
            let from_checkpoint =
                restored.apply_block(n(2)?, &updates, &Authority(n(3)?, governing));
            let same = match (&result, &from_checkpoint) {
                (Ok(a), Ok(b)) => bytes(a)? == bytes(b)?,
                (Err(a), Err(b)) => a.0 == b.0,
                _ => false,
            };
            check(same, &format!("{label}-checkpoint-replay"))?;

            check(bytes(&parent)? == prior, "immutable-parent")?;
            result
        } else {
            parent
        };
        if label == "coordinate-overflow" {
            check(
                result.as_ref().err().is_some_and(|e| e.0 == "block-gap"),
                "coordinate-overflow-early-admission",
            )?;
        }
        check(result.is_ok() == (n(5)? == 1), &format!("{label}: {:?}", result.as_ref().err()))?;
        if let Ok(result) = result {
            let expected = value(cells::read_boc(&read("result")?, true), "expected-root")?;
            // Normalize only the BOC container flags; every native cell bit and
            // ordered reference must match the independent C++ output.
            let expected_bytes = chain_block::write_boc(&expected).map_err(|e| e.to_string())?;
            check(bytes(&result)? == expected_bytes, &format!("{label}-bytes"))?;
            let at = if n(0)? == 0 { n(2)? } else { n(1)? };
            let restarted = value(
                RegistryState::decode_cell(
                    value(result.encode_cell(), "persist")?,
                    at,
                    StateReadBudget::default(),
                ),
                "restart",
            )?;
            check(bytes(&restarted)? == bytes(&result)?, "restart-roundtrip")?;
            continuous.insert((at, expected.repr_hash().as_slice().to_vec()), result.clone());
            if i == 0 {
                let identities: Vec<_> = result.identities().values().cloned().collect();
                let keys: Vec<_> = result.keys().values().cloned().collect();
                let policy = value(result.policy_at(0), "genesis-policy")?.clone();
                let genesis = value(
                    RegistryState::genesis(
                        *result.chain_domain(),
                        policy.clone(),
                        identities.clone(),
                        keys.clone(),
                    ),
                    "genesis",
                )?;
                check(
                    bytes(&genesis)? == expected_bytes && genesis.identities().len() == 501,
                    "genesis-bytes",
                )?;
                let mut duplicate = identities.clone();
                duplicate.push(identities[0].clone());
                check(
                    RegistryState::genesis(
                        *result.chain_domain(),
                        policy.clone(),
                        duplicate,
                        keys.clone(),
                    )
                    .is_err(),
                    "genesis-duplicate-identity",
                )?;
                let mut duplicate = keys.clone();
                duplicate.push(keys[0].clone());
                check(
                    RegistryState::genesis(
                        *result.chain_domain(),
                        policy.clone(),
                        identities.clone(),
                        duplicate,
                    )
                    .is_err(),
                    "genesis-duplicate-key",
                )?;
                check(
                    RegistryState::genesis(
                        [0; 32],
                        policy.clone(),
                        identities.clone(),
                        keys.clone(),
                    )
                    .is_err(),
                    "genesis-domain",
                )?;
                let mut invalid = policy.clone();
                invalid.phase = 2;
                check(
                    RegistryState::genesis(
                        *result.chain_domain(),
                        invalid,
                        identities.clone(),
                        keys.clone(),
                    )
                    .is_err(),
                    "genesis-policy",
                )?;
                let mut duplicate = keys.clone();
                let mut key = keys[0].clone();
                key.valid_until += 1;
                duplicate.push(key);
                check(
                    RegistryState::genesis(*result.chain_domain(), policy, identities, duplicate)
                        .is_err(),
                    "genesis-duplicate-epoch",
                )?;
                for key in result.keys().values() {
                    check(
                        value(
                            result
                                .latest_epoch(&key.identity, (key.role, key.suite, key.parameters)),
                            "latest-epoch",
                        )? == key.epoch
                            && value(result.ever_registered(&key.identity), "registered")?,
                        "epoch-index",
                    )?;
                }
            }
        }
    }
    println!("PASS: independent native registry replay {count} cases and genesis checks");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("ASSERTION: {error}");
        std::process::exit(1);
    }
}
