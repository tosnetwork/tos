use std::{collections::BTreeMap, env, fs, path::Path};
use tos_validator_auth::{
    codec::{decode, Error},
    lifecycle::{KeyHistory, LifecycleAuthority},
    types::*,
};
use tos_validator_auth_native::{
    cells, native_apply::CurrentRegistry, native_registry::NativeRegistry,
    registry::StateReadBudget,
};
struct Authority(u32);
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
fn root(path: &Path) -> Result<chain_block::Cell, String> {
    value(cells::read_boc(&fs::read(path).map_err(|e| e.to_string())?, true), "fixture-boc")
}
fn bytes(root: chain_block::Cell) -> Result<Vec<u8>, String> {
    chain_block::write_boc(&root).map_err(|e| e.to_string())
}
fn h(n: u32) -> [u8; 32] {
    let mut h = [0; 32];
    h[28..].copy_from_slice(&n.to_be_bytes());
    h
}
fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    check(args.len() == 3 || (args.len() == 4 && args[3] == "--guards"), "arguments")?;
    let guards = args.len() == 4;
    let input = Path::new(&args[1]);
    let native = Path::new(&args[2]);
    let count: usize = fs::read_to_string(input.join("complete"))
        .map_err(|e| e.to_string())?
        .trim()
        .parse()
        .map_err(|_| "count")?;
    check(count >= 30, "complete-corpus")?;
    let mut continuous: BTreeMap<_, NativeRegistry> = BTreeMap::new();
    for i in 0..count {
        if guards && i < 2 {
            continue;
        }
        let path = |suffix: &str| input.join(format!("{i}.{suffix}"));
        let meta = fs::read_to_string(path("case")).map_err(|e| e.to_string())?;
        let fields: Vec<_> = meta.split_whitespace().collect();
        check(fields.len() >= 7, "metadata")?;
        let n =
            |index: usize| fields[index].parse::<u32>().map_err(|_| "metadata-number".to_string());
        let label = fields[6];
        let cell = root(&path("boc"))?;
        let loaded = NativeRegistry::bootstrap(cell.clone(), n(1)?, StateReadBudget::default());
        let result = if n(0)? == 0 {
            let loaded = value(loaded, "parent-setup")?;
            let parent = continuous.get(&(n(1)?, cell.repr_hash())).cloned().unwrap_or(loaded);
            let checkpoint = value(parent.checkpoint(), "parent-checkpoint")?;
            let mut updates = Vec::new();
            for j in 0..n(4)? {
                updates.push((
                    value(
                        decode::<Update>(
                            &fs::read(path(&format!("update{j}"))).map_err(|e| e.to_string())?,
                        ),
                        "update",
                    )?,
                    value(
                        decode::<Authorizations>(
                            &fs::read(path(&format!("auth{j}"))).map_err(|e| e.to_string())?,
                        ),
                        "evidence",
                    )?,
                ));
            }
            let result =
                parent.apply_block(n(2)?, &updates, &Authority(n(3)?), StateReadBudget::default());
            let restored = value(
                NativeRegistry::restore(
                    checkpoint.clone(),
                    cell.repr_hash().as_slice(),
                    n(1)?,
                    StateReadBudget::default(),
                ),
                "checkpoint-load",
            )?;
            let replay = restored.apply_block(
                n(2)?,
                &updates,
                &Authority(n(3)?),
                StateReadBudget::default(),
            );
            let same = match (&result, &replay) {
                (Ok(a), Ok(b)) => {
                    bytes(value(a.checkpoint(), "continuous")?)?
                        == bytes(value(b.checkpoint(), "restart")?)?
                }
                (Err(a), Err(b)) => a.0 == b.0,
                _ => false,
            };
            check(same, "persistent-restart-bytes")?;
            check(
                bytes(value(parent.checkpoint(), "parent-after")?)? == bytes(checkpoint)?,
                "persistent-atomic-parent",
            )?;
            if label == "large-registry-apply" {
                check(
                    parent
                        .apply_block(
                            n(2)?,
                            &updates,
                            &Authority(n(3)?),
                            StateReadBudget { entries: 256, bytes: 65536 },
                        )
                        .is_ok(),
                    "persistent-bounded-archive",
                )?;
                let empty = value(
                    parent.apply_block(
                        n(2)?,
                        &[],
                        &Authority(0),
                        StateReadBudget { entries: 2, bytes: 32 },
                    ),
                    "persistent-constant-empty",
                )?;
                let budget = value(empty.remaining(), "budget")?;
                check(budget.entries == 0 && budget.bytes == 0, "persistent-empty-cost")?;
                let no_entries = parent.apply_block(
                    n(2)?,
                    &[],
                    &Authority(0),
                    StateReadBudget { entries: 0, bytes: 65536 },
                );
                check(
                    no_entries.err().is_some_and(|e| e.0 == "state-resource"),
                    "persistent-entry-budget",
                )?;
                let no_bytes = parent.apply_block(
                    n(2)?,
                    &[],
                    &Authority(0),
                    StateReadBudget { entries: 256, bytes: 0 },
                );
                check(
                    no_bytes.err().is_some_and(|e| e.0 == "state-resource"),
                    "persistent-byte-budget",
                )?;
            }
            result
        } else {
            loaded
        };
        check(result.is_ok() == (n(5)? == 1), label)?;
        let Ok(next) = result else {
            continue;
        };
        check(
            bytes(value(next.encode_cell(), "result")?)? == bytes(root(&path("result"))?)?,
            &format!("{label}-bytes"),
        )?;
        let checkpoint = value(next.checkpoint(), "checkpoint")?;
        check(
            bytes(checkpoint.clone())? == bytes(root(&native.join(format!("{i}.checkpoint")))?)?,
            "persistent-index-bytes",
        )?;
        let root = value(next.encode_cell(), "result-root")?;
        let restored = value(
            NativeRegistry::restore(
                checkpoint.clone(),
                root.repr_hash().as_slice(),
                next.coordinate(),
                StateReadBudget::default(),
            ),
            "checkpoint-roundtrip",
        )?;
        check(
            bytes(value(restored.checkpoint(), "restored")?)? == bytes(checkpoint)?,
            "persistent-index-roundtrip",
        )?;
        if i == 2 {
            let no_entries = next.apply_block(
                next.coordinate() + 1,
                &[],
                &Authority(0),
                StateReadBudget { entries: 0, bytes: 65536 },
            );
            check(
                no_entries.err().is_some_and(|e| e.0 == "state-resource"),
                "persistent-entry-budget",
            )?;
            let no_bytes = next.apply_block(
                next.coordinate() + 1,
                &[],
                &Authority(0),
                StateReadBudget { entries: 256, bytes: 0 },
            );
            check(
                no_bytes.err().is_some_and(|e| e.0 == "state-resource"),
                "persistent-byte-budget",
            )?;
            check(value(next.ever_registered(&h(1)), "registered")?, "persistent-ever-registered")?;
            check(
                !value(next.ever_registered(&h(9999)), "unregistered")?,
                "persistent-neighbor-registration",
            )?;
            check(
                value(next.latest_epoch(&h(1), (1, 1, 1)), "epoch")? == 1,
                "persistent-initial-epoch",
            )?;
            check(
                value(next.latest_epoch(&h(1), (1, 2, 1)), "other-slot")? == 0,
                "persistent-slot-isolation",
            )?;
            check(
                NativeRegistry::bootstrap(
                    cell,
                    n(1)?,
                    StateReadBudget { entries: 0, bytes: 65536 },
                )
                .err()
                .is_some_and(|e| e.0 == "state-resource"),
                "persistent-bootstrap-budget",
            )?;
        }
        continuous.insert((next.coordinate(), root.repr_hash()), next);
    }
    let cases = fs::read_to_string(native.join("negative-cases")).map_err(|e| e.to_string())?;
    check(cases.lines().count() == 8, "negative-completeness")?;
    for line in cases.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        check(f.len() == 4, "negative-fields")?;
        let at = f[1].parse().map_err(|_| "negative-coordinate")?;
        let expected = fs::read(native.join(format!("{}.hash", f[0])))
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "negative-hash")?;
        let result = NativeRegistry::restore(
            root(&native.join(format!("{}.boc", f[0])))?,
            &expected,
            at,
            StateReadBudget::default(),
        );
        check(result.err().is_some_and(|e| e.0 == f[2]), f[3])?;
    }
    println!("PASS: independent persistent native registry {count} replay cases, 8 checkpoint attacks and bounded archive work");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("ASSERTION: {error}");
        std::process::exit(1);
    }
}
