//! The development keys exist for the sandbox tests of the circuit and the
//! contract. Nothing on the path a spender runs may name them: not this crate,
//! not the shield commands of the CLI. A proof under the development key would
//! verify against a pool deployed with it, which is exactly the pool a spender
//! must refuse.
#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

const FORBIDDEN: &str = "development_keys";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read a source directory") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn the_spending_path_never_names_the_development_keys() {
    let mut sources = Vec::new();
    rust_sources(&root().join("tools/shielded-pool-prover/src"), &mut sources);
    rust_sources(
        &root().join("tosctl/src/node-control/commands/src/commands/nodectl/shield"),
        &mut sources,
    );
    assert!(sources.len() >= 2, "the guard found too few sources: {sources:?}");
    let offenders: Vec<_> = sources
        .iter()
        .filter(|path| {
            std::fs::read_to_string(path).expect("read a source file").contains(FORBIDDEN)
        })
        .collect();
    assert!(offenders.is_empty(), "development keys named on the spending path: {offenders:?}");
}
